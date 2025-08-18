# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import copy
import logging
import os
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta
from functools import update_wrapper
from inspect import getfullargspec, isgeneratorfunction
from os.path import basename
from threading import Lock
from time import sleep
from typing import TYPE_CHECKING, Any, Union

from sqlalchemy import MetaData, create_engine, event, text
from sqlalchemy.exc import DatabaseError, DisconnectionError, OperationalError, SQLAlchemyError, TimeoutError
from sqlalchemy.orm import DeclarativeBase, Session, scoped_session, sessionmaker
from sqlalchemy.pool import NullPool, Pool, QueuePool, SingletonThreadPool

from rucio.common.config import config_get
from rucio.common.exception import DatabaseException, InputValidationError, RucioException
from rucio.common.extra import import_extras
from rucio.common.utils import retrying
from rucio.db.sqla.constants import DatabaseOperationType

EXTRA_MODULES = import_extras(['MySQLdb', 'pymysql'])

LOG = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from typing import Optional, ParamSpec, TypeVar

    from pymysql import Connection as MySQLConnection
    from sqlalchemy.engine.base import Engine

    from rucio.common.types import LoggerFunction

    P = ParamSpec('P')
    R = TypeVar('R')
    CallableTypeVar = TypeVar('CallableTypeVar', bound='Callable[..., Any]')

try:
    main_script = os.path.basename(sys.argv[0])
    CURRENT_COMPONENT = main_script.split('-')[1]
except Exception:
    CURRENT_COMPONENT = None

DATABASE_SECTION = 'database'
try:
    if CURRENT_COMPONENT:
        sql_connection = config_get('%s-database' % CURRENT_COMPONENT, 'default', check_config_table=False).strip()
        if sql_connection and len(sql_connection):
            DATABASE_SECTION = '%s-database' % CURRENT_COMPONENT
except Exception:
    pass

DEFAULT_SCHEMA_NAME = config_get(DATABASE_SECTION, 'schema',
                                 raise_exception=False, default=None, check_config_table=False)
_METADATA = MetaData(schema=DEFAULT_SCHEMA_NAME)
_MAKER, _ENGINE, _LOCK = None, None, Lock()

SQLA_CONFIG_POOLCLASS_MAPPING = {
    'queuepool': QueuePool,
    'singletonthreadpool': SingletonThreadPool,
    'nullpool': NullPool,
}


class BASE(DeclarativeBase):
    metadata = _METADATA


def _fk_pragma_on_connect(dbapi_con, con_record) -> None:
    # Hack for previous versions of sqlite3
    try:
        dbapi_con.execute('pragma foreign_keys=ON')
    except AttributeError:
        pass


def mysql_ping_listener(
        dbapi_conn: "MySQLConnection",
        connection_rec,
        connection_proxy
) -> None:
    """
    Ensures that MySQL connections checked out of the
    pool are alive.

    Borrowed from:
    http://groups.google.com/group/sqlalchemy/msg/a4ce563d802c929f

    :param dbapi_conn: DBAPI connection
    :param connection_rec: connection record
    :param connection_proxy: connection proxy
    """

    try:
        dbapi_conn.cursor().execute('select 1')
    except dbapi_conn.OperationalError as ex:
        if ex.args[0] in (2006, 2013, 2014, 2045, 2055):
            msg = 'Got mysql server has gone away: %s' % ex
            raise DisconnectionError(msg)
        else:
            raise


def mysql_convert_decimal_to_float(
        pymysql: bool = False
) -> dict[Union[type[object], int], 'Callable[..., Any]']:
    """
    The default datatype returned by mysql-python for numerics is decimal.Decimal.
    This type cannot be serialised to JSON, therefore we need to autoconvert to floats.
    Even worse, there's two types of decimals created by the MySQLdb driver, so we must
    override both.

    :return converter: Converter object
    """

    def pymysql_converter() -> dict[Union[type[object], int], 'Callable[..., Any]']:
        from pymysql.constants import FIELD_TYPE
        from pymysql.converters import conversions as conv
        converter = conv.copy()
        converter[FIELD_TYPE.DECIMAL] = float
        converter[FIELD_TYPE.NEWDECIMAL] = float
        return converter

    if pymysql:
        if not EXTRA_MODULES['pymysql']:
            raise RucioException('Trying to use pymysql without having it installed!')
        else:
            converter = pymysql_converter()
    elif EXTRA_MODULES['MySQLdb']:
        import MySQLdb.converters  # pylint: disable=import-error
        from MySQLdb.constants import FIELD_TYPE  # pylint: disable=import-error
        converter = MySQLdb.converters.conversions.copy()
        converter[FIELD_TYPE.DECIMAL] = float
        converter[FIELD_TYPE.NEWDECIMAL] = float
    elif EXTRA_MODULES['pymysql']:
        converter = pymysql_converter()
    else:
        raise RucioException('Trying to use MySQL without mysql-python or pymysql installed!')

    return converter


def psql_convert_decimal_to_float(dbapi_conn, connection_rec) -> None:
    """
    Configure the PostgreSQL connection to return numeric types as float instead of Decimal.
    Psycopg3 provides this functionality through type adapters.

    :param dbapi_conn: DBAPI connection
    :param connection_rec: connection record
    """
    try:
        import psycopg
        # Register a global loader that converts numeric types to float
        dbapi_conn.adapters.register_loader("numeric", psycopg.types.numeric.FloatLoader)
    except ImportError:
        raise RucioException('Trying to use PostgreSQL without psycopg installed!')
    except Exception as error:
        raise RucioException(f'Error setting up PostgreSQL Decimal to Float conversion: {str(error)}')


def my_on_connect(dbapi_con, connection_record) -> None:
    """ Adds information to track performance and resource by module.
        Info are recorded in the V$SESSION and V$SQLAREA views.
    """
    caller = basename(sys.argv[0])
    dbapi_con.clientinfo = caller
    dbapi_con.client_identifier = caller
    dbapi_con.module = caller
    dbapi_con.action = caller


def _get_engine_poolclass(poolclass: str) -> Pool:
    """Resolve the correct SQLAlchemy Pool type to use from the
    poolclass config option.

    :param poolclass: User-selected pool class from config file.
    :returns: The corresponding SQLAlchemy Pool class.
    :raises InputValidationError: if config value doesn't correspond to an SQLAlchemy Pool class.
    """

    poolclass = poolclass.lower()

    if poolclass not in SQLA_CONFIG_POOLCLASS_MAPPING:
        raise InputValidationError('Unknown poolclass: %s' % poolclass)

    return SQLA_CONFIG_POOLCLASS_MAPPING[poolclass]


def get_engine() -> 'Engine':
    """ Creates an engine to a specific database.
        :returns: engine
    """
    global _ENGINE
    if not _ENGINE:
        sql_connection = config_get(DATABASE_SECTION, 'default', check_config_table=False)
        config_params = [('pool_size', int), ('max_overflow', int), ('pool_timeout', int),
                         ('pool_recycle', int), ('echo', int), ('echo_pool', str),
                         ('pool_reset_on_return', str), ('use_threadlocal', int),
                         ('poolclass', _get_engine_poolclass)]
        params = {}
        if 'mysql' in sql_connection:
            conv = mysql_convert_decimal_to_float(pymysql=sql_connection.startswith('mysql+pymysql'))
            params['connect_args'] = {'conv': conv}
        elif 'oracle' in sql_connection:
            try:
                import oracledb  # pylint: disable=import-error
                oracledb.init_oracle_client()
            except Exception as err:
                LOG.warning('Could not start Oracle thick mode; falling back to thin: %s', err)
        for param, param_type in config_params:
            try:
                params[param] = param_type(config_get(DATABASE_SECTION, param, check_config_table=False))
            except Exception:
                pass
        _ENGINE = create_engine(sql_connection, **params)
        if 'mysql' in sql_connection:
            event.listen(_ENGINE, 'checkout', mysql_ping_listener)
        elif 'postgresql' in sql_connection:
            event.listen(_ENGINE, 'connect', psql_convert_decimal_to_float)
        elif 'sqlite' in sql_connection:
            event.listen(_ENGINE, 'connect', _fk_pragma_on_connect)
        elif 'oracle' in sql_connection:
            event.listen(_ENGINE, 'connect', my_on_connect)
    if not _ENGINE:
        raise RuntimeError("Could not form database engine.")
    return _ENGINE


def get_dump_engine(
        echo: bool = False
) -> 'Engine':
    """ Creates a dump engine to a specific database.
        :returns: engine """

    statements = list()

    def dump(sql, *multiparams, **params):
        statement = str(sql.compile(dialect=engine.dialect))
        if statement in statements:
            return
        statements.append(statement)
        if statement.endswith(')\n\n'):
            if engine.dialect.name == 'oracle':
                print(statement.replace(')\n\n', ') PCTFREE 0;\n'))
            else:
                print(statement.replace(')\n\n', ');\n'))
        elif statement.endswith(')'):
            print(statement.replace(')', ');\n'))
        else:
            print(statement)

    sql_connection = config_get(DATABASE_SECTION, 'default', check_config_table=False)

    engine = create_engine(sql_connection, echo=echo, strategy='mock', executor=dump)
    return engine


def get_maker() -> sessionmaker:
    """
        Return a SQLAlchemy sessionmaker.
        May assign __MAKER if not already assigned.
    """
    global _MAKER, _ENGINE
    if not _ENGINE:
        raise RuntimeError("Could not form database engine.")
    if not _MAKER:
        _MAKER = sessionmaker(bind=_ENGINE, autocommit=False, autoflush=True, expire_on_commit=True)
    return _MAKER


def get_session() -> scoped_session:
    """ Creates a session to a specific database, assumes that schema already in place.
        :returns: session
    """
    global _MAKER, _LOCK
    if not _MAKER:
        _LOCK.acquire()
        try:
            get_engine()
            get_maker()
        finally:
            _LOCK.release()
    if not _MAKER:
        raise RuntimeError("Session factory is not defined.")
    session = scoped_session(_MAKER)
    return session


def wait_for_database(
        timeout: int = 60,
        interval: int = 2,
        *,
        logger: "LoggerFunction" = logging.log
) -> None:
    """ Wait for the database for a specific amount of time """

    end_time = datetime.utcnow() + timedelta(seconds=timeout)
    while True:
        try:
            session = get_session()
            if session.bind.dialect.name == 'oracle':
                session.execute(text('select 1 from dual'))
            else:
                session.execute(text('select 1'))
            session.close()
            break
        except SQLAlchemyError as e:
            logger(logging.WARNING, 'Still waiting for database: %s', e)
            if datetime.utcnow() >= end_time:
                raise

        sleep(interval)


def retry_if_db_connection_error(exception: Exception) -> bool:
    """Return True if error in connecting to db."""
    if isinstance(exception, (OperationalError, DatabaseException)):
        conn_err_codes = ('2002', '2003', '2006',  # MySQL
                          'ORA-00028',  # Oracle session has been killed
                          'ORA-01012',  # not logged on
                          'ORA-03113',  # end-of-file on communication channel
                          'ORA-03114',  # not connected to ORACLE
                          'ORA-03135',  # connection lost contact
                          'ORA-25408',)  # can not safely replay call
        for err_code in conn_err_codes:
            if exception.args[0].find(err_code) != -1:
                return True
    return False


def _update_session_wrapper(
        wrapper: "CallableTypeVar",
        wrapped: 'Callable'
) -> "CallableTypeVar":
    """
    In addition to the work done by functools.update_wrapper, this function also preservers
    the signature of the initial function. With the exception that the 'session' parameter
    is overridden to have a default value of 'None'.

    wrapper is the function to be updated
    wrapped is the original function

    To simplify the implementation of this function, we require 'session' be a
    keyword-only argument in the wrapped function.
    """
    try:
        arg_spec = getfullargspec(wrapped)
        arg_spec.kwonlyargs.index('session')
    except ValueError:
        # We require decorated functions to have a 'session' keyword-only attribute.
        # re-raise ValueError if not
        raise

    update_wrapper(wrapper, wrapped)

    wrapper.__defaults__ = copy.copy(wrapped.__defaults__)
    wrapper.__kwdefaults__ = copy.copy(wrapped.__kwdefaults__)
    wrapper.__annotations__["session"] = "Optional[Session]"

    # Set the default of the keyword-only attribute 'session' to None
    if not wrapped.__kwdefaults__:
        wrapper.__kwdefaults__ = {'session': None}
    elif 'session' not in wrapped.__kwdefaults__:
        wrapper.__kwdefaults__['session'] = None
    return wrapper


def read_session(function: "Callable[P, R]"):
    '''
    decorator that set the session variable to use inside a function.
    With that decorator it's possible to use the session variable like if a global variable session is declared.

    session is a sqlalchemy session, and you can get one calling get_session().
    This is useful if only SELECTs and the like are being done; anything involving
    INSERTs, UPDATEs etc should use transactional_session.
    '''

    @retrying(retry_on_exception=retry_if_db_connection_error,
              wait_fixed=500,
              stop_max_attempt_number=2)
    def new_funct(*args: "P.args", session: "Optional[Session]" = None, **kwargs):  # pylint:disable=missing-kwoa
        if isgeneratorfunction(function):
            raise RucioException(
                'read_session decorator should not be used with generator. Use stream_session instead.')

        if not session:
            session_scoped = get_session()
            session = session_scoped()
            session.begin()  # type: ignore
            try:
                return function(*args, session=session, **kwargs)
            except TimeoutError as error:
                session.rollback()  # type: ignore
                raise DatabaseException(str(error))
            except DatabaseError as error:
                session.rollback()  # type: ignore
                raise DatabaseException(str(error))
            except Exception:
                session.rollback()  # type: ignore
                raise
            finally:
                session_scoped.remove()
        try:
            return function(*args, session=session, **kwargs)
        except Exception:
            raise

    return _update_session_wrapper(new_funct, function)


def stream_session(function: "Callable[P, R]"):
    '''
    decorator that set the session variable to use inside a function.
    With that decorator it's possible to use the session variable like if a global variable session is declared.

    session is a sqlalchemy session, and you can get one calling get_session().
    This is useful if only SELECTs and the like are being done; anything involving
    INSERTs, UPDATEs etc should use transactional_session.
    '''

    @retrying(retry_on_exception=retry_if_db_connection_error,
              wait_fixed=500,
              stop_max_attempt_number=2)
    def new_funct(*args: "P.args", session: "Optional[Session]" = None, **kwargs):  # pylint:disable=missing-kwoa

        if not isgeneratorfunction(function):
            raise RucioException(
                'stream_session decorator should be used only with generator. Use read_session instead.')

        if not session:
            session_scoped = get_session()
            session = session_scoped()
            session.begin()  # type: ignore
            try:
                for row in function(*args, session=session, **kwargs):
                    yield row
            except TimeoutError as error:
                session.rollback()  # type: ignore
                raise DatabaseException(str(error))
            except DatabaseError as error:
                session.rollback()  # type: ignore
                raise DatabaseException(str(error))
            except Exception:
                session.rollback()  # type: ignore
                raise
            finally:
                session_scoped.remove()
        else:
            try:
                for row in function(*args, session=session, **kwargs):
                    yield row
            except Exception:
                raise
    return _update_session_wrapper(new_funct, function)


def transactional_session(function: "Callable[P, R]") -> 'Callable':
    '''
    decorator that set the session variable to use inside a function.
    With that decorator it's possible to use the session variable like if a global variable session is declared.

    session is a sqlalchemy session, and you can get one calling get_session().
    '''

    def new_funct(
            *args: "P.args",
            session: "Optional[Session]" = None,
            **kwargs
    ) -> "R":  # pylint:disable=missing-kwoa
        if not session:
            session_scoped = get_session()
            session = session_scoped()
            session.begin()  # type: ignore
            try:
                result = function(*args, session=session, **kwargs)
                session.commit()  # type: ignore
            except TimeoutError as error:
                session.rollback()  # type: ignore
                raise DatabaseException(str(error))
            except DatabaseError as error:
                session.rollback()  # type: ignore
                raise DatabaseException(str(error))
            except Exception:
                session.rollback()  # type: ignore
                raise
            finally:
                session_scoped.remove()  # pylint: disable=maybe-no-member
        else:
            result = function(*args, session=session, **kwargs)
        return result

    return _update_session_wrapper(new_funct, function)


@retrying(retry_on_exception=retry_if_db_connection_error,
          wait_fixed=500,
          stop_max_attempt_number=2)
@contextmanager
def db_session(operation: DatabaseOperationType) -> "Iterator[Session]":
    session_scoped = get_session()
    session = session_scoped()
    session.begin()

    try:
        yield session
        if operation is DatabaseOperationType.WRITE:
            session.commit()
    except TimeoutError as error:
        session.rollback()
        raise DatabaseException(str(error))
    except DatabaseError as error:
        session.rollback()
        raise DatabaseException(str(error))
    except Exception:
        session.rollback()
        raise
    finally:
        session_scoped.remove()
