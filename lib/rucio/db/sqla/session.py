'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
  - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
  - Vincent Garonne,  <vincent.garonne@cern.ch>, 2011-2016
  - Cedric Serfon, <cedric.serfon@cern.ch>, 2014
  - Wen Guan, <wen.guan@cern.ch>, 2016
'''

import os
import sys

from ConfigParser import NoOptionError
from functools import wraps
from inspect import isgeneratorfunction
from retrying import retry
from threading import Lock
from os.path import basename

from sqlalchemy import create_engine, event
from sqlalchemy.exc import DatabaseError, DisconnectionError, OperationalError, TimeoutError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session

from rucio.common.config import config_get
from rucio.common.exception import RucioException, DatabaseException

try:
    main_script = os.path.basename(sys.argv[0])
    CURRENT_COMPONENT = main_script.split('-')[1]
except:
    CURRENT_COMPONENT = None

DATABASE_SECTION = 'database'
try:
    if CURRENT_COMPONENT:
        sql_connection = config_get('%s-database' % CURRENT_COMPONENT, 'default').strip()
        if sql_connection and len(sql_connection):
            DATABASE_SECTION = '%s-database' % CURRENT_COMPONENT
except:
    pass

BASE = declarative_base()
try:
    DEFAULT_SCHEMA_NAME = config_get(DATABASE_SECTION, 'schema')
    BASE.metadata.schema = DEFAULT_SCHEMA_NAME
except NoOptionError:
    DEFAULT_SCHEMA_NAME = None

_MAKER, _ENGINE, _LOCK = None, None, Lock()


def _fk_pragma_on_connect(dbapi_con, con_record):
    # Hack for previous versions of sqlite3
    try:
        dbapi_con.execute('pragma foreign_keys=ON')
    except AttributeError:
        pass


def mysql_ping_listener(dbapi_conn, connection_rec, connection_proxy):
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
    except dbapi_conn.OperationalError, ex:
        if ex.args[0] in (2006, 2013, 2014, 2045, 2055):
            msg = 'Got mysql server has gone away: %s' % ex
            raise DisconnectionError(msg)
        else:
            raise


def my_on_connect(dbapi_con, connection_record):
    """ Adds information to track performance and ressource by module.
        Info are recorded in the V$SESSION and V$SQLAREA views.
    """
    caller = basename(sys.argv[0])
    dbapi_con.clientinfo = caller
    dbapi_con.client_identifier = caller
    dbapi_con.module = caller
    dbapi_con.action = caller


def get_engine(echo=True):
    """ Creates a engine to a specific database.
        :returns: engine
    """
    global _ENGINE
    if not _ENGINE:
        sql_connection = config_get(DATABASE_SECTION, 'default')
        config_params = [('pool_size', int), ('max_overflow', int), ('pool_timeout', int),
                         ('pool_recycle', int), ('echo', int), ('echo_pool', str),
                         ('pool_reset_on_return', str), ('use_threadlocal', int)]
        params = {}
        for param, param_type in config_params:
            try:
                params[param] = param_type(config_get(DATABASE_SECTION, param))
            except NoOptionError:
                pass
        _ENGINE = create_engine(sql_connection, **params)
        if 'mysql' in sql_connection:
            event.listen(_ENGINE, 'checkout', mysql_ping_listener)
        elif 'sqlite' in sql_connection:
            event.listen(_ENGINE, 'connect', _fk_pragma_on_connect)
        elif 'oracle' in sql_connection:
            event.listen(_ENGINE, 'connect', my_on_connect)
    assert _ENGINE
    return _ENGINE


def get_dump_engine(echo=False):
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
                print statement.replace(')\n\n', ') PCTFREE 0;\n')
            else:
                print statement.replace(')\n\n', ');\n')
        elif statement.endswith(')'):
            print statement.replace(')', ');\n')
        else:
            print statement
    sql_connection = config_get(DATABASE_SECTION, 'default')

    engine = create_engine(sql_connection, echo=echo, strategy='mock', executor=dump)
    return engine


def get_maker():
    """
        Return a SQLAlchemy sessionmaker.
        May assign __MAKER if not already assigned.
    """
    global _MAKER, _ENGINE
    assert _ENGINE
    if not _MAKER:
        _MAKER = sessionmaker(bind=_ENGINE, autocommit=False, autoflush=True, expire_on_commit=True)
    return _MAKER


def get_session():
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
    assert _MAKER
    session = scoped_session(_MAKER)
    return session


def retry_if_db_connection_error(exception):
    """Return True if error in connecting to db."""
    print exception
    if isinstance(exception, OperationalError):
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


def read_session(function):
    '''
    decorator that set the session variable to use inside a function.
    With that decorator it's possible to use the session variable like if a global variable session is declared.

    session is a sqlalchemy session, and you can get one calling get_session().
    This is useful if only SELECTs and the like are being done; anything involving
    INSERTs, UPDATEs etc should use transactional_session.
    '''
    @retry(retry_on_exception=retry_if_db_connection_error,
           wait_fixed=0.5,
           stop_max_attempt_number=2,
           wrap_exception=False)
    @wraps(function)
    def new_funct(*args, **kwargs):

        if isgeneratorfunction(function):
            raise RucioException('read_session decorator should not be used with generator. Use stream_session instead.')

        if not kwargs.get('session'):
            session = get_session()
            try:
                kwargs['session'] = session
                return function(*args, **kwargs)
            except TimeoutError, error:
                session.rollback()  # pylint: disable=maybe-no-member
                raise DatabaseException(str(error))
            except DatabaseError, error:
                session.rollback()  # pylint: disable=maybe-no-member
                raise DatabaseException(str(error))
            except:
                session.rollback()  # pylint: disable=maybe-no-member
                raise
            finally:
                session.remove()
        try:
            return function(*args, **kwargs)
        except:
            raise
    new_funct.__doc__ = function.__doc__
    return new_funct


def stream_session(function):
    '''
    decorator that set the session variable to use inside a function.
    With that decorator it's possible to use the session variable like if a global variable session is declared.

    session is a sqlalchemy session, and you can get one calling get_session().
    This is useful if only SELECTs and the like are being done; anything involving
    INSERTs, UPDATEs etc should use transactional_session.
    '''
    @retry(retry_on_exception=retry_if_db_connection_error,
           wait_fixed=0.5,
           stop_max_attempt_number=2,
           wrap_exception=False)
    @wraps(function)
    def new_funct(*args, **kwargs):

        if not isgeneratorfunction(function):
            raise RucioException('stream_session decorator should be used only with generator. Use read_session instead.')

        if not kwargs.get('session'):
            session = get_session()
            try:
                kwargs['session'] = session
                for row in function(*args, **kwargs):
                    yield row
            except TimeoutError, error:
                print error
                session.rollback()  # pylint: disable=maybe-no-member
                raise DatabaseException(str(error))
            except DatabaseError, error:
                print error
                session.rollback()  # pylint: disable=maybe-no-member
                raise DatabaseException(str(error))
            except:
                session.rollback()  # pylint: disable=maybe-no-member
                raise
            finally:
                session.remove()
        else:
            try:
                for row in function(*args, **kwargs):
                    yield row
            except:
                raise
    new_funct.__doc__ = function.__doc__
    return new_funct


def transactional_session(function):
    '''
    decorator that set the session variable to use inside a function.
    With that decorator it's possible to use the session variable like if a global variable session is declared.

    session is a sqlalchemy session, and you can get one calling get_session().
    '''
    @wraps(function)
    def new_funct(*args, **kwargs):
        if not kwargs.get('session'):
            session = get_session()
            try:
                kwargs['session'] = session
                result = function(*args, **kwargs)
                session.commit()  # pylint: disable=maybe-no-member
            except TimeoutError, error:
                print error
                session.rollback()  # pylint: disable=maybe-no-member
                raise DatabaseException(str(error))
            except DatabaseError, error:
                print error
                session.rollback()  # pylint: disable=maybe-no-member
                raise DatabaseException(str(error))
            except:
                session.rollback()  # pylint: disable=maybe-no-member
                raise
            finally:
                session.remove()  # pylint: disable=maybe-no-member
        else:
            result = function(*args, **kwargs)
        return result
    new_funct.__doc__ = function.__doc__
    return new_funct
