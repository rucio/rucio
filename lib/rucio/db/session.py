# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Vincent Garonne,  <vincent.garonne@cern.ch>, 2011-2013


from ConfigParser import NoOptionError
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.exc import DisconnectionError
from sqlalchemy.ext.declarative import declarative_base

from rucio.common.config import config_get

BASE = declarative_base()
try:
    BASE.metadata.schema = config_get('database', 'schema')
except NoOptionError:
    pass


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


def get_engine(echo=True):
    """ Creates a engine to a specific database.
        :returns: engine """

    sql_connection = config_get('database', 'default')
    engine = create_engine(sql_connection, echo=echo)
    return engine


def get_session():
    """ Creates a session to a specific database, assumes that schema already in place.
        :returns: session """

    database = config_get('database', 'default')
    engine = create_engine(database, echo=False, echo_pool=False)
    # , pool_reset_on_return='rollback'
    if 'mysql' in database:
        event.listen(engine, 'checkout', mysql_ping_listener)

    event.listen(engine, 'connect', _fk_pragma_on_connect)
    return scoped_session(sessionmaker(bind=engine, autocommit=False, autoflush=True, expire_on_commit=True))
