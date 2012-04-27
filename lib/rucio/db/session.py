# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas,  <angelos.molfetas@cern.ch> , 2012

from sqlalchemy import create_engine
from sqlalchemy.interfaces import PoolListener
from sqlalchemy.orm import sessionmaker, scoped_session

from rucio.common.config import config_get
from rucio.db import models1 as models


class ForeignKeysListener(PoolListener):
    def connect(self, dbapi_con, con_record):
        db_cursor = dbapi_con.execute('pragma foreign_keys=ON')


def get_session():
    """ Creates a session to a specific database, assumes that schema already in place
    :returns: session
    """

    database = config_get('database', 'default')
    engine = create_engine(database, echo=False, listeners=[ForeignKeysListener()])
    session = scoped_session(sessionmaker(bind=engine, autocommit=False, expire_on_commit=False))
    return session


def build_database():
    """ Applies the schema to the database. Run this command once to build the database
    :returns: nothing
    """

    engine = create_engine(config_get('database', 'default'), echo=True)
    models.register_models(engine)
