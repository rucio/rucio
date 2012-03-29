# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.exc import IntegrityError

from rucio.db import models1 as models
from rucio.common import exception
from rucio.common.config import config_get

""" Only for testing """
engine = create_engine(config_get('database', 'default'))
models.register_models(engine)  # this only creates the necessary tables, should be done once somewhere else and then never again

session = sessionmaker(bind=engine, autocommit=True, expire_on_commit=False)


def get_session():
    return scoped_session(session)


def add_rse(rse):
    """ add a Rucio Storage Element (RSE).

    :param rse: the name of the new rse.
    """
    session = get_session()

    with session.begin():

        values = {}
        values['rse'] = rse

        new_rse = models.RSE()

        new_rse.update(values)

        try:
            new_rse.save(session=session)
        except IntegrityError, e:
            raise exception.Duplicate('Account ID \'%s\' already exists!' % values['account'])
        finally:
            session.flush()


def list_rses():
    """ returns a list of all rse names.

    returns: a list of all rses names.
    """
    session = get_session()
    rse_list = []

    with session.begin():
        for rse in session.query(models.RSE).order_by(models.RSE.rse):
            account_list.append(rse.rse)

    return rse_list
