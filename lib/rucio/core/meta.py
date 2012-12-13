# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from sqlalchemy.exc import IntegrityError

from rucio.common.exception import Duplicate, RucioException, KeyNotFound
from rucio.db import models
from rucio.db.session import get_session

session = get_session()


def add_key(key, type=None, regexp=None):
    """ add a new allowed key.

    :param key: the name for the new key.
    :param type: the type of the value, if defined.
    :param regexp: the regular expression that values should match, if defined.
    """

    new_key = models.DIDKey(key=key, type=type, regexp=regexp)
    try:
        new_key.save(session=session)
    except IntegrityError, e:
        session.rollback()
        if e.args[0] == "(IntegrityError) column key is not unique":
            raise Duplicate('key \'%(key)s\' already exists!' % locals())
        else:
            raise RucioException(e.args[0])

    session.commit()


def list_keys():
    """
    Lists all keys.

    :returns: A list containing all keys.
    """
    key_list = []
    query = session.query(models.DIDKey)
    for s in query:
        key_list.append(s.key)
    return key_list


def add_value(key, value):
    """ add a new value to a key.

    :param key: the name for the key.
    :param value: the value.
    """
    new_value = models.DIDKeyValueAssociation(key=key, value=value)
    try:
        new_value.save(session=session)
    except IntegrityError, e:
        session.rollback()
        if e.args[0] == "(IntegrityError) columns key, value are not unique":
            raise Duplicate('key-value \'%(key)s-%(value)s\' already exists!' % locals())
        if e.args[0] == "(IntegrityError) foreign key constraint failed":
            raise KeyNotFound("key '%(key)s' does not exist!" % locals())
        else:
            raise RucioException(e.args[0])
    session.commit()


def list_values(key):
    """
    Lists all values for a key.

    :param key: the name for the key.


    :returns: A list containing all values.
    """
    value_list = []
    query = session.query(models.DIDKeyValueAssociation).filter_by(key=key)
    for s in query:
        value_list.append(s.value)
    return value_list
