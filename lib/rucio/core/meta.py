# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from re import match
from sqlalchemy.exc import IntegrityError

from rucio.common.constraints import AUTHORIZED_VALUE_TYPES
from rucio.common.exception import Duplicate, RucioException, KeyNotFound, InvalidValueForKey, UnsupportedValueType
from rucio.db import models
from rucio.db.session import get_session

session = get_session()


def add_key(key, type=None, regexp=None):
    """
    Adds a new allowed key.

    :param key: the name for the new key.
    :param type: the type of the value, if defined.
    :param regexp: the regular expression that values should match, if defined.
    """

    # Check if type is supported
    if type and type not in [str(t) for t in AUTHORIZED_VALUE_TYPES]:
        raise UnsupportedValueType('The type \'%(type)s\' is not supported for values!' % locals())

    new_key = models.DIDKey(key=key, type=type and str(type), regexp=regexp)
    try:
        new_key.save(session=session)
    except IntegrityError, e:
        session.rollback()
        if e.args[0] == "(IntegrityError) column key is not unique":
            raise Duplicate('key \'%(key)s\' already exists!' % locals())
        else:
            raise RucioException(e.args[0])
    session.commit()


def del_key(key):
    """
    Deletes a key.

    :param key: the name for the key.
    """
    pass


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
    """
    Adds a new value to a key.

    :param key: the name for the key.
    :param value: the value.
    """
    new_value = models.DIDKeyValueAssociation(key=key, value=value)
    try:
        new_value.save(session=session)
    except IntegrityError, e:
        session.rollback()
        print e.args[0]
        if e.args[0] == "(IntegrityError) columns key, value are not unique":
            raise Duplicate('key-value \'%(key)s-%(value)s\' already exists!' % locals())

        if e.args[0] == "(IntegrityError) foreign key constraint failed":
            raise KeyNotFound("key '%(key)s' does not exist!" % locals())
        if match('.*IntegrityError.*ORA-02291: integrity constraint.*DID_MAP_KEYS_FK.*violated.*', e.args[0]):
            raise KeyNotFound("key '%(key)s' does not exist!" % locals())
        if e.args[0] == "(IntegrityError) (1452, 'Cannot add or update a child row: a foreign key constraint fails (`rucio`.`did_key_map`, CONSTRAINT `DID_MAP_KEYS_FK` FOREIGN KEY (`key`) REFERENCES `did_keys` (`key`))')":
            raise KeyNotFound("key '%(key)s' does not exist!" % locals())

        raise RucioException(e.args[0])

    k = session.query(models.DIDKey).filter_by(key=key).one()

    # Check value against regexp, if defined
    if k.regexp and not match(k.regexp, value):
        session.rollback()
        raise InvalidValueForKey('The value %s for the key %s does not match the regular expression %s' % (value, key, k.regexp))

    # Check value type, if defined
    type_map = dict([(str(t), t) for t in AUTHORIZED_VALUE_TYPES])
    if k.type and not isinstance(value, type_map.get(k.type)):
            session.rollback()
            raise InvalidValueForKey('The value %s for the key %s does not match the required type %s' % (value, key, k.type))

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
