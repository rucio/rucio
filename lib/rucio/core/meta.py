# -*- coding: utf-8 -*-
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

from re import match

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound

from rucio.common.constraints import AUTHORIZED_VALUE_TYPES
from rucio.common.exception import (Duplicate, RucioException,
                                    KeyNotFound, InvalidValueForKey, UnsupportedValueType,
                                    InvalidObject, UnsupportedKeyType)
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType, KeyType
from rucio.db.sqla.session import read_session, transactional_session


@transactional_session
def add_key(key, key_type, value_type=None, value_regexp=None, session=None):
    """
    Adds a new allowed key.

    :param key: the name for the new key.
    :param key_type: the type of the key: all(container, dataset, file), collection(dataset or container), file, derived(compute from file for collection).
    :param value_type: the type of the value, if defined.
    :param value_regexp: the regular expression that values should match, if defined.
    :param session: The database session in use.
    """

    # Check if value_type is supported
    if value_type and value_type not in [str(t) for t in AUTHORIZED_VALUE_TYPES]:
        raise UnsupportedValueType('The type \'%(value_type)s\' is not supported for values!' % locals())

    # Convert key_type
    if isinstance(key_type, str):
        key_type = str(key_type)
    else:
        key_type = str(key_type.value)

    if key_type == 'F':
        key_type = 'FILE'
    elif key_type == 'D':
        key_type = 'DATASET'
    elif key_type == 'C':
        key_type = 'CONTAINER'

    try:
        key_type = KeyType(key_type)
    except ValueError:
        raise UnsupportedKeyType('The type \'%s\' is not supported for keys!' % str(key_type))

    new_key = models.DIDKey(key=key, value_type=value_type and str(value_type), value_regexp=value_regexp, key_type=key_type)
    try:
        new_key.save(session=session)
    except IntegrityError as error:
        if ('UNIQUE constraint failed' in error.args[0]) \
           or ('conflicts with persistent instance' in error.args[0]) \
           or match('.*IntegrityError.*ORA-00001: unique constraint.*DID_KEYS_PK.*violated.*', error.args[0]) \
           or match('.*IntegrityError.*1062.*Duplicate entry.*for key.*', error.args[0]) \
           or match('.*IntegrityError.*duplicate key value violates unique constraint.*', error.args[0]) \
           or match('.*UniqueViolation.*duplicate key value violates unique constraint.*', error.args[0]) \
           or match('.*IntegrityError.*columns? key.*not unique.*', error.args[0]):
            raise Duplicate('key \'%(key)s\' already exists!' % locals())
        raise


@transactional_session
def del_key(key, session=None):
    """
    Deletes a key.

    :param key: the name for the key.
    :param session: The database session in use.
    """
    session.query(models.DIDKey).filter(key == key).delete()


@read_session
def list_keys(session=None):
    """
    Lists all keys.

    :param session: The database session in use.

    :returns: A list containing all keys.
    """
    key_list = []
    query = session.query(models.DIDKey)
    for row in query:
        key_list.append(row.key)
    return key_list


@transactional_session
def add_value(key, value, session=None):
    """
    Adds a new value to a key.

    :param key: the name for the key.
    :param value: the value.
    :param session: The database session in use.
    """
    new_value = models.DIDKeyValueAssociation(key=key, value=value)
    try:
        new_value.save(session=session)
    except IntegrityError as error:
        if ('UNIQUE constraint failed' in error.args[0]) \
           or ('conflicts with persistent instance' in error.args[0]) \
           or match('.*IntegrityError.*ORA-00001: unique constraint.*DID_KEYS_PK.*violated.*', error.args[0]) \
           or match('.*IntegrityError.*1062.*Duplicate entry.*for key.*', error.args[0]) \
           or match('.*IntegrityError.*duplicate key value violates unique constraint.*', error.args[0]) \
           or match('.*UniqueViolation.*duplicate key value violates unique constraint.*', error.args[0]) \
           or match('.*IntegrityError.*columns? key.*value.*not unique.*', error.args[0]):
            raise Duplicate('key-value \'%(key)s-%(value)s\' already exists!' % locals())
        if match('.*IntegrityError.*foreign key constraints? failed.*', error.args[0]):
            raise KeyNotFound("key '%(key)s' does not exist!" % locals())
        if match('.*IntegrityError.*ORA-02291: integrity constraint.*DID_MAP_KEYS_FK.*violated.*', error.args[0]):
            raise KeyNotFound("key '%(key)s' does not exist!" % locals())
        if error.args[0] == "(IntegrityError) (1452, 'Cannot add or update a child row: a foreign key constraint fails (`rucio`.`did_key_map`, CONSTRAINT `DID_MAP_KEYS_FK` FOREIGN KEY (`key`) REFERENCES `did_keys` (`key`))')":
            raise KeyNotFound("key '%(key)s' does not exist!" % locals())

        raise RucioException(error.args)

    k = session.query(models.DIDKey).filter_by(key=key).one()

    # Check value against regexp, if defined
    if k.value_regexp and not match(k.value_regexp, value):
        raise InvalidValueForKey("The value '%s' for the key '%s' does not match the regular expression '%s'" % (value, key, k.value_regexp))

    # Check value type, if defined
    type_map = dict([(str(t), t) for t in AUTHORIZED_VALUE_TYPES])
    if k.value_type and not isinstance(value, type_map.get(k.value_type)):
        raise InvalidValueForKey("The value '%s' for the key '%s' does not match the required type '%s'" % (value, key, k.value_type))


@read_session
def list_values(key, session=None):
    """
    Lists all values for a key.

    :param key: the name for the key.
    :param session: The database session in use.

    :returns: A list containing all values.
    """
    value_list = []
    query = session.query(models.DIDKeyValueAssociation).filter_by(key=key)
    for row in query:
        value_list.append(row.value)
    return value_list


@read_session
def validate_meta(meta, did_type, session=None):
    """
    Validates metadata for a did.

    :param meta: the dictionary of metadata.
    :param meta: the type of the did, e.g, DATASET, CONTAINER, FILE.
    :param session: The database session in use.

    :returns: True
    """
    # For now only validate the datatype for datasets
    key = 'datatype'
    if did_type == DIDType.DATASET and key in meta:
        try:
            session.query(models.DIDKeyValueAssociation.value).\
                filter_by(key=key).\
                filter_by(value=meta[key]).\
                one()
        except NoResultFound:
            print("The value '%s' for the key '%s' is not valid" % (meta[key], key))
            raise InvalidObject("The value '%s' for the key '%s' is not valid" % (meta[key], key))
