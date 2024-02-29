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
from typing import TYPE_CHECKING, Optional, Union

from sqlalchemy import select, and_
from sqlalchemy.exc import IntegrityError, NoResultFound

from rucio.common.constraints import AUTHORIZED_VALUE_TYPES
from rucio.common.exception import (Duplicate, RucioException,
                                    KeyNotFound, InvalidValueForKey, UnsupportedValueType,
                                    InvalidObject, UnsupportedKeyType)
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType, KeyType
from rucio.db.sqla.session import read_session, transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


@transactional_session
def add_key(key: str, key_type: Union[KeyType, str], value_type: Optional[str] = None, value_regexp: Optional[str] = None, *, session: "Session") -> None:
    """
    Add an allowed key for DID metadata (update the DID Metadata Conventions table with a new key).

    :param key: the name for the new key.
    :param key_type: the type of the key: all(container, dataset, file), collection(dataset or container), file, derived(compute from file for collection).
    :param value_type: the type of the value, if defined.
    :param value_regexp: the regular expression that values should match, if defined.
    :param session: The database session in use.
    """

    # Check if value_type is supported
    if value_type and value_type not in [str(t) for t in AUTHORIZED_VALUE_TYPES]:
        raise UnsupportedValueType(f"The type '{value_type}' is not supported for values!")

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

    new_key = models.DIDMetaConventionsKey(key=key, value_type=value_type and str(value_type), value_regexp=value_regexp, key_type=key_type)
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
            raise Duplicate(f"key '{key}' already exists!")
        raise RucioException(error.args)


@transactional_session
def del_key(key: str, *, session: "Session") -> None:
    """
    Delete a key in the DID Metadata Conventions table.

    :param key: the name for the key.
    :param session: The database session in use.
    """
    statement = select(models.DIDMetaConventionsKey.key).where(models.DIDMetaConventionsKey.key == key)
    session.delete(statement)


@read_session
def list_keys(*, session: "Session") -> list[str]:
    """
    Lists all keys for DID Metadata Conventions.

    :param session: The database session in use.

    :returns: A list containing all keys.
    """
    key_list = []
    statement = select(models.DIDMetaConventionsKey.key)
    query = session.execute(statement).scalars()
    for row in query:
        key_list.append(row)
    return key_list


@transactional_session
def add_value(key: str, value: str, *, session: "Session") -> None:
    """
    Adds a new value for a key in DID Metadata Convention.

    :param key: the name for the key.
    :param value: the value.
    :param session: The database session in use.

    :raises Duplicate: Key-Value pair exists
    :raises KeyNotFound: Key not in metadata conventions table
    :raises InvalidValueForKey: Value conflicts with rse expression for key values or does not have the correct type
    """
    new_value = models.DIDMetaConventionsConstraints(key=key, value=value)
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
            raise Duplicate(f"key-value '{key}-{value}' already exists!")
        if match('.*IntegrityError.*foreign key constraints? failed.*', error.args[0]):
            raise KeyNotFound(f"key '{key}' does not exist!")
        if match('.*IntegrityError.*ORA-02291: integrity constraint.*DID_MAP_KEYS_FK.*violated.*', error.args[0]):
            raise KeyNotFound(f"key '{key}' does not exist!")
        if error.args[0] == "(IntegrityError) (1452, 'Cannot add or update a child row: a foreign key constraint fails (`rucio`.`did_key_map`, CONSTRAINT `DID_MAP_KEYS_FK` FOREIGN KEY (`key`) REFERENCES `did_keys` (`key`))')":
            raise KeyNotFound(f"key '{key}' does not exist!")

        raise RucioException(error.args)

    statement = select(
        models.DIDMetaConventionsKey,
    ).where(
        models.DIDMetaConventionsKey.key == key
    )
    query = session.execute(statement).scalar_one()

    # Check value against regexp, if defined
    if query.value_regexp and not match(query.value_regexp, value):
        raise InvalidValueForKey(f"The value {value} for the key {key} does not match the regular expression {query.value_regexp}")

    # Check value type, if defined
    type_map = dict([(str(t), t) for t in AUTHORIZED_VALUE_TYPES])
    if query.value_type and not isinstance(value, type_map.get(query.value_type)):  # type: ignore ; Typing error caused by 'isinstaince' not thinking types count as classes
        raise InvalidValueForKey(f"The value {value} for the key {key} does not match the required type {query.value_type}")


@read_session
def list_values(key: str, *, session: "Session") -> list[str]:
    """
    Lists all allowed values for a DID key (all values for a key in DID Metadata Conventions).

    :param key: the name for the key.
    :param session: The database session in use.

    :returns: A list containing all values.
    """
    value_list = []
    statement = select(models.DIDMetaConventionsConstraints.value).where(models.DIDMetaConventionsConstraints.key == key)
    query = session.execute(statement).scalars()
    for row in query:
        value_list.append(row)
    return value_list


@read_session
def validate_meta(meta: dict, did_type: DIDType, *, session: "Session") -> None:
    """
    Validates metadata for a did.

    :param meta: the dictionary of metadata.
    :param meta: the type of the did, e.g, DATASET, CONTAINER, FILE.
    :param session: The database session in use.

    :raises InvalidObject:
    """
    # For now only validate the datatype for datasets
    key = 'datatype'
    if did_type == DIDType.DATASET and key in meta:
        try:
            statement = select(
                models.DIDMetaConventionsConstraints.value
            ).where(
                and_(models.DIDMetaConventionsConstraints.value == meta[key], models.DIDMetaConventionsConstraints.key == key)
            )
            session.execute(statement).one()
        except NoResultFound:
            raise InvalidObject(f"The value {meta[key]}' for the key {key} is not valid")
