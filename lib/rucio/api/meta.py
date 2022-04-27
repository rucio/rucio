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

from rucio.api.permission import has_permission
from rucio.common.exception import AccessDenied
from rucio.core import meta
from rucio.db.sqla.session import read_session, transactional_session


@read_session
def list_keys(session=None):
    """
    Lists all keys.

    :param session: The database session in use.

    :returns: A list containing all keys.
    """
    return meta.list_keys(session=session)


@read_session
def list_values(key, session=None):
    """
    Lists all values for a key.

    :param key: the name for the key.
    :param session: The database session in use.


    :returns: A list containing all values.
    """
    return meta.list_values(key=key, session=session)


@transactional_session
def add_key(key, key_type, issuer, value_type=None, value_regexp=None, vo='def', session=None):
    """
    Add a new allowed key.

    :param key: the name for the new key.
    :param key_type: the type of the key: all(container, dataset, file), collection(dataset or container), file, derived(compute from file for collection).
    :param issuer: The issuer account.
    :param value_type: the type of the value, if defined.
    :param value_regexp: the regular expression that values should match, if defined.
    :param vo: The vo to act on
    :param session: The database session in use.
    """
    kwargs = {'key': key, 'key_type': key_type, 'value_type': value_type, 'value_regexp': value_regexp}
    if not has_permission(issuer=issuer, vo=vo, action='add_key', kwargs=kwargs, session=session):
        raise AccessDenied('Account %s can not add key' % (issuer))
    return meta.add_key(key=key, key_type=key_type, value_type=value_type, value_regexp=value_regexp, session=session)


@transactional_session
def add_value(key, value, issuer, vo='def', session=None):
    """
    Add a new value to a key.

    :param key: the name for the key.
    :param value: the value.
    :param vo: the vo to act on.
    :param session: The database session in use.
    """
    kwargs = {'key': key, 'value': value}
    if not has_permission(issuer=issuer, vo=vo, action='add_value', kwargs=kwargs, session=session):
        raise AccessDenied('Account %s can not add value %s to key %s' % (issuer, value, key))
    return meta.add_value(key=key, value=value, session=session)
