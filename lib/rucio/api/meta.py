# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
#
# PY3K COMPATIBLE

from rucio.api.permission import has_permission
from rucio.common.exception import AccessDenied
from rucio.core import meta


def list_keys():
    """
    Lists all keys.

    :returns: A list containing all keys.
    """
    return meta.list_keys()


def list_values(key):
    """
    Lists all values for a key.

    :param key: the name for the key.


    :returns: A list containing all values.
    """
    return meta.list_values(key=key)


def add_key(key, key_type, issuer, value_type=None, value_regexp=None, vo='def'):
    """
    Add a new allowed key.

    :param key: the name for the new key.
    :param key_type: the type of the key: all(container, dataset, file), collection(dataset or container), file, derived(compute from file for collection).
    :param issuer: The issuer account.
    :param value_type: the type of the value, if defined.
    :param value_regexp: the regular expression that values should match, if defined.
    :param vo: The vo to act on
    """
    kwargs = {'key': key, 'key_type': key_type, 'value_type': value_type, 'value_regexp': value_regexp}
    if not has_permission(issuer=issuer, vo=vo, action='add_key', kwargs=kwargs):
        raise AccessDenied('Account %s can not add key' % (issuer))
    return meta.add_key(key=key, key_type=key_type, value_type=value_type, value_regexp=value_regexp)


def add_value(key, value, issuer, vo='def'):
    """
    Add a new value to a key.

    :param key: the name for the key.
    :param value: the value.
    :param vo: the vo to act on.
    """
    kwargs = {'key': key, 'value': value}
    if not has_permission(issuer=issuer, vo=vo, action='add_value', kwargs=kwargs):
        raise AccessDenied('Account %s can not add value %s to key %s' % (issuer, value, key))
    return meta.add_value(key=key, value=value)
