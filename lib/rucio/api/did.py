# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the
# License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2013
# - Yun-Pin Sun, <yun-pin.sun@cern.ch>, 2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013

import rucio.api.permission

from rucio.core import did


def list_replicas(scope, name, schemes=None):
    """
    List file replicas for a data did.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param schemes: A list of schemes to filter the replicas.
    """

    return did.list_replicas(scope=scope, name=name, schemes=schemes)


def add_identifier(scope, name, type, issuer, account=None, statuses={}, meta=[], rules=[], lifetime=None):
    """
    Add data did.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param type: The data identifier type.
    :param issuer: The issuer account.
    :param account: The account owner. If None, then issuer is selected as owner.
    :param statuses: Dictionary with statuses, e.g.g {'monotonic':True}.
    :meta: Meta-data associated with the data identifier is represented using key/value pairs in a dictionary.
    :param lifetime: DID's lifetime (in seconds).
    :rules: Replication rules associated with the data did. A list of dictionaries, e.g., [{'copies': 2, 'rse_expression': 'TIERS1'}, ].
    """

    kwargs = {'scope': scope, 'name': name, 'type': type, 'issuer': issuer, 'account': account, 'statuses': statuses, 'meta': meta, 'rules': rules, 'lifetime': lifetime}
    if not rucio.api.permission.has_permission(issuer=issuer, action='add_identifier', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add data identifier to scope %s' % (issuer, scope))
    return did.add_identifier(scope=scope, name=name, type=type, account=account or issuer, statuses=statuses, meta=meta, rules=rules, lifetime=lifetime)


def append_identifier(scope, name, dids, issuer, account=None):
    """
    Append content to data did.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param dids: The content as a list of data identifiers.
    :param issuer: The issuer account.
    :param account: The account owner. If None, then issuer is selected.

    """

    kwargs = {'scope': scope, 'name': name, 'dids': dids, 'issuer': issuer, 'account': account}
    if not rucio.api.permission.has_permission(issuer=issuer, action='append_identifier', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add data identifiers to %s:%s' % (issuer, scope, name))
    return did.append_identifier(scope=scope, name=name, dids=dids, account=account or issuer)


def detach_identifier(scope, name, dids, issuer):
    """
    Detach data identifier

    :param scope: The scope name.
    :param name: The data identifier name.
    :param dids: The content.
    :param issuer: The issuer account.
    """

    kwargs = {'scope': scope, 'name': name, 'dids': dids, 'issuer': issuer}
    if not rucio.api.permission.has_permission(issuer=issuer, action='detach_identifier', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not detach data identifiers from %s:%s' % (issuer, scope, name))
    return did.detach_identifier(scope=scope, name=name, dids=dids, issuer=issuer)


def list_new_identifier(type=None):
    """
    List recent identifiers.

    :param type : The DID type.
    """
    return did.list_new_identifier(type)


def set_new_identifier(scope, name, new_flag=True):
    """
    Set/reset the flag new

    :param scope: The scope name.
    :param name: The data identifier name.
    :param new_flag: A boolean to flag new DIDs.
    """
    return did.set_new_identifier(scope, name, new_flag)


def list_content(scope, name):
    """
    List data identifier contents.

    :param scope: The scope name.
    :param name: The data identifier name.
    """
    return did.list_content(scope=scope, name=name)


def list_files(scope, name):
    """
    List data identifier file contents.

    :param scope: The scope name.
    :param name: The data identifier name.
    """

    return did.list_files(scope=scope, name=name)


def scope_list(scope, name=None, recursive=False):
    """
    List data identifiers in a scope.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param recursive: boolean, True or False.
    """

    return did.scope_list(scope, name=name, recursive=recursive)


def get_did(scope, name):
    """
    Retrieve a single data did.

    :param scope: The scope name.
    :param name: The data identifier name.
    :return did: Dictionary containing {'name', 'scope', 'type'}, Exception otherwise
    """

    return did.get_did(scope=scope, name=name)


def set_metadata(scope, name, key, value, issuer):
    """
    Add metadata to data did.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param key: the key.
    :param value: the value.
    :param issuer: The issuer account.
    """

    kwargs = {'scope': scope, 'name': name, 'key': key, 'value': value, 'issuer': issuer}
    if not rucio.api.permission.has_permission(issuer=issuer, action='set_metadata', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add metadate to data identifier %s:%s' % (issuer, scope, name))
    return did.set_metadata(scope=scope, name=name, key=key, value=value)


def get_metadata(scope, name):
    """
    Get data identifier metadata

    :param scope: The scope name.
    :param name: The data identifier name.
    """
    return did.get_metadata(scope=scope, name=name)


def set_status(scope, name, issuer, **kwargs):
    """
    Set data identifier status

    :param scope: The scope name.
    :param name: The data identifier name.
    :param issuer: The issuer account.
    :param kwargs:  Keyword arguments of the form status_name=value.
    """

    if not rucio.api.permission.has_permission(issuer=issuer, action='set_status', kwargs={'scope': scope, 'name': name, 'issuer': issuer}):
        raise rucio.common.exception.AccessDenied('Account %s can not set status on data identifier %s:%s' % (issuer, scope, name))
    return did.set_status(scope=scope, name=name, **kwargs)
