'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the
  License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2015
  - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2013,2015
  - Yun-Pin Sun, <yun-pin.sun@cern.ch>, 2013
  - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2014
  - Martin Barisits, <martin.barisits@cern.ch>, 2014-2015
'''

import rucio.api.permission

from rucio.core import did, naming_convention, meta as meta_core
from rucio.common.constants import RESERVED_KEYS
from rucio.common.schema import validate_schema
from rucio.db.sqla.constants import DIDType


def list_dids(scope, filters, type='collection', ignore_case=False, limit=None, offset=None, long=False):
    """
    List dids in a scope.

    :param scope: The scope name.
    :param pattern: The wildcard pattern.
    :param type:  The type of the did: all(container, dataset, file), collection(dataset or container), dataset, container
    :param ignore_case: Ignore case distinctions.
    :param limit: The maximum number of DIDs returned.
    :param offset: Offset number.
    :param long: Long format option to display more information for each DID.
    """
    validate_schema(name='did_filters', obj=filters)
    return did.list_dids(scope=scope, filters=filters, type=type, ignore_case=ignore_case,
                         limit=limit, offset=offset, long=long)


def add_did(scope, name, type, issuer, account=None, statuses={}, meta={}, rules=[], lifetime=None, dids=[], rse=None):
    """
    Add data did.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param type: The data identifier type.
    :param issuer: The issuer account.
    :param account: The account owner. If None, then issuer is selected as owner.
    :param statuses: Dictionary with statuses, e.g.g {'monotonic':True}.
    :meta: Meta-data associated with the data identifier is represented using key/value pairs in a dictionary.
    :rules: Replication rules associated with the data did. A list of dictionaries, e.g., [{'copies': 2, 'rse_expression': 'TIERS1'}, ].
    :param lifetime: DID's lifetime (in seconds).
    :param dids: The content.
    :param rse: The RSE name when registering replicas.
    """
    validate_schema(name='name', obj=name)
    validate_schema(name='scope', obj=scope)
    validate_schema(name='dids', obj=dids)
    validate_schema(name='rse', obj=rse)
    kwargs = {'scope': scope, 'name': name, 'type': type, 'issuer': issuer, 'account': account, 'statuses': statuses, 'meta': meta, 'rules': rules, 'lifetime': lifetime}
    if not rucio.api.permission.has_permission(issuer=issuer, action='add_did', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add data identifier to scope %s' % (issuer, scope))

    if type == 'DATASET':
        # naming_convention validation
        extra_meta = naming_convention.validate_name(scope=scope, name=name, did_type='D')

        # merge extra_meta with meta
        for k in extra_meta or {}:
            if k not in meta:
                meta[k] = extra_meta[k]
            elif meta[k] != extra_meta[k]:
                print "Provided metadata %s doesn't match the naming convention: %s != %s" % (k, meta[k], extra_meta[k])
                raise rucio.common.exception.InvalidObject("Provided metadata %s doesn't match the naming convention: %s != %s" % (k, meta[k], extra_meta[k]))

        # Validate metadata
        meta_core.validate_meta(meta=meta, did_type=DIDType.from_sym(type))

    return did.add_did(scope=scope, name=name, type=DIDType.from_sym(type), account=account or issuer,
                       statuses=statuses, meta=meta, rules=rules, lifetime=lifetime,
                       dids=dids, rse=rse)


def add_dids(dids, issuer):
    """
    Bulk Add did.

    :param dids: A list of dids.
    :param issuer: The issuer account.
    """
    kwargs = {'issuer': issuer, 'dids': dids}
    if not rucio.api.permission.has_permission(issuer=issuer, action='add_dids', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not bulk add data identifier' % (issuer))

    return did.add_dids(dids, account=issuer)


def attach_dids(scope, name, attachment, issuer):
    """
    Append content to data did.

    :param attachment: The attachment.
    :param issuer: The issuer account.
    """
    validate_schema(name='attachment', obj=attachment)

    kwargs = {'scope': scope, 'name': name, 'attachment': attachment}
    if not rucio.api.permission.has_permission(issuer=issuer, action='attach_dids', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add data identifiers to %s:%s' % (issuer, scope, name))

    return did.attach_dids(scope=scope, name=name, dids=attachment['dids'],
                           account=attachment.get('account', issuer), rse=attachment.get('rse'))


def attach_dids_to_dids(attachments, issuer, ignore_duplicate=False):
    """
    Append content to dids.

    :param attachments: The contents.
    :param issuer: The issuer account.
    :param ignore_duplicate: If True, ignore duplicate entries.
    """
    validate_schema(name='attachments', obj=attachments)

    if not rucio.api.permission.has_permission(issuer=issuer, action='attach_dids_to_dids', kwargs={'attachments': attachments}):
        raise rucio.common.exception.AccessDenied('Account %s can not add data identifiers' % (issuer))

    return did.attach_dids_to_dids(attachments=attachments, account=issuer,
                                   ignore_duplicate=ignore_duplicate)


def detach_dids(scope, name, dids, issuer):
    """
    Detach data identifier

    :param scope: The scope name.
    :param name: The data identifier name.
    :param dids: The content.
    :param issuer: The issuer account.
    """
    kwargs = {'scope': scope, 'name': name, 'dids': dids, 'issuer': issuer}
    if not rucio.api.permission.has_permission(issuer=issuer, action='detach_dids', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not detach data identifiers from %s:%s' % (issuer, scope, name))
    return did.detach_dids(scope=scope, name=name, dids=dids)


def list_new_dids(type=None, thread=None, total_threads=None, chunk_size=1000):
    """
    List recent identifiers.

    :param type : The DID type.
    """
    return did.list_new_dids(did_type=type and DIDType.from_sym(type), thread=thread, total_threads=total_threads, chunk_size=chunk_size)


def set_new_dids(dids, new_flag=True):
    """
    Set/reset the flag new

    :param scope: The scope name.
    :param name: The data identifier name.
    :param new_flag: A boolean to flag new DIDs.
    """
    return did.set_new_dids(dids, new_flag)


def list_content(scope, name):
    """
    List data identifier contents.

    :param scope: The scope name.
    :param name: The data identifier name.
    """
    return did.list_content(scope=scope, name=name)


def list_files(scope, name, long):
    """
    List data identifier file contents.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param long:       A boolean to choose if GUID is returned or not.
    """

    return did.list_files(scope=scope, name=name, long=long)


def scope_list(scope, name=None, recursive=False):
    """
    List data identifiers in a scope.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param recursive: boolean, True or False.
    """

    return did.scope_list(scope, name=name, recursive=recursive)


def get_did(scope, name, dynamic=False):
    """
    Retrieve a single data did.

    :param scope: The scope name.
    :param name: The data identifier name.
    :return did: Dictionary containing {'name', 'scope', 'type'}, Exception otherwise
    """

    return did.get_did(scope=scope, name=name, dynamic=dynamic)


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

    if key in RESERVED_KEYS:
        raise rucio.common.exception.AccessDenied('Account %s can not change this metadata value to data identifier %s:%s' % (issuer, scope, name))

    if not rucio.api.permission.has_permission(issuer=issuer, action='set_metadata', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add metadata to data identifier %s:%s' % (issuer, scope, name))
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


def get_dataset_by_guid(guid):
    """
    Get the parent datasets for a given GUID.
    :param guid: The GUID.

    :returns: A did
    """
    return did.get_dataset_by_guid(guid=guid)


def list_parent_dids(scope, name):
    """
    List parent datasets and containers of a did.

    :param scope:   The scope.
    :param name:    The name.
    """

    return did.list_parent_dids(scope=scope, name=name)


def create_did_sample(input_scope, input_name, output_scope, output_name, issuer, nbfiles):
    """
    Create a sample from an input collection.

    :param input_scope: The scope of the input DID.
    :param input_name: The name of the input DID.
    :param output_scope: The scope of the output dataset.
    :param output_name: The name of the output dataset.
    :param account: The account.
    :param nbfiles: The number of files to register in the output dataset.
    :param session: The database session in use.
    """
    kwargs = {'issuer': issuer, 'scope': output_scope}
    if not rucio.api.permission.has_permission(issuer=issuer, action='create_did_sample', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not bulk add data identifier' % (issuer))
    return did.create_did_sample(input_scope=input_scope, input_name=input_name, output_scope=output_scope, output_name=output_name, account=issuer, nbfiles=nbfiles)
