# -*- coding: utf-8 -*-
# Copyright 2013-2020 CERN
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
#
# Authors:
# - Vincent Garonne <vincent.garonne@cern.ch>, 2013-2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013-2020
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2020
# - Yun-Pin Sun <winter0128@gmail.com>, 2013
# - Thomas Beermann <thomas.beermann@cern.ch>, 2013
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2020
# - asket <asket.agarwal96@gmail.com>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Ruturaj Gujar <ruturaj.gujar23@gmail.com>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Eric Vaandering <ewv@fnal.gov>, 2020
# - Aristeidis Fkiaras <aristeidis.fkiaras@cern.ch>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from __future__ import print_function

from copy import deepcopy

import rucio.api.permission
from rucio.common.constants import RESERVED_KEYS
from rucio.common.exception import RucioException
from rucio.common.schema import validate_schema
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import api_update_return_dict
from rucio.core import did, naming_convention, meta as meta_core
from rucio.core.rse import get_rse_id
from rucio.db.sqla.constants import DIDType


def list_dids(scope, filters, type='collection', ignore_case=False, limit=None, offset=None, long=False, recursive=False, vo='def'):
    """
    List dids in a scope.

    :param scope: The scope name.
    :param pattern: The wildcard pattern.
    :param type:  The type of the did: all(container, dataset, file), collection(dataset or container), dataset, container
    :param ignore_case: Ignore case distinctions.
    :param limit: The maximum number of DIDs returned.
    :param offset: Offset number.
    :param long: Long format option to display more information for each DID.
    :param recursive: Recursively list DIDs content.
    :param vo: The VO to act on.
    """
    validate_schema(name='did_filters', obj=filters, vo=vo)

    scope = InternalScope(scope, vo=vo)

    if 'account' in filters:
        filters['account'] = InternalAccount(filters['account'], vo=vo)
    if 'scope' in filters:
        filters['scope'] = InternalScope(filters['scope'], vo=vo)

    result = did.list_dids(scope=scope, filters=filters, type=type, ignore_case=ignore_case,
                           limit=limit, offset=offset, long=long, recursive=recursive)

    for d in result:
        yield api_update_return_dict(d)


def list_dids_extended(scope, filters, type='collection', ignore_case=False, limit=None, offset=None, long=False, recursive=False, vo='def'):
    """
    List dids in a scope.

    :param scope: The scope name.
    :param pattern: The wildcard pattern.
    :param type:  The type of the did: all(container, dataset, file), collection(dataset or container), dataset, container
    :param ignore_case: Ignore case distinctions.
    :param limit: The maximum number of DIDs returned.
    :param offset: Offset number.
    :param long: Long format option to display more information for each DID.
    :param recursive: Recursively list DIDs content.
    """
    validate_schema(name='did_filters', obj=filters, vo=vo)
    scope = InternalScope(scope, vo=vo)

    if 'account' in filters:
        filters['account'] = InternalAccount(filters['account'], vo=vo)
    if 'scope' in filters:
        filters['scope'] = InternalScope(filters['scope'], vo=vo)

    result = did.list_dids_extended(scope=scope, filters=filters, type=type, ignore_case=ignore_case,
                                    limit=limit, offset=offset, long=long, recursive=recursive)

    for d in result:
        yield api_update_return_dict(d)


def add_did(scope, name, type, issuer, account=None, statuses={}, meta={}, rules=[], lifetime=None, dids=[], rse=None, vo='def'):
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
    :param vo: The VO to act on.
    """
    v_did = {'name': name, 'type': type.upper(), 'scope': scope}
    validate_schema(name='did', obj=v_did, vo=vo)
    validate_schema(name='dids', obj=dids, vo=vo)
    validate_schema(name='rse', obj=rse, vo=vo)
    kwargs = {'scope': scope, 'name': name, 'type': type, 'issuer': issuer, 'account': account, 'statuses': statuses, 'meta': meta, 'rules': rules, 'lifetime': lifetime}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='add_did', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add data identifier to scope %s' % (issuer, scope))

    if account is not None:
        account = InternalAccount(account, vo=vo)
    issuer = InternalAccount(issuer, vo=vo)
    scope = InternalScope(scope, vo=vo)
    for d in dids:
        d['scope'] = InternalScope(d['scope'], vo=vo)
    for r in rules:
        r['account'] = InternalAccount(r['account'], vo=vo)

    rse_id = None
    if rse is not None:
        rse_id = get_rse_id(rse=rse, vo=vo)

    if type == 'DATASET':
        # naming_convention validation
        extra_meta = naming_convention.validate_name(scope=scope, name=name, did_type='D')

        # merge extra_meta with meta
        for k in extra_meta or {}:
            if k not in meta:
                meta[k] = extra_meta[k]
            elif meta[k] != extra_meta[k]:
                print("Provided metadata %s doesn't match the naming convention: %s != %s" % (k, meta[k], extra_meta[k]))
                raise rucio.common.exception.InvalidObject("Provided metadata %s doesn't match the naming convention: %s != %s" % (k, meta[k], extra_meta[k]))

        # Validate metadata
        meta_core.validate_meta(meta=meta, did_type=DIDType[type.upper()])

    return did.add_did(scope=scope, name=name, type=DIDType[type.upper()], account=account or issuer,
                       statuses=statuses, meta=meta, rules=rules, lifetime=lifetime,
                       dids=dids, rse_id=rse_id)


def add_dids(dids, issuer, vo='def'):
    """
    Bulk Add did.

    :param dids: A list of dids.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    """
    for d in dids:
        if 'rse' in d:
            rse_id = None
            if d['rse'] is not None:
                rse_id = get_rse_id(rse=d['rse'], vo=vo)
            d['rse_id'] = rse_id

    kwargs = {'issuer': issuer, 'dids': dids}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='add_dids', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not bulk add data identifier' % (issuer))

    issuer = InternalAccount(issuer, vo=vo)
    for d in dids:
        d['scope'] = InternalScope(d['scope'], vo=vo)
        if 'account' in d.keys():
            d['account'] = InternalAccount(d['account'], vo=vo)
        if 'dids' in d.keys():
            for child in d['dids']:
                child['scope'] = InternalScope(child['scope'], vo=vo)
    return did.add_dids(dids, account=issuer)


def attach_dids(scope, name, attachment, issuer, vo='def'):
    """
    Append content to data did.

    :param attachment: The attachment.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    """
    validate_schema(name='attachment', obj=attachment, vo=vo)

    rse_id = None
    if 'rse' in attachment:
        if attachment['rse'] is not None:
            rse_id = get_rse_id(rse=attachment['rse'], vo=vo)
        attachment['rse_id'] = rse_id

    kwargs = {'scope': scope, 'name': name, 'attachment': attachment}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='attach_dids', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add data identifiers to %s:%s' % (issuer, scope, name))

    scope = InternalScope(scope, vo=vo)
    issuer = InternalAccount(issuer, vo=vo)
    if 'account' in attachment.keys():
        attachment['account'] = InternalAccount(attachment['account'], vo=vo)
    for d in attachment['dids']:
        d['scope'] = InternalScope(d['scope'], vo=vo)
        if 'account' in d.keys():
            d['account'] = InternalAccount(d['account'], vo=vo)

    if rse_id is not None:
        dids = did.attach_dids(scope=scope, name=name, dids=attachment['dids'],
                               account=attachment.get('account', issuer), rse_id=rse_id)
    else:
        dids = did.attach_dids(scope=scope, name=name, dids=attachment['dids'],
                               account=attachment.get('account', issuer))

    return dids


def attach_dids_to_dids(attachments, issuer, ignore_duplicate=False, vo='def'):
    """
    Append content to dids.

    :param attachments: The contents.
    :param issuer: The issuer account.
    :param ignore_duplicate: If True, ignore duplicate entries.
    :param vo: The VO to act on.
    """
    validate_schema(name='attachments', obj=attachments, vo=vo)

    for a in attachments:
        if 'rse' in a:
            rse_id = None
            if a['rse'] is not None:
                rse_id = get_rse_id(rse=a['rse'], vo=vo)
            a['rse_id'] = rse_id

    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='attach_dids_to_dids', kwargs={'attachments': attachments}):
        raise rucio.common.exception.AccessDenied('Account %s can not add data identifiers' % (issuer))

    issuer = InternalAccount(issuer, vo=vo)
    for attachment in attachments:
        attachment['scope'] = InternalScope(attachment['scope'], vo=vo)
        for d in attachment['dids']:
            d['scope'] = InternalScope(d['scope'], vo=vo)
            if 'account' in d.keys():
                d['account'] = InternalAccount(d['account'], vo=vo)

    return did.attach_dids_to_dids(attachments=attachments, account=issuer,
                                   ignore_duplicate=ignore_duplicate)


def detach_dids(scope, name, dids, issuer, vo='def'):
    """
    Detach data identifier

    :param scope: The scope name.
    :param name: The data identifier name.
    :param dids: The content.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    """
    kwargs = {'scope': scope, 'name': name, 'dids': dids, 'issuer': issuer}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='detach_dids', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not detach data identifiers from %s:%s' % (issuer, scope, name))

    scope = InternalScope(scope, vo=vo)
    for d in dids:
        d['scope'] = InternalScope(d['scope'], vo=vo)

    return did.detach_dids(scope=scope, name=name, dids=dids)


def list_new_dids(type=None, thread=None, total_threads=None, chunk_size=1000, vo='def'):
    """
    List recent identifiers.

    :param type : The DID type.
    :param thread: The assigned thread for this necromancer.
    :param total_threads: The total number of threads of all necromancers.
    :param chunk_size: Number of requests to return per yield.
    :param vo: The VO to act on.
    """
    dids = did.list_new_dids(did_type=type and DIDType[type.upper()], thread=thread, total_threads=total_threads, chunk_size=chunk_size)
    for d in dids:
        if d['scope'].vo == vo:
            yield api_update_return_dict(d)


def set_new_dids(dids, new_flag=True, vo='def'):
    """
    Set/reset the flag new

    :param scope: The scope name.
    :param name: The data identifier name.
    :param new_flag: A boolean to flag new DIDs.
    :param vo: The VO to act on.
    """
    for d in dids:
        d['scope'] = InternalScope(d['scope'], vo=vo)

    return did.set_new_dids(dids, new_flag)


def list_content(scope, name, vo='def'):
    """
    List data identifier contents.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param vo: The VO to act on.
    """

    scope = InternalScope(scope, vo=vo)

    dids = did.list_content(scope=scope, name=name)
    for d in dids:
        yield api_update_return_dict(d)


def list_content_history(scope, name, vo='def'):
    """
    List data identifier contents history.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param vo: The VO to act on.
    """

    scope = InternalScope(scope, vo=vo)

    dids = did.list_content_history(scope=scope, name=name)

    for d in dids:
        yield api_update_return_dict(d)


def list_files(scope, name, long, vo='def'):
    """
    List data identifier file contents.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param long:       A boolean to choose if GUID is returned or not.
    :param vo: The VO to act on.
    """

    scope = InternalScope(scope, vo=vo)

    dids = did.list_files(scope=scope, name=name, long=long)

    for d in dids:
        yield api_update_return_dict(d)


def scope_list(scope, name=None, recursive=False, vo='def'):
    """
    List data identifiers in a scope.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param recursive: boolean, True or False.
    :param vo: The VO to act on.
    """

    scope = InternalScope(scope, vo=vo)

    dids = did.scope_list(scope, name=name, recursive=recursive)

    for d in dids:
        ret_did = deepcopy(d)
        ret_did['scope'] = ret_did['scope'].external
        if ret_did['parent'] is not None:
            ret_did['parent']['scope'] = ret_did['parent']['scope'].external
        yield ret_did


def get_did(scope, name, dynamic=False, vo='def'):
    """
    Retrieve a single data did.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param dynamic:  Dynamically resolve the bytes and length of the did
    :param vo: The VO to act on.
    :return did: Dictionary containing {'name', 'scope', 'type'}, Exception otherwise
    """

    scope = InternalScope(scope, vo=vo)

    d = did.get_did(scope=scope, name=name, dynamic=dynamic)
    return api_update_return_dict(d)


def set_metadata(scope, name, key, value, issuer, recursive=False, vo='def'):
    """
    Add metadata to data did.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param key: the key.
    :param value: the value.
    :param issuer: The issuer account.
    :param recursive: Option to propagate the metadata update to content.
    :param vo: The VO to act on.
    """
    kwargs = {'scope': scope, 'name': name, 'key': key, 'value': value, 'issuer': issuer}

    if key in RESERVED_KEYS:
        raise rucio.common.exception.AccessDenied('Account %s can not change this metadata value to data identifier %s:%s' % (issuer, scope, name))

    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='set_metadata', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add metadata to data identifier %s:%s' % (issuer, scope, name))

    scope = InternalScope(scope, vo=vo)
    return did.set_metadata(scope=scope, name=name, key=key, value=value, recursive=recursive)


def set_metadata_bulk(scope, name, meta, issuer, recursive=False, vo='def'):
    """
    Add metadata to data did.

    :param scope: The scope name.
    :param name: The data identifier name.
    :param meta: the key-values.
    :param issuer: The issuer account.
    :param recursive: Option to propagate the metadata update to content.
    :param vo: The VO to act on.
    """
    kwargs = {'scope': scope, 'name': name, 'meta': meta, 'issuer': issuer}

    for key in meta:
        if key in RESERVED_KEYS:
            raise rucio.common.exception.AccessDenied('Account %s can not change the value of the metadata key %s to data identifier %s:%s' % (issuer, key, scope, name))

    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='set_metadata_bulk', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not add metadata to data identifier %s:%s' % (issuer, scope, name))

    scope = InternalScope(scope, vo=vo)
    return did.set_metadata_bulk(scope=scope, name=name, meta=meta, recursive=recursive)


def get_metadata(scope, name, plugin='DID_COLUMN', vo='def'):
    """
    Get data identifier metadata

    :param scope: The scope name.
    :param name: The data identifier name.
    :param vo: The VO to act on.
    """

    scope = InternalScope(scope, vo=vo)

    d = did.get_metadata(scope=scope, name=name, plugin=plugin)
    return api_update_return_dict(d)


def get_metadata_bulk(dids, vo='def', session=None):
    """
    Get metadata for a list of dids
    :param dids: A list of dids.
    :param session: The database session in use.
    """

    validate_schema(name='dids', obj=dids, vo=vo)
    for entry in dids:
        entry['scope'] = InternalScope(entry['scope'], vo=vo)
    meta = did.get_metadata_bulk(dids)
    for met in meta:
        yield api_update_return_dict(met)


def delete_metadata(scope, name, key, vo='def'):
    """
    Delete a key from the metadata column

    :param scope: the scope of did
    :param name: the name of the did
    :param key: the key to be deleted
    :param vo: The VO to act on.
    """

    scope = InternalScope(scope, vo=vo)
    return did.delete_metadata(scope=scope, name=name, key=key)


def set_status(scope, name, issuer, vo='def', **kwargs):
    """
    Set data identifier status

    :param scope: The scope name.
    :param name: The data identifier name.
    :param issuer: The issuer account.
    :param kwargs:  Keyword arguments of the form status_name=value.
    :param vo: The VO to act on.
    """

    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='set_status', kwargs={'scope': scope, 'name': name, 'issuer': issuer}):
        raise rucio.common.exception.AccessDenied('Account %s can not set status on data identifier %s:%s' % (issuer, scope, name))

    scope = InternalScope(scope, vo=vo)

    return did.set_status(scope=scope, name=name, **kwargs)


def get_dataset_by_guid(guid, vo='def'):
    """
    Get the parent datasets for a given GUID.
    :param guid: The GUID.
    :param vo: The VO to act on.

    :returns: A did
    """
    dids = did.get_dataset_by_guid(guid=guid)

    for d in dids:
        if d['scope'].vo != vo:
            raise RucioException('GUID unavailable on VO {}'.format(vo))
        yield api_update_return_dict(d)


def list_parent_dids(scope, name, vo='def'):
    """
    List parent datasets and containers of a did.

    :param scope:   The scope.
    :param name:    The name.
    :param vo:      The VO to act on.
    """

    scope = InternalScope(scope, vo=vo)

    dids = did.list_parent_dids(scope=scope, name=name)

    for d in dids:
        yield api_update_return_dict(d)


def create_did_sample(input_scope, input_name, output_scope, output_name, issuer, nbfiles, vo='def'):
    """
    Create a sample from an input collection.

    :param input_scope: The scope of the input DID.
    :param input_name: The name of the input DID.
    :param output_scope: The scope of the output dataset.
    :param output_name: The name of the output dataset.
    :param account: The account.
    :param nbfiles: The number of files to register in the output dataset.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    """
    kwargs = {'issuer': issuer, 'scope': output_scope}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='create_did_sample', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not bulk add data identifier' % (issuer))

    input_scope = InternalScope(input_scope, vo=vo)
    output_scope = InternalScope(output_scope, vo=vo)

    issuer = InternalAccount(issuer, vo=vo)

    return did.create_did_sample(input_scope=input_scope, input_name=input_name, output_scope=output_scope, output_name=output_name, account=issuer, nbfiles=nbfiles)


def resurrect(dids, issuer, vo='def'):
    """
    Resurrect DIDs.

    :param dids: A list of dids.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    """
    kwargs = {'issuer': issuer}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='resurrect', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not resurrect data identifiers' % (issuer))
    validate_schema(name='dids', obj=dids, vo=vo)

    for d in dids:
        d['scope'] = InternalScope(d['scope'], vo=vo)

    return did.resurrect(dids=dids)


def list_archive_content(scope, name, vo='def'):
    """
    List archive contents.

    :param scope: The archive scope name.
    :param name: The archive data identifier name.
    :param vo: The VO to act on.
    """

    scope = InternalScope(scope, vo=vo)

    dids = did.list_archive_content(scope=scope, name=name)
    for d in dids:
        yield api_update_return_dict(d)


def add_did_to_followed(scope, name, account, session=None, vo='def'):
    """
    Mark a did as followed by the given account

    :param scope: The scope name.
    :param name: The data identifier name.
    :param account: The account owner.
    :param session: The database session in use.
    """
    scope = InternalScope(scope, vo=vo)
    account = InternalAccount(account, vo=vo)
    return did.add_did_to_followed(scope=scope, name=name, account=account, session=session)


def add_dids_to_followed(dids, account, session=None, vo='def'):
    """
    Bulk mark datasets as followed

    :param dids: A list of dids.
    :param account: The account owner.
    :param session: The database session in use.
    """
    account = InternalAccount(account, vo=vo)
    return did.add_dids_to_followed(dids=dids, account=account, session=session)


def get_users_following_did(name, scope, session=None, vo='def'):
    """
    Return list of users following a did

    :param scope: The scope name.
    :param name: The data identifier name.
    :param session: The database session in use.
    """
    scope = InternalScope(scope, vo=vo)
    users = did.get_users_following_did(name=name, scope=scope, session=session)
    for user in users:
        user['user'] = user['user'].external
        yield user


def remove_did_from_followed(scope, name, account, issuer, session=None, vo='def'):
    """
    Mark a did as not followed

    :param scope: The scope name.
    :param name: The data identifier name.
    :param account: The account owner.
    :param session: The database session in use.
    :param issuer: The issuer account
    """
    kwargs = {'scope': scope, 'issuer': issuer}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='remove_did_from_followed', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not remove data identifiers from followed table' % (issuer))

    scope = InternalScope(scope, vo=vo)
    account = InternalAccount(account, vo=vo)
    return did.remove_did_from_followed(scope=scope, name=name, account=account, session=session)


def remove_dids_from_followed(dids, account, issuer, session=None, vo='def'):
    """
    Bulk mark datasets as not followed

    :param dids: A list of dids.
    :param account: The account owner.
    :param session: The database session in use.
    """
    kwargs = {'dids': dids, 'issuer': issuer}
    if not rucio.api.permission.has_permission(issuer=issuer, vo=vo, action='remove_dids_from_followed', kwargs=kwargs):
        raise rucio.common.exception.AccessDenied('Account %s can not bulk remove data identifiers from followed table' % (issuer))

    account = InternalAccount(account, vo=vo)
    return did.remove_dids_from_followed(dids=dids, account=account, session=session)
