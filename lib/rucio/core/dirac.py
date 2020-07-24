#!/usr/bin/env python
# Copyright 2020 CERN
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2020
#
# PY3K COMPATIBLE

from __future__ import print_function
from sqlalchemy.orm.exc import NoResultFound
from rucio.db.sqla import models
from rucio.db.sqla.session import transactional_session, read_session
from rucio.db.sqla.constants import DIDType, RuleGrouping
from rucio.common.exception import InvalidType
from rucio.common.types import InternalScope, InternalAccount
from rucio.common.utils import extract_scope
from rucio.core.did import add_did, attach_dids_to_dids
from rucio.core.replica import add_replicas
from rucio.core.scope import list_scopes


@read_session
def _exists(scope, name, session=None):
    """
    Check if the did exists

    :scope: The scope
    :name: The name
    :session: The session used
    """
    try:
        session.query(models.DataIdentifier).filter_by(scope=scope, name=name).\
            with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').one()
        return True
    except NoResultFound:
        return False


@transactional_session
def add_files(lfns, account, ignore_availability, session=None):
    """
    Bulk add files :
    - Create the file and replica.
    - If doesn't exist create the dataset containing the file as well as a rule on the dataset on ANY sites.
    - Create all the ascendants of the dataset if they do not exist

    :param lfns: List of lfn (dictionary {'lfn': <lfn>, 'rse': <rse>, 'bytes': <bytes>, 'adler32': <adler32>, 'guid': <guid>, 'pfn': <pfn>}
    :param issuer: The issuer account.
    :param ignore_availability: A boolean to ignore blacklisted sites.
    :session: The session used
    """
    attachments = []
    # The list of scopes is necessary for the extract_scope
    scopes = list_scopes(session=session)
    scopes = [scope.external for scope in scopes]
    exist_lfn = []
    for lfn in lfns:
        # First check if the file exists
        filename = lfn['lfn']
        lfn_scope, _ = extract_scope(filename, scopes)
        lfn_scope = InternalScope(lfn_scope)
        if _exists(lfn_scope, filename):
            continue

        # Get all the ascendants of the file
        lfn_split = filename.split('/')
        lpns = ["/".join(lfn_split[:idx]) for idx in range(2, len(lfn_split))]
        lpns.reverse()
        print(lpns)

        # The parent must be a dataset. Register it as well as the rule
        dsn_name = lpns[0]
        dsn_scope, _ = extract_scope(dsn_name, scopes)
        dsn_scope = InternalScope(dsn_scope)
        if (dsn_name not in exist_lfn) and (not _exists(dsn_scope, dsn_name)):
            print('Will create %s' % dsn_name)
            add_did(scope=dsn_scope,
                    name=dsn_name,
                    type=DIDType.DATASET,
                    account=InternalAccount(account),
                    statuses=None,
                    meta=None,
                    rules=[{'copies': 1, 'rse_expression': 'ANY=true', 'weight': None, 'account': InternalAccount(account), 'lifetime': None, 'GROUPING': RuleGrouping.NONE}],
                    lifetime=None,
                    dids=None,
                    rse_id=None,
                    session=session)
            exist_lfn.append(dsn_name)
            parent_name = lpns[1]
            parent_scope, _ = extract_scope(parent_name, scopes)
            parent_scope = InternalScope(parent_scope)
            attachments.append({'scope': parent_scope, 'name': parent_name, 'dids': [{'scope': dsn_scope, 'name': dsn_name}]})

        # Register the file
        rse_id = lfn.get('rse_id', None)
        if not rse_id:
            raise InvalidType('Missing rse_id')
        bytes = lfn.get('bytes', None)
        guid = lfn.get('guid', None)
        adler32 = lfn.get('adler32', None)
        pfn = lfn.get('pfn', None)
        files = {'scope': lfn_scope, 'name': filename, 'bytes': bytes, 'adler32': adler32}
        if pfn:
            files['pfn'] = str(pfn)
        if guid:
            files['meta'] = {'guid': guid}
        add_replicas(rse_id=rse_id,
                     files=[files],
                     dataset_meta=None,
                     account=InternalAccount(account),
                     ignore_availability=ignore_availability,
                     session=session)
        attachments.append({'scope': dsn_scope, 'name': dsn_name, 'dids': [{'scope': lfn_scope, 'name': filename}]})

        # Now loop over the ascendants of the dataset and created them
        for lpn in lpns[1:]:
            child_scope, _ = extract_scope(lpn, scopes)
            child_scope = InternalScope(child_scope)
            if (lpn not in exist_lfn) and (not _exists(child_scope, lpn)):
                print('Will create %s' % lpn)
                add_did(scope=child_scope,
                        name=lpn,
                        type=DIDType.CONTAINER,
                        account=InternalAccount(account),
                        statuses=None,
                        meta=None,
                        rules=None,
                        lifetime=None,
                        dids=None,
                        rse_id=None,
                        session=session)
                exist_lfn.append(lpn)
                parent_name = lpns[lpns.index(lpn) + 1]
                parent_scope, _ = extract_scope(parent_name, scopes)
                parent_scope = InternalScope(parent_scope)
                attachments.append({'scope': parent_scope, 'name': parent_name, 'dids': [{'scope': child_scope, 'name': lpn}]})
    # Finally attach everything
    attach_dids_to_dids(attachments,
                        account=InternalAccount(account),
                        ignore_duplicate=True,
                        session=session)
