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

import re

from json import loads
from json.decoder import JSONDecodeError

from sqlalchemy.orm.exc import NoResultFound
from rucio.db.sqla import models
from rucio.db.sqla.session import transactional_session, read_session
from rucio.db.sqla.constants import DIDType
from rucio.common.exception import InvalidType, UnsupportedOperation, ConfigNotFound, RucioException
from rucio.common.types import InternalScope, InternalAccount
from rucio.common.utils import extract_scope
from rucio.core.config import get as config_get
from rucio.core.did import add_did, attach_dids_to_dids
from rucio.core.replica import add_replicas
from rucio.core.rule import add_rule, list_rules, update_rule
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
        res = session.query(models.DataIdentifier).filter_by(scope=scope, name=name).\
            with_hint(models.DataIdentifier, "INDEX(DIDS DIDS_PK)", 'oracle').one()
        return True, res.did_type
    except NoResultFound:
        return False, None


@transactional_session
def add_files(lfns, account, ignore_availability, vo='def', session=None):
    """
    Bulk add files :
    - Create the file and replica.
    - If doesn't exist create the dataset containing the file as well as a rule on the dataset on ANY sites.
    - Create all the ascendants of the dataset if they do not exist

    :param lfns: List of lfn (dictionary {'lfn': <lfn>, 'rse': <rse>, 'bytes': <bytes>, 'adler32': <adler32>, 'guid': <guid>, 'pfn': <pfn>}
    :param issuer: The issuer account.
    :param ignore_availability: A boolean to ignore blocklisted sites.
    :param vo: The VO to act on
    :param session: The session used
    """
    rule_extension_list = []
    attachments = []
    # The list of scopes is necessary for the extract_scope
    filter_ = {'scope': InternalScope(scope='*', vo=vo)}
    scopes = list_scopes(filter_=filter_, session=session)
    scopes = [scope.external for scope in scopes]
    exist_lfn = []
    try:
        lifetime_dict: str = config_get(section='dirac', option='lifetime', default='{}', session=session)
        lifetime_dict = loads(lifetime_dict)
    except ConfigNotFound:
        lifetime_dict = {}
    except JSONDecodeError as err:
        raise InvalidType('Problem parsing lifetime option in dirac section : %s' % str(err))
    except Exception as err:
        raise RucioException(str(err))

    for lfn in lfns:
        # First check if the file exists
        filename = lfn['lfn']
        lfn_scope, _ = extract_scope(filename, scopes)
        lfn_scope = InternalScope(lfn_scope, vo=vo)

        exists, did_type = _exists(lfn_scope, filename)
        if exists:
            continue

        # Get all the ascendants of the file
        lfn_split = filename.split('/')
        lpns = ["/".join(lfn_split[:idx]) for idx in range(2, len(lfn_split))]
        lpns.reverse()
        print(lpns)

        # The parent must be a dataset. Register it as well as the rule
        dsn_name = lpns[0]
        dsn_scope, _ = extract_scope(dsn_name, scopes)
        dsn_scope = InternalScope(dsn_scope, vo=vo)

        # Compute lifetime
        lifetime = None
        if dsn_scope in lifetime_dict:
            lifetime = lifetime_dict[dsn_scope.external]
        else:
            for pattern in lifetime_dict:
                if dsn_scope.external and re.match(pattern, str(dsn_scope.external)):
                    lifetime = lifetime_dict[pattern]
                    break

        exists, did_type = _exists(dsn_scope, dsn_name)
        if exists and did_type == DIDType.CONTAINER:
            raise UnsupportedOperation('Cannot create %s as dataset' % dsn_name)
        if (dsn_name not in exist_lfn) and not exists:
            print('Will create %s' % dsn_name)
            # to maintain a compatibility between master and LTS-1.26 branches remove keywords for first 3 arguments
            add_did(dsn_scope,
                    dsn_name,
                    DIDType.DATASET,
                    account=InternalAccount(account, vo=vo),
                    statuses=None,
                    meta=None,
                    rules=[{'copies': 1, 'rse_expression': 'ANY=true', 'weight': None, 'account': InternalAccount(account, vo=vo), 'lifetime': lifetime, 'grouping': 'NONE'}],
                    lifetime=None,
                    dids=None,
                    rse_id=None,
                    session=session)
            exist_lfn.append(dsn_name)
            parent_name = lpns[1]
            parent_scope, _ = extract_scope(parent_name, scopes)
            parent_scope = InternalScope(parent_scope, vo=vo)
            attachments.append({'scope': parent_scope, 'name': parent_name, 'dids': [{'scope': dsn_scope, 'name': dsn_name}]})
            rule_extension_list.append((dsn_scope, dsn_name))
        if lifetime and (dsn_scope, dsn_name) not in rule_extension_list:
            # Reset the lifetime of the rule to the configured value
            rule = [rul for rul in list_rules({'scope': dsn_scope, 'name': dsn_name, 'account': InternalAccount(account, vo=vo)}, session=session) if rul['rse_expression'] == 'ANY=true']
            if rule:
                update_rule(rule[0]['id'], options={'lifetime': lifetime}, session=session)
            rule_extension_list.append((dsn_scope, dsn_name))

        # Register the file
        rse_id = lfn.get('rse_id', None)
        if not rse_id:
            raise InvalidType('Missing rse_id')
        bytes_ = lfn.get('bytes', None)
        guid = lfn.get('guid', None)
        adler32 = lfn.get('adler32', None)
        pfn = lfn.get('pfn', None)
        files = {'scope': lfn_scope, 'name': filename, 'bytes': bytes_, 'adler32': adler32}
        if pfn:
            files['pfn'] = str(pfn)
        if guid:
            files['meta'] = {'guid': guid}
        add_replicas(rse_id=rse_id,
                     files=[files],
                     dataset_meta=None,
                     account=InternalAccount(account, vo=vo),
                     ignore_availability=ignore_availability,
                     session=session)
        add_rule(dids=[{'scope': lfn_scope, 'name': filename}],
                 account=InternalAccount(account, vo=vo),
                 copies=1,
                 rse_expression=lfn['rse'],
                 grouping=None,
                 weight=None,
                 lifetime=86400,
                 locked=None,
                 subscription_id=None,
                 session=session)
        attachments.append({'scope': dsn_scope, 'name': dsn_name, 'dids': [{'scope': lfn_scope, 'name': filename}]})

        # Now loop over the ascendants of the dataset and created them
        for lpn in lpns[1:]:
            child_scope, _ = extract_scope(lpn, scopes)
            child_scope = InternalScope(child_scope, vo=vo)
            exists, did_type = _exists(child_scope, lpn)
            if exists and did_type == DIDType.DATASET:
                raise UnsupportedOperation('Cannot create %s as container' % lpn)
            if (lpn not in exist_lfn) and not exists:
                print('Will create %s' % lpn)
                add_did(child_scope,
                        lpn,
                        DIDType.CONTAINER,
                        account=InternalAccount(account, vo=vo),
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
                parent_scope = InternalScope(parent_scope, vo=vo)
                attachments.append({'scope': parent_scope, 'name': parent_name, 'dids': [{'scope': child_scope, 'name': lpn}]})
    # Finally attach everything
    attach_dids_to_dids(attachments,
                        account=InternalAccount(account, vo=vo),
                        ignore_duplicate=True,
                        session=session)
