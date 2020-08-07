#!/usr/bin/env python
# Copyright 2012-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020
#
# PY3K COMPATIBLE

from web import application, loadhook

from rucio.common.schema import get_schema_value
from rucio.web.rest.common import rucio_loadhook
from rucio.web.rest.account import (Attributes as AAttributes, Scopes as AScopes, Identities as AIdentities,  # NOQA: F401
                                    LocalAccountLimits as ALocalAccountLimits, GlobalAccountLimits as  # NOQA: F401
                                    AGlobalAccountLimits, Rules as ARules, UsageHistory as  # NOQA: F401
                                    AUsageHistory, LocalUsage as ALocalUsage, GlobalUsage as  # NOQA: F401
                                    AGlobalUsage, AccountParameter as AAccountParameter, Account as  # NOQA: F401
                                    AAccount)  # NOQA: F401
from rucio.web.rest.account_limit import LocalAccountLimit as ALLocalAccountLimit, GlobalAccountLimit as ALGlobalAccountLimit  # NOQA: F401
from rucio.web.rest.archive import Archive as AVArchive  # NOQA: F401
from rucio.web.rest.config import OptionSet as COptionSet, OptionGetDel as COptionGetDel, Section as CSection, Config as CConfig  # NOQA: F401
from rucio.web.rest.did import (Scope as DScope, GUIDLookup as DGUIDLookup, Search as DSearch, Files as DFiles,  # NOQA: F401
                                    AttachmentHistory as DAttachmentHistory, Attachment as DAttachment,  # NOQA: F401
                                    Meta as DMeta, DIDs as DDIDs, Rules as DRules, Parents as DParents,  # NOQA: F401
                                    AssociatedRules as DAssociatedRules, Sample as  # NOQA: F401
                                    DSample, BulkDIDS as DBulkDIDS, Attachments as DAttachments, NewDIDs  # NOQA: F401
                                    as DNewDIDs, Resurrect as DResurrect,  # NOQA: F401
                                    Follow as DFollow, BulkMeta as DBulkMeta)  # NOQA: F401
from rucio.web.rest.exporter import Export as EExport  # NOQA: F401
from rucio.web.rest.heartbeat import Heartbeat as HHeartbeat  # NOQA: F401
from rucio.web.rest.identity import Accounts as IAccounts, UserPass as IUserPass, X509 as IX509, GSS as IGSS  # NOQA: F401
from rucio.web.rest.importer import Import as IMImport  # NOQA: F401
from rucio.web.rest.lifetime_exception import LifetimeException as LELifetimeException, LifetimeExceptionId as LELifetimeExceptionId  # NOQA: F401
from rucio.web.rest.meta import Values as MValues, Meta as MMeta  # NOQA: F401
from rucio.web.rest.lock import LockByScopeName as LLockByScopeName, LockByRSE as LLockByRSE  # NOQA: F401
from rucio.web.rest.replica import (ListReplicas as RPListReplicas, Replicas as RPReplicas, SuspiciousReplicas as RPSuspiciousReplicas,  # NOQA: F401
                                    BadReplicasStates as RPBadReplicasStates, BadReplicasSummary as  # NOQA: F401
                                    RPBadReplicasSummary, BadPFNs as RPBadPFNs, ReplicasRSE as  # NOQA: F401
                                    RPReplicasRSE, BadReplicas as RPBadReplicas, ReplicasDIDs as  # NOQA: F401
                                    RPReplicasDIDs, DatasetReplicas as RPDatasetReplicas,  # NOQA: F401
                                    DatasetReplicasVP as RPDatasetReplicasVP, Tombstone as RPTombstone)  # NOQA: F401
from rucio.web.rest.request import RequestGet as RQRequestGet, RequestsGet as RQRequestsGet  # NOQA: F401
from rucio.web.rest.rule import (ReplicaLocks as RUReplicaLocks, ReduceRule as RUReduceRule, MoveRule as RUMoveRule,  # NOQA: F401
                                RuleHistoryFull as RURuleHistoryFull, RuleHistory as RURuleHistory,  # NOQA: F401
                                RuleAnalysis as RURuleAnalysis, AllRule as RUAllRule, Rule as RURule)  # NOQA: F401
from rucio.web.rest.rse import (Attributes as RAttributes, Distance as RDistance, Protocol as RProtocol, Protocols as RProtocols,  # NOQA: F401
                                LFNS2PFNS as RLFNS2PFNS, RSEAccountUsageLimit as RRSEAccountUsageLimit,  # NOQA: F401
                                Usage as RUsage, UsageHistory as RUsageHistory, Limits as RLimits, RSE
                                as RRSE, RSEs as RRSEs, QoSPolicy as RQoSPolicy)  # NOQA: F401
from rucio.web.rest.scope import Scope as SCScope, ScopeList as SCScopeList  # NOQA: F401
from rucio.web.rest.subscription import SubscriptionId as SSubscriptionId, States as AStates, Rules as SRules, SubscriptionName as SSubscriptionName, Subscription as SSubscription  # NOQA: F401
from rucio.web.rest.temporary_did import BulkDIDS as TBulkDIDS   # NOQA: F401


URLS = [
    '/accounts/(.+)/attr/', 'AAttributes',
    '/accounts/(.+)/attr/(.+)', 'AAttributes',
    '/accounts/(.+)/scopes/', 'AScopes',
    '/accounts/(.+)/scopes/(.+)', 'AScopes',
    '/accounts/(.+)/identities', 'AIdentities',
    '/accounts/(.+)/limits/local', 'ALocalAccountLimits',
    '/accounts/(.+)/limits/local/(.+)', 'ALocalAccountLimits',
    '/accounts/(.+)/limits/global', 'AGlobalAccountLimits',
    '/accounts/(.+)/limits/global/(.+)', 'AGlobalAccountLimits',
    '/accounts/(.+)/limits', 'ALocalAccountLimits',
    '/accounts/(.+)/limits/(.+)', 'ALocalAccountLimits',
    '/accounts/(.+)/rules', 'ARules',
    '/accounts/(.+)/usage/history/(.+)', 'AUsageHistory',
    '/accounts/(.+)/usage/local', 'ALocalUsage',
    '/accounts/(.+)/usage/local/(.+)', 'ALocalUsage',
    '/accounts/(.+)/usage/global', 'AGlobalUsage',
    '/accounts/(.+)/usage/global/(.+)', 'AGlobalUsage',
    '/accounts/(.+)/usage/', 'ALocalUsage',
    '/accounts/(.+)/usage/(.+)', 'ALocalUsage',
    '/accounts/(.+)', 'AAccountParameter',
    '/accounts/?$', 'AAccount'
]

URLS += [
    '/accountlimits/local/(.+)/(.+)', 'ALLocalAccountLimit',
    '/accountlimits/global/(.+)/(.+)', 'ALGlobalAccountLimit',
    '/accountlimits/(.+)/(.+)', 'ALLocalAccountLimit',
]

URLS += ['/archives%s/files' % get_schema_value('SCOPE_NAME_REGEXP'), 'AVArchive']

URLS += [
    '/config/(.+)/(.+)/(.*)', 'COptionSet',
    '/config/(.+)/(.+)', 'COptionGetDel',
    '/config/(.+)', 'CSection',
    '/config', 'CConfig'
]

URLS += [
    '/dids/(.*)/$', 'DScope',
    '/dids/(.*)/guid', 'DGUIDLookup',
    '/dids/(.*)/dids/search', 'DSearch',
    '/dids%s/files' % get_schema_value('SCOPE_NAME_REGEXP'), 'DFiles',
    '/dids%s/dids/history' % get_schema_value('SCOPE_NAME_REGEXP'), 'DAttachmentHistory',
    '/dids%s/dids' % get_schema_value('SCOPE_NAME_REGEXP'), 'DAttachment',
    '/dids%s/meta/(.*)' % get_schema_value('SCOPE_NAME_REGEXP'), 'DMeta',
    '/dids%s/meta' % get_schema_value('SCOPE_NAME_REGEXP'), 'DMeta',
    '/dids%s/status' % get_schema_value('SCOPE_NAME_REGEXP'), 'DDIDs',
    '/dids%s/rules' % get_schema_value('SCOPE_NAME_REGEXP'), 'DRules',
    '/dids%s/parents' % get_schema_value('SCOPE_NAME_REGEXP'), 'DParents',
    '/dids%s/associated_rules' % get_schema_value('SCOPE_NAME_REGEXP'), 'DAssociatedRules',
    '/dids%s/did_meta' % get_schema_value('SCOPE_NAME_REGEXP'), 'DDidMeta',
    '/dids/(.*)/(.*)/(.*)/(.*)/(.*)/sample', 'DSample',
    '/dids%s' % get_schema_value('SCOPE_NAME_REGEXP'), 'DDIDs',
    '/dids', 'DBulkDIDS',
    '/dids/attachments', 'DAttachments',
    '/dids/new', 'DNewDIDs',
    '/dids/resurrect', 'DResurrect',
    '/dids/list_dids_by_meta', 'DListByMeta',
    '/dids%s/follow' % get_schema_value('SCOPE_NAME_REGEXP'), 'DFollow',
    '/dids/bulkmeta', 'DBulkMeta',
]

URLS += [
    '/export/', 'EExport',
    '/export', 'EExport'
]

URLS += ['/heartbeat', 'HHeartbeat']

URLS += [
    '/identities/(.+)/(.+)/accounts', 'IAccounts',
    '/identities/(.+)/userpass', 'IUserPass',
    '/identities/(.+)/x509', 'IX509',
    '/identities/(.+)/gss', 'IGSS'
]

URLS += [
    '/import/', 'IMImport',
    '/import', 'IMImport'
]

URLS += [
    '/lifetime_exceptions/', 'LELifetimeException',
    '/lifetime_exceptions/(.+)', 'LELifetimeExceptionId'
]

URLS += [
    '/locks%s' % get_schema_value('SCOPE_NAME_REGEXP'), 'LLockByScopeName',
    '/locks/(.*)', 'LLockByRSE'
]

URLS += [
    '/meta/(.+)/(.+)', 'MValues',
    '/meta/(.+)/', 'MValues',
    '/meta/(.+)', 'MMeta',
    '/meta/', 'MMeta'
]

URLS += [
    '/replicas/list/?$', 'RPListReplicas',
    '/replicas/?$', 'RPReplicas',
    '/replicas/suspicious/?$', 'RPSuspiciousReplicas',
    '/replicas/bad/states/?$', 'RPBadReplicasStates',
    '/replicas/bad/summary/?$', 'RPBadReplicasSummary',
    '/replicas/bad/pfns/?$', 'RPBadPFNs',
    '/replicas/rse/(.*)/?$', 'RPReplicasRSE',
    '/replicas/bad/?$', 'RPBadReplicas',
    '/replicas/dids/?$', 'RPReplicasDIDs',
    '/replicas%s/datasets$' % get_schema_value('SCOPE_NAME_REGEXP'), 'RPDatasetReplicas',
    '/replicas%s/datasets_vp$' % get_schema_value('SCOPE_NAME_REGEXP'), 'RPDatasetReplicasVP',
    '/replicas%s/?$' % get_schema_value('SCOPE_NAME_REGEXP'), 'RPReplicas',
    '/replicas/tombstone/?$', 'RPTombstone'
]

URLS += [
    '/requests/%s/(.+)' % get_schema_value('SCOPE_NAME_REGEXP'), 'RQRequestGet',
    '/requests/list', 'RQRequestsGet'
]

URLS += [
    '/rses/(.+)/attr/(.+)', 'RAttributes',
    '/rses/(.+)/attr/', 'RAttributes',
    '/rses/(.+)/distances/(.+)', 'RDistance',  # List (GET), create (POST), Updates (PUT) distance
    '/rses/(.+)/protocols/(.+)/(.+)/(.+)', 'RProtocol',  # Updates (PUT) protocol attributes
    '/rses/(.+)/protocols/(.+)/(.+)/(.+)', 'RProtocol',  # delete (DELETE) a specific protocol
    '/rses/(.+)/protocols/(.+)/(.+)', 'RProtocol',  # delete (DELETE) all protocols with the same identifier and the same hostname
    '/rses/(.+)/protocols/(.+)', 'RProtocol',  # List (GET), create (POST), update (PUT), or delete (DELETE) a all protocols with the same identifier
    '/rses/(.+)/protocols', 'RProtocols',  # List all supported protocols (GET)
    '/rses/(.+)/lfns2pfns', 'RLFNS2PFNS',  # Translate a list of LFNs to PFNs (GET)
    '/rses/(.+)/accounts/usage', 'RRSEAccountUsageLimit',
    '/rses/(.+)/usage', 'RUsage',  # Update RSE usage information
    '/rses/(.+)/usage/history', 'RUsageHistory',  # Get RSE usage history information
    '/rses/(.+)/limits', 'RLimits',  # Update/List RSE limits
    '/rses/(.+)/qos_policy', 'RQoSPolicy',  # List QoS policies
    '/rses/(.+)/qos_policy/(.+)', 'RQoSPolicy',  # Add/Delete QoS policies
    '/rses/(.+)', 'RRSE',
    '/rses/', 'RRSEs',
]

URLS += [
    '/rules/(.+)/locks', 'RUReplicaLocks',
    '/rules/(.+)/reduce', 'RUReduceRule',
    '/rules/(.+)/move', 'RUMoveRule',
    '/rules%s/history' % get_schema_value('SCOPE_NAME_REGEXP'), 'RURuleHistoryFull',
    '/rules/(.+)/history', 'RURuleHistory',
    '/rules/(.+)/analysis', 'RURuleAnalysis',
    '/rules/', 'RUAllRule',
    '/rules/(.+)', 'RURule'
]

URLS += [
    '/scopes/', 'SCScope',
    '/scopes/(.+)/scopes', 'SCScopeList'
]

URLS += [
    '/subscriptions/Id/(.*)', 'SSubscriptionId',
    '/subscriptions/(.*)/(.*)/Rules/States', 'SStates',
    '/subscriptions/(.*)/Rules/States', 'SStates',
    '/subscriptions/(.*)/(.*)/Rules', 'SRules',
    '/subscriptions/Name/(.*)', 'SSubscriptionName',
    '/subscriptions/(.*)/(.*)', 'SSubscription',
    '/subscriptions/(.*)', 'SSubscription',
    '/subscriptions/', 'SSubscription',
]

URLS += ['/tmp_dids', 'TBulkDIDS']

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
application = APP.wsgifunc()
