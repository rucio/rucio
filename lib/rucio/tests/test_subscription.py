# -*- coding: utf-8 -*-
# Copyright 2013-2021 CERN
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013-2017
# - Vincent Garonne <vincent.garonne@cern.ch>, 2013-2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2014
# - Martin Barisits <martin.barisits@cern.ch>, 2015-2021
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

from __future__ import print_function

import unittest
from json import loads

import pytest

from rucio.api.subscription import list_subscriptions, add_subscription, update_subscription, \
    list_subscription_rule_states, get_subscription_by_id
from rucio.client.didclient import DIDClient
from rucio.client.subscriptionclient import SubscriptionClient
from rucio.common.config import config_get, config_get_bool
from rucio.common.exception import InvalidObject, SubscriptionNotFound, SubscriptionDuplicate
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account import add_account
from rucio.core.account_limit import set_local_account_limit
from rucio.core.did import add_did, set_new_dids
from rucio.core.rse import add_rse
from rucio.core.rule import add_rule
from rucio.core.scope import add_scope
from rucio.daemons.transmogrifier.transmogrifier import run
from rucio.db.sqla.constants import AccountType, DIDType
from rucio.tests.common import headers, auth


class TestSubscriptionCoreApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            cls.vo = {}

        cls.projects = ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV']
        cls.pattern1 = r'(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).* \
                        \.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)'

    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_create_and_update_and_list_subscription(self):
        """ SUBSCRIPTION (API): Test the creation of a new subscription, update it, list it """
        subscription_name = uuid()
        with pytest.raises(InvalidObject):
            result = add_subscription(name=subscription_name,
                                      account='root',
                                      filter={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                      replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'noactivity'}],
                                      lifetime=100000,
                                      retroactive=0,
                                      dry_run=0,
                                      comments='This is a comment',
                                      issuer='root',
                                      **self.vo)

        result = add_subscription(name=subscription_name,
                                  account='root',
                                  filter={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                  replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}],
                                  lifetime=100000,
                                  retroactive=0,
                                  dry_run=0,
                                  comments='This is a comment',
                                  issuer='root',
                                  **self.vo)

        with pytest.raises(TypeError):
            result = update_subscription(name=subscription_name, account='root', metadata={'filter': 'toto'}, issuer='root', **self.vo)
        with pytest.raises(InvalidObject):
            result = update_subscription(name=subscription_name, account='root', metadata={'filter': {'project': 'toto'}}, issuer='root', **self.vo)
        result = update_subscription(name=subscription_name, account='root', metadata={'filter': {'project': ['toto', ]}}, issuer='root', **self.vo)
        assert result is None
        result = list_subscriptions(name=subscription_name, account='root', **self.vo)
        sub = []
        for res in result:
            sub.append(res)
        assert len(sub) == 1
        assert loads(sub[0]['filter'])['project'][0] == 'toto'

    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_create_list_subscription_by_id(self):
        """ SUBSCRIPTION (API): Test the creation of a new subscription and list it by id """
        subscription_name = uuid()
        subscription_id = add_subscription(name=subscription_name,
                                           account='root',
                                           filter={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                           replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}],
                                           lifetime=100000,
                                           retroactive=0,
                                           dry_run=0,
                                           comments='This is a comment',
                                           issuer='root',
                                           **self.vo)

        subscription_info = get_subscription_by_id(subscription_id, **self.vo)
        assert loads(subscription_info['filter'])['project'] == self.projects

    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_create_existing_subscription(self):
        """ SUBSCRIPTION (API): Test the creation of a existing subscription """
        subscription_name = uuid()

        def genkwargs():
            kwargs = {
                'name': subscription_name,
                'account': 'root',
                'filter': {'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                'replication_rules': [{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}],
                'lifetime': 100000,
                'retroactive': 0,
                'dry_run': 0,
                'comments': 'This is a comment',
                'issuer': 'root'
            }
            kwargs.update(self.vo)
            return kwargs

        add_subscription(**genkwargs())

        with pytest.raises(SubscriptionDuplicate):
            add_subscription(**genkwargs())

    def test_update_nonexisting_subscription(self):
        """ SUBSCRIPTION (API): Test the update of a non-existing subscription """
        subscription_name = uuid()
        with pytest.raises(SubscriptionNotFound):
            update_subscription(name=subscription_name, account='root', metadata={'filter': {'project': ['toto', ]}}, issuer='root', **self.vo)

    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_list_rules_states(self):
        """ SUBSCRIPTION (API): Test listing of rule states for subscription """
        tmp_scope = InternalScope('mock_' + uuid()[:8], **self.vo)
        root = InternalAccount('root', **self.vo)
        add_scope(tmp_scope, root)
        site_a = 'RSE%s' % uuid().upper()
        site_b = 'RSE%s' % uuid().upper()

        site_a_id = add_rse(site_a, **self.vo)
        site_b_id = add_rse(site_b, **self.vo)

        # Add quota
        set_local_account_limit(root, site_a_id, -1)
        set_local_account_limit(root, site_b_id, -1)

        # add a new dataset
        dsn = 'dataset-%s' % uuid()
        add_did(scope=tmp_scope, name=dsn,
                type=DIDType.DATASET, account=root)

        subscription_name = uuid()
        subid = add_subscription(name=subscription_name,
                                 account='root',
                                 filter={'account': ['root', ], 'scope': [tmp_scope.external, ]},
                                 replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}],
                                 lifetime=100000,
                                 retroactive=0,
                                 dry_run=0,
                                 comments='This is a comment',
                                 issuer='root',
                                 **self.vo)

        # Add two rules
        add_rule(dids=[{'scope': tmp_scope, 'name': dsn}], account=root, copies=1, rse_expression=site_a, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=subid)
        add_rule(dids=[{'scope': tmp_scope, 'name': dsn}], account=root, copies=1, rse_expression=site_b, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=subid)

        for rule in list_subscription_rule_states(account='root', name=subscription_name, **self.vo):
            assert rule[3] == 2


@pytest.mark.noparallel(reason='uses pre-defined RSE')
def test_create_and_update_and_list_subscription(rest_client, auth_token):
    """ SUBSCRIPTION (REST): Test the creation of a new subscription, update it, list it """
    subscription_name = uuid()
    projects = ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV']
    pattern1 = r'(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).* \
                 \.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)'
    data = {'options': {'filter': {'project': projects, 'datatype': ['AOD', ], 'excluded_pattern': pattern1, 'account': ['tier0', ]},
                        'replication_rules': [{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}],
                        'lifetime': 100000, 'retroactive': 0, 'dry_run': 0, 'comments': 'blahblah'}}
    response = rest_client.post('/subscriptions/root/' + subscription_name, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    data = {'options': {'filter': {'project': ['toto', ]}}}
    response = rest_client.put('/subscriptions/root/' + subscription_name, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    response = rest_client.get('/subscriptions/root/' + subscription_name, headers=headers(auth(auth_token)))
    assert response.status_code == 200
    assert loads(loads(response.get_data(as_text=True))['filter'])['project'][0] == 'toto'


@pytest.mark.noparallel(reason='uses pre-defined RSE')
def test_create_and_list_subscription_by_id(rest_client, auth_token):
    """ SUBSCRIPTION (REST): Test the creation of a new subscription and get by subscription id """
    subscription_name = uuid()
    projects = ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV']
    pattern1 = r'(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).* \
                 \.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)'
    data = {'options': {'filter': {'project': projects, 'datatype': ['AOD', ], 'excluded_pattern': pattern1, 'account': ['tier0', ]},
                        'replication_rules': [{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}],
                        'lifetime': 100000, 'retroactive': 0, 'dry_run': 0, 'comments': 'blahblah'}}
    response = rest_client.post('/subscriptions/root/' + subscription_name, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    subscription_id = response.get_data(as_text=True)
    response = rest_client.get('/subscriptions/Id/' + subscription_id, headers=headers(auth(auth_token)))
    assert response.status_code == 200
    assert loads(loads(response.get_data(as_text=True))['filter'])['project'][0] == 'data12_900GeV'


@pytest.mark.noparallel(reason='uses pre-defined RSE')
def test_create_existing_subscription(rest_client, auth_token):
    """ SUBSCRIPTION (REST): Test the creation of a existing subscription """
    subscription_name = uuid()
    projects = ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV']
    pattern1 = r'(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).* \
                 \.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)'
    data = {'options': {'name': subscription_name, 'filter': {'project': projects, 'datatype': ['AOD', ], 'excluded_pattern': pattern1, 'account': ['tier0', ]},
                        'replication_rules': [{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}],
                        'lifetime': 100000, 'retroactive': 0, 'dry_run': 0, 'comments': 'We are the knights who say Ni !'}}
    response = rest_client.post('/subscriptions/root/' + subscription_name, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    response = rest_client.post('/subscriptions/root/' + subscription_name, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 409
    assert response.headers.get('ExceptionClass') == 'SubscriptionDuplicate'


def test_update_nonexisting_subscription(rest_client, auth_token):
    """ SUBSCRIPTION (REST): Test the update of a non-existing subscription """
    subscription_name = uuid()
    data = {'options': {'filter': {'project': ['toto', ]}}}
    response = rest_client.put('/subscriptions/root/' + subscription_name, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 404
    assert response.headers.get('ExceptionClass') == 'SubscriptionNotFound'


@pytest.mark.noparallel(reason='uses pre-defined RSE')
def test_list_rules_states(vo, rest_client, auth_token):
    """ SUBSCRIPTION (REST): Test listing of rule states for subscription """
    tmp_scope = InternalScope('mock_' + uuid()[:8], vo=vo)
    root = InternalAccount('root', vo=vo)
    add_scope(tmp_scope, root)
    site_a = 'RSE%s' % uuid().upper()
    site_b = 'RSE%s' % uuid().upper()

    site_a_id = add_rse(site_a, vo=vo)
    site_b_id = add_rse(site_b, vo=vo)

    # Add quota
    set_local_account_limit(root, site_a_id, -1)
    set_local_account_limit(root, site_b_id, -1)

    # add a new dataset
    dsn = 'dataset-%s' % uuid()
    add_did(scope=tmp_scope, name=dsn,
            type=DIDType.DATASET, account=root)

    subscription_name = uuid()
    subid = add_subscription(name=subscription_name,
                             account='root',
                             filter={'account': ['root', ], 'scope': [tmp_scope.external, ]},
                             replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}],
                             lifetime=100000,
                             retroactive=0,
                             dry_run=0,
                             comments='We want a shrubbery',
                             issuer='root',
                             vo=vo)

    # Add two rules
    add_rule(dids=[{'scope': tmp_scope, 'name': dsn}], account=root, copies=1, rse_expression=site_a, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=subid)
    add_rule(dids=[{'scope': tmp_scope, 'name': dsn}], account=root, copies=1, rse_expression=site_b, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=subid)

    response = rest_client.get('/subscriptions/%s/%s/Rules/States' % ('root', subscription_name), headers=headers(auth(auth_token)))
    assert response.status_code == 200

    rulestates = None
    for line in response.get_data(as_text=True).split('\n'):
        if line:
            rulestates = loads(line)
            if rulestates[1] == subscription_name:
                break
    assert rulestates is not None
    assert rulestates[3] == 2


class TestSubscriptionClient(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            cls.vo = {}

        cls.sub_client = SubscriptionClient()
        cls.did_client = DIDClient()
        cls.projects = ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV']
        cls.pattern1 = r'(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).* \
                         \.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)'

    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_create_and_update_and_list_subscription(self):
        """ SUBSCRIPTION (CLIENT): Test the creation of a new subscription, update it, list it """
        subscription_name = uuid()
        with pytest.raises(InvalidObject):
            subid = self.sub_client.add_subscription(name=subscription_name, account='root', filter={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                                     replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'noactivity'}], lifetime=100000, retroactive=0, dry_run=0, comments='Ni ! Ni!')
        subid = self.sub_client.add_subscription(name=subscription_name, account='root', filter={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                                 replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}], lifetime=100000, retroactive=0, dry_run=0, comments='Ni ! Ni!')
        result = [sub['id'] for sub in list_subscriptions(name=subscription_name, account='root', **self.vo)]
        assert subid == result[0]
        with pytest.raises(TypeError):
            result = self.sub_client.update_subscription(name=subscription_name, account='root', filter='toto')
        result = self.sub_client.update_subscription(name=subscription_name, account='root', filter={'project': ['toto', ]})
        assert result
        result = list_subscriptions(name=subscription_name, account='root', **self.vo)
        sub = []
        for res in result:
            sub.append(res)
        assert len(sub) == 1
        assert loads(sub[0]['filter'])['project'][0] == 'toto'

    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_create_existing_subscription(self):
        """ SUBSCRIPTION (CLIENT): Test the creation of a existing subscription """
        subscription_name = uuid()
        result = self.sub_client.add_subscription(name=subscription_name, account='root', filter={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                                  replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}], lifetime=100000, retroactive=0, dry_run=0, comments='Ni ! Ni!')
        assert result
        with pytest.raises(SubscriptionDuplicate):
            self.sub_client.add_subscription(name=subscription_name, account='root', filter={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                             replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}], lifetime=100000, retroactive=0, dry_run=0, comments='Ni ! Ni!')

    def test_update_nonexisting_subscription(self):
        """ SUBSCRIPTION (CLIENT): Test the update of a non-existing subscription """
        subscription_name = uuid()
        with pytest.raises(SubscriptionNotFound):
            self.sub_client.update_subscription(name=subscription_name, filter={'project': ['toto', ]})

    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_create_and_list_subscription_by_account(self):
        """ SUBSCRIPTION (CLIENT): Test retrieval of subscriptions for an account """
        subscription_name = uuid()
        account_name = uuid()[:10]
        add_account(InternalAccount(account_name, **self.vo), AccountType.USER, 'rucio@email.com')
        subid = self.sub_client.add_subscription(name=subscription_name, account=account_name, filter={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                                 replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}], lifetime=100000, retroactive=0, dry_run=0, comments='Ni ! Ni!')
        result = [sub['id'] for sub in self.sub_client.list_subscriptions(account=account_name)]
        assert subid == result[0]

    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_create_and_list_subscription_by_name(self):
        """ SUBSCRIPTION (CLIENT): Test retrieval of subscriptions for an account """
        subscription_name = uuid()
        subid = self.sub_client.add_subscription(name=subscription_name, account='root', filter={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                                 replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}], lifetime=100000, retroactive=0, dry_run=0, comments='Ni ! Ni!')
        result = [sub['id'] for sub in self.sub_client.list_subscriptions(name=subscription_name)]
        assert subid == result[0]

    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_run_transmogrifier(self):
        """ SUBSCRIPTION (DAEMON): Test the transmogrifier and the split_rule mode """
        tmp_scope = InternalScope('mock_' + uuid()[:8], **self.vo)
        root = InternalAccount('root', **self.vo)
        add_scope(tmp_scope, root)
        subscription_name = uuid()
        dsn = 'dataset-%s' % uuid()
        add_did(scope=tmp_scope, name=dsn, type=DIDType.DATASET, account=root)

        subid = self.sub_client.add_subscription(name=subscription_name, account='root', filter={'scope': [tmp_scope.external, ], 'pattern': 'dataset-.*', 'split_rule': True},
                                                 replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK-POSIX|MOCK2|MOCK3', 'copies': 2, 'activity': 'Data Brokering'}],
                                                 lifetime=None, retroactive=0, dry_run=0, comments='Ni ! Ni!', priority=1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in self.did_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
        assert len(rules) == 2
        set_new_dids([{'scope': tmp_scope, 'name': dsn}, ], 1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in self.did_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
        assert len(rules) == 2

    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_run_transmogrifier_did_type(self):
        """ SUBSCRIPTION (DAEMON): Test the transmogrifier with did_type subscriptions """
        tmp_scope = InternalScope('mock_' + uuid()[:8], **self.vo)
        root = InternalAccount('root', **self.vo)
        add_scope(tmp_scope, root)
        subscription_name = uuid()
        dsn = 'dataset-%s' % uuid()
        add_did(scope=tmp_scope, name=dsn, type=DIDType.DATASET, account=root)

        subid = self.sub_client.add_subscription(name=subscription_name, account='root', filter={'scope': [tmp_scope.external, ], 'pattern': 'dataset-.*', 'split_rule': True, 'did_type': ['DATASET', ]},
                                                 replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK-POSIX|MOCK2|MOCK3', 'copies': 2, 'activity': 'Data Brokering'}],
                                                 lifetime=None, retroactive=0, dry_run=0, comments='Ni ! Ni!', priority=1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in self.did_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
        assert len(rules) == 2
        set_new_dids([{'scope': tmp_scope, 'name': dsn}, ], 1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in self.did_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
        assert len(rules) == 2
