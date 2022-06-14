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

import unittest
from datetime import datetime
from json import loads

import pytest

from rucio.api.subscription import list_subscriptions, add_subscription, update_subscription, \
    list_subscription_rule_states, get_subscription_by_id
from rucio.db.sqla.constants import RuleState
from rucio.client.didclient import DIDClient
from rucio.client.subscriptionclient import SubscriptionClient
from rucio.common.config import config_get_bool
from rucio.common.exception import InvalidObject, SubscriptionNotFound, SubscriptionDuplicate
from rucio.common.schema import get_schema_value
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account import add_account
from rucio.core.did import add_did, set_new_dids, list_new_dids, attach_dids
from rucio.core.rule import add_rule
from rucio.core.rse import add_rse_attribute
from rucio.core.scope import add_scope
from rucio.daemons.transmogrifier.transmogrifier import run, get_subscriptions
from rucio.db.sqla.constants import AccountType, DIDType
from rucio.tests.common import headers, auth, did_name_generator, rse_name_generator
from rucio.tests.common_server import get_vo


@pytest.mark.usefixtures("rse_factory_unittest")
class TestSubscriptionCoreApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': get_vo()}
        else:
            cls.vo = {}

        cls.projects = ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV']
        cls.pattern1 = r'(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).* \
                        \.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)'
        cls.activity = get_schema_value('ACTIVITY')['enum'][0]

    def test_create_and_update_and_list_subscription(self):
        """ SUBSCRIPTION (API): Test the creation of a new subscription, update it, list it """
        rse1, _ = self.rse_factory.make_mock_rse()
        rse2, _ = self.rse_factory.make_mock_rse()
        rse_expression = '%s|%s' % (rse1, rse2)
        subscription_name = uuid()
        with pytest.raises(InvalidObject):
            result = add_subscription(name=subscription_name,
                                      account='root',
                                      filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                      replication_rules=[{'lifetime': 86400, 'rse_expression': rse_expression, 'copies': 2, 'activity': 'noactivity'}],
                                      lifetime=100000,
                                      retroactive=0,
                                      dry_run=0,
                                      comments='This is a comment',
                                      issuer='root',
                                      **self.vo)

        result = add_subscription(name=subscription_name,
                                  account='root',
                                  filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                  replication_rules=[{'lifetime': 86400, 'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}],
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
        rse1, _ = self.rse_factory.make_mock_rse()
        rse2, _ = self.rse_factory.make_mock_rse()
        rse_expression = '%s|%s' % (rse1, rse2)
        subscription_name = uuid()
        subscription_id = add_subscription(name=subscription_name,
                                           account='root',
                                           filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                           replication_rules=[{'lifetime': 86400, 'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}],
                                           lifetime=100000,
                                           retroactive=0,
                                           dry_run=0,
                                           comments='This is a comment',
                                           issuer='root',
                                           **self.vo)

        subscription_info = get_subscription_by_id(subscription_id, **self.vo)
        assert loads(subscription_info['filter'])['project'] == self.projects

    def test_create_existing_subscription(self):
        """ SUBSCRIPTION (API): Test the creation of a existing subscription """
        subscription_name = uuid()
        rse1, _ = self.rse_factory.make_mock_rse()
        rse2, _ = self.rse_factory.make_mock_rse()
        rse_expression = '%s|%s' % (rse1, rse2)

        def genkwargs(rse_expression):
            kwargs = {
                'name': subscription_name,
                'account': 'root',
                'filter_': {'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                'replication_rules': [{'lifetime': 86400, 'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}],
                'lifetime': 100000,
                'retroactive': 0,
                'dry_run': 0,
                'comments': 'This is a comment',
                'issuer': 'root'
            }
            kwargs.update(self.vo)
            return kwargs

        add_subscription(**genkwargs(rse_expression))

        with pytest.raises(SubscriptionDuplicate):
            add_subscription(**genkwargs(rse_expression))

    def test_update_nonexisting_subscription(self):
        """ SUBSCRIPTION (API): Test the update of a non-existing subscription """
        subscription_name = uuid()
        with pytest.raises(SubscriptionNotFound):
            update_subscription(name=subscription_name, account='root', metadata={'filter': {'project': ['toto', ]}}, issuer='root', **self.vo)

    def test_list_rules_states(self):
        """ SUBSCRIPTION (API): Test listing of rule states for subscription """
        tmp_scope = InternalScope('mock_' + uuid()[:8], **self.vo)
        root = InternalAccount('root', **self.vo)
        add_scope(tmp_scope, root)
        rse1, _ = self.rse_factory.make_mock_rse()
        rse2, _ = self.rse_factory.make_mock_rse()
        rse_expression = '%s|%s' % (rse1, rse2)

        rse3, _ = self.rse_factory.make_mock_rse()
        rse4, _ = self.rse_factory.make_mock_rse()

        # add a new dataset
        dsn = did_name_generator('dataset')
        add_did(scope=tmp_scope, name=dsn,
                did_type=DIDType.DATASET, account=root)

        subscription_name = uuid()
        subid = add_subscription(name=subscription_name,
                                 account='root',
                                 filter_={'account': ['root', ], 'scope': [tmp_scope.external, ]},
                                 replication_rules=[{'lifetime': 86400, 'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}],
                                 lifetime=100000,
                                 retroactive=0,
                                 dry_run=0,
                                 comments='This is a comment',
                                 issuer='root',
                                 **self.vo)

        # Add two rules
        add_rule(dids=[{'scope': tmp_scope, 'name': dsn}], account=root, copies=1, rse_expression=rse3, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=subid)
        add_rule(dids=[{'scope': tmp_scope, 'name': dsn}], account=root, copies=1, rse_expression=rse4, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=subid)

        for rule in list_subscription_rule_states(account='root', name=subscription_name, **self.vo):
            assert rule[3] == 2


def test_create_and_update_and_list_subscription(rse_factory, rest_client, auth_token):
    """ SUBSCRIPTION (REST): Test the creation of a new subscription, update it, list it """
    subscription_name = uuid()
    activity = get_schema_value('ACTIVITY')['enum'][0]
    rse1, _ = rse_factory.make_mock_rse()
    rse2, _ = rse_factory.make_mock_rse()
    rse_expression = '%s|%s' % (rse1, rse2)
    projects = ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV']
    pattern1 = r'(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).* \
                 \.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)'
    data = {'options': {'filter': {'project': projects, 'datatype': ['AOD', ], 'excluded_pattern': pattern1, 'account': ['tier0', ]},
                        'replication_rules': [{'lifetime': 86400, 'rse_expression': rse_expression, 'copies': 2, 'activity': activity}],
                        'lifetime': 100000, 'retroactive': 0, 'dry_run': 0, 'comments': 'blahblah'}}
    response = rest_client.post('/subscriptions/root/' + subscription_name, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    data = {'options': {'filter': {'project': ['toto', ]}}}
    response = rest_client.put('/subscriptions/root/' + subscription_name, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    response = rest_client.get('/subscriptions/root/' + subscription_name, headers=headers(auth(auth_token)))
    assert response.status_code == 200
    assert loads(loads(response.get_data(as_text=True))['filter'])['project'][0] == 'toto'


def test_create_and_list_subscription_by_id(rse_factory, rest_client, auth_token):
    """ SUBSCRIPTION (REST): Test the creation of a new subscription and get by subscription id """
    subscription_name = uuid()
    activity = get_schema_value('ACTIVITY')['enum'][0]
    rse1, _ = rse_factory.make_mock_rse()
    rse2, _ = rse_factory.make_mock_rse()
    rse_expression = '%s|%s' % (rse1, rse2)
    projects = ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV']
    pattern1 = r'(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).* \
                 \.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)'
    data = {'options': {'filter': {'project': projects, 'datatype': ['AOD', ], 'excluded_pattern': pattern1, 'account': ['tier0', ]},
                        'replication_rules': [{'lifetime': 86400, 'rse_expression': rse_expression, 'copies': 2, 'activity': activity}],
                        'lifetime': 100000, 'retroactive': 0, 'dry_run': 0, 'comments': 'blahblah'}}
    response = rest_client.post('/subscriptions/root/' + subscription_name, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    subscription_id = response.get_data(as_text=True)
    response = rest_client.get('/subscriptions/Id/' + subscription_id, headers=headers(auth(auth_token)))
    assert response.status_code == 200
    assert loads(loads(response.get_data(as_text=True))['filter'])['project'][0] == 'data12_900GeV'


def test_create_existing_subscription(rse_factory, rest_client, auth_token):
    """ SUBSCRIPTION (REST): Test the creation of a existing subscription """
    subscription_name = uuid()
    activity = get_schema_value('ACTIVITY')['enum'][0]
    rse1, _ = rse_factory.make_mock_rse()
    rse2, _ = rse_factory.make_mock_rse()
    rse_expression = '%s|%s' % (rse1, rse2)
    projects = ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV']
    pattern1 = r'(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).* \
                 \.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)'
    data = {'options': {'name': subscription_name, 'filter': {'project': projects, 'datatype': ['AOD', ], 'excluded_pattern': pattern1, 'account': ['tier0', ]},
                        'replication_rules': [{'lifetime': 86400, 'rse_expression': rse_expression, 'copies': 2, 'activity': activity}],
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
def test_list_rules_states(vo, rse_factory, rest_client, auth_token):
    """ SUBSCRIPTION (REST): Test listing of rule states for subscription """
    tmp_scope = InternalScope('mock_' + uuid()[:8], vo=vo)
    root = InternalAccount('root', vo=vo)
    add_scope(tmp_scope, root)
    activity = get_schema_value('ACTIVITY')['enum'][0]
    rse1, _ = rse_factory.make_mock_rse()
    rse2, _ = rse_factory.make_mock_rse()
    rse_expression = '%s|%s' % (rse1, rse2)

    rse3, _ = rse_factory.make_mock_rse()
    rse4, _ = rse_factory.make_mock_rse()

    # add a new dataset
    dsn = 'dataset-%s' % uuid()
    add_did(scope=tmp_scope, name=dsn,
            did_type=DIDType.DATASET, account=root)

    subscription_name = uuid()
    subid = add_subscription(name=subscription_name,
                             account='root',
                             filter_={'account': ['root', ], 'scope': [tmp_scope.external, ]},
                             replication_rules=[{'lifetime': 86400, 'rse_expression': rse_expression, 'copies': 2, 'activity': activity}],
                             lifetime=100000,
                             retroactive=0,
                             dry_run=0,
                             comments='We want a shrubbery',
                             issuer='root',
                             vo=vo)

    # Add two rules
    add_rule(dids=[{'scope': tmp_scope, 'name': dsn}], account=root, copies=1, rse_expression=rse3, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=subid)
    add_rule(dids=[{'scope': tmp_scope, 'name': dsn}], account=root, copies=1, rse_expression=rse4, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=subid)

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


@pytest.mark.usefixtures("rse_factory_unittest")
class TestSubscriptionClient(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': get_vo()}
        else:
            cls.vo = {}

        cls.sub_client = SubscriptionClient()
        cls.did_client = DIDClient()
        cls.projects = ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV']
        cls.pattern1 = r'(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).* \
                         \.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)'
        cls.activity = get_schema_value('ACTIVITY')['enum'][0]

    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_create_and_update_and_list_subscription(self):
        """ SUBSCRIPTION (CLIENT): Test the creation of a new subscription, update it, list it """
        subscription_name = uuid()
        rse1, _ = self.rse_factory.make_mock_rse()
        rse2, _ = self.rse_factory.make_mock_rse()
        rse_expression = '%s|%s' % (rse1, rse2)
        with pytest.raises(InvalidObject):
            subid = self.sub_client.add_subscription(name=subscription_name, account='root', filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                                     replication_rules=[{'lifetime': 86400, 'rse_expression': rse_expression, 'copies': 2, 'activity': 'noactivity'}], lifetime=100000, retroactive=0, dry_run=0, comments='Ni ! Ni!')
        subid = self.sub_client.add_subscription(name=subscription_name, account='root', filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                                 replication_rules=[{'lifetime': 86400, 'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}], lifetime=100000, retroactive=0, dry_run=0, comments='Ni ! Ni!')
        result = [sub['id'] for sub in list_subscriptions(name=subscription_name, account='root', **self.vo)]
        assert subid == result[0]
        with pytest.raises(TypeError):
            result = self.sub_client.update_subscription(name=subscription_name, account='root', filter_='toto')
        result = self.sub_client.update_subscription(name=subscription_name, account='root', filter_={'project': ['toto', ]})
        assert result
        result = list_subscriptions(name=subscription_name, account='root', **self.vo)
        sub = []
        for res in result:
            sub.append(res)
        assert len(sub) == 1
        assert loads(sub[0]['filter'])['project'][0] == 'toto'

    def test_create_existing_subscription(self):
        """ SUBSCRIPTION (CLIENT): Test the creation of a existing subscription """
        subscription_name = uuid()
        rse1, _ = self.rse_factory.make_mock_rse()
        rse2, _ = self.rse_factory.make_mock_rse()
        rse_expression = '%s|%s' % (rse1, rse2)
        result = self.sub_client.add_subscription(name=subscription_name, account='root', filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                                  replication_rules=[{'lifetime': 86400, 'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}], lifetime=100000, retroactive=0, dry_run=0, comments='Ni ! Ni!')
        assert result
        with pytest.raises(SubscriptionDuplicate):
            self.sub_client.add_subscription(name=subscription_name, account='root', filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                             replication_rules=[{'lifetime': 86400, 'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}], lifetime=100000, retroactive=0, dry_run=0, comments='Ni ! Ni!')

    def test_update_nonexisting_subscription(self):
        """ SUBSCRIPTION (CLIENT): Test the update of a non-existing subscription """
        subscription_name = uuid()
        with pytest.raises(SubscriptionNotFound):
            self.sub_client.update_subscription(name=subscription_name, filter_={'project': ['toto', ]})

    def test_create_and_list_subscription_by_account(self):
        """ SUBSCRIPTION (CLIENT): Test retrieval of subscriptions for an account """
        subscription_name = uuid()
        rse1, _ = self.rse_factory.make_mock_rse()
        rse2, _ = self.rse_factory.make_mock_rse()
        rse_expression = '%s|%s' % (rse1, rse2)
        account_name = uuid()[:10]
        add_account(InternalAccount(account_name, **self.vo), AccountType.USER, 'rucio@email.com')
        subid = self.sub_client.add_subscription(name=subscription_name, account=account_name, filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                                 replication_rules=[{'lifetime': 86400, 'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}], lifetime=100000, retroactive=0, dry_run=0, comments='Ni ! Ni!')
        result = [sub['id'] for sub in self.sub_client.list_subscriptions(account=account_name)]
        assert subid == result[0]

    def test_create_and_list_subscription_by_name(self):
        """ SUBSCRIPTION (CLIENT): Test retrieval of subscriptions for an account """
        subscription_name = uuid()
        rse1, _ = self.rse_factory.make_mock_rse()
        rse2, _ = self.rse_factory.make_mock_rse()
        rse_expression = '%s|%s' % (rse1, rse2)
        subid = self.sub_client.add_subscription(name=subscription_name, account='root', filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                                 replication_rules=[{'lifetime': 86400, 'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}], lifetime=100000, retroactive=0, dry_run=0, comments='Ni ! Ni!')
        result = [sub['id'] for sub in self.sub_client.list_subscriptions(name=subscription_name)]
        assert subid == result[0]

    @pytest.mark.noparallel(reason='runs transmogrifier. Cannot be run at the same time with other tests running it')
    def test_run_transmogrifier(self):
        """ SUBSCRIPTION (DAEMON): Test the transmogrifier and the split_rule mode """
        new_dids = [did for did in list_new_dids(did_type=None, thread=None, total_threads=None, chunk_size=100000, session=None)]
        set_new_dids(new_dids, None)

        rse1, _ = self.rse_factory.make_mock_rse()
        rse2, _ = self.rse_factory.make_mock_rse()
        rse3, _ = self.rse_factory.make_mock_rse()
        rse_expression = '%s|%s|%s' % (rse1, rse2, rse3)
        tmp_scope = InternalScope('mock_' + uuid()[:8], **self.vo)
        root = InternalAccount('root', **self.vo)
        add_scope(tmp_scope, root)
        subscription_name = uuid()
        dsn_prefix = did_name_generator('dataset')
        dsn = '%sdataset-%s' % (dsn_prefix, uuid())
        add_did(scope=tmp_scope, name=dsn, did_type=DIDType.DATASET, account=root)

        subid = self.sub_client.add_subscription(name=subscription_name, account='root', filter_={'scope': [tmp_scope.external, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': True},
                                                 replication_rules=[{'lifetime': 86400, 'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}],
                                                 lifetime=None, retroactive=0, dry_run=0, comments='Ni ! Ni!', priority=1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in self.did_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
        assert len(rules) == 2
        set_new_dids([{'scope': tmp_scope, 'name': dsn}, ], 1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in self.did_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
        assert len(rules) == 2

    @pytest.mark.noparallel(reason='runs transmogrifier. Cannot be run at the same time with other tests running it')
    def test_run_transmogrifier_did_type(self):
        """ SUBSCRIPTION (DAEMON): Test the transmogrifier with did_type subscriptions """
        new_dids = [did for did in list_new_dids(did_type=None, thread=None, total_threads=None, chunk_size=100000, session=None)]
        set_new_dids(new_dids, None)
        rse1, _ = self.rse_factory.make_mock_rse()
        rse2, _ = self.rse_factory.make_mock_rse()
        rse3, _ = self.rse_factory.make_mock_rse()
        rse_expression = '%s|%s|%s' % (rse1, rse2, rse3)
        tmp_scope = InternalScope('mock_' + uuid()[:8], **self.vo)
        root = InternalAccount('root', **self.vo)
        add_scope(tmp_scope, root)
        subscription_name = uuid()
        dsn_prefix = did_name_generator('dataset')
        dsn = '%sdataset-%s' % (dsn_prefix, uuid())
        add_did(scope=tmp_scope, name=dsn, did_type=DIDType.DATASET, account=root)

        subid = self.sub_client.add_subscription(name=subscription_name, account='root', filter_={'scope': [tmp_scope.external, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': True, 'did_type': ['DATASET', ]},
                                                 replication_rules=[{'lifetime': 86400, 'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}],
                                                 lifetime=None, retroactive=0, dry_run=0, comments='Ni ! Ni!', priority=1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in self.did_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
        assert len(rules) == 2
        set_new_dids([{'scope': tmp_scope, 'name': dsn}, ], 1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in self.did_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
        assert len(rules) == 2


@pytest.mark.noparallel(reason='uses daemon')
class TestDaemon():
    def test_run_transmogrifier_chained_subscription(self, rse_factory, vo, rucio_client, root_account):
        """ SUBSCRIPTION (DAEMON): Test the transmogrifier with chained subscriptions """
        rse1, rse1_id = rse_factory.make_mock_rse()
        rse2, rse2_id = rse_factory.make_mock_rse()
        rse3, _ = rse_factory.make_mock_rse()
        rse4, _ = rse_factory.make_mock_rse()
        rse5, _ = rse_factory.make_mock_rse()
        rse6, _ = rse_factory.make_mock_rse()
        add_rse_attribute(rse_id=rse1_id, key='associated_sites', value='%s,%s' % (rse3, rse4))
        add_rse_attribute(rse_id=rse2_id, key='associated_sites', value='%s,%s' % (rse5, rse6))
        rses = []
        for cnt in range(5):
            rse, _ = rse_factory.make_mock_rse()
            rses.append(rse)
        rse_expression = '%s|%s' % (rse1, rse2)
        tmp_scope = InternalScope('mock_' + uuid()[:8], vo=vo)
        add_scope(tmp_scope, root_account)
        subscription_name = uuid()
        dsn_prefix = did_name_generator('dataset')
        dsn = '%sdataset-%s' % (dsn_prefix, uuid())

        add_did(scope=tmp_scope, name=dsn, did_type=DIDType.DATASET, account=root_account)
        rule1 = {'rse_expression': rse_expression,
                 'copies': 1,
                 'activity': 'Data Brokering'}
        rule2 = {'rse_expression': '*',
                 'copies': 1,
                 'activity': 'Data Brokering',
                 'algorithm': 'associated_site',
                 'chained_idx': 1,
                 'associated_site_idx': 2}

        subid = rucio_client.add_subscription(name=subscription_name,
                                              account=root_account.external,
                                              filter_={'scope': [tmp_scope.external, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': True, 'did_type': ['DATASET', ]},
                                              replication_rules=[rule1, rule2],
                                              lifetime=None,
                                              retroactive=0,
                                              dry_run=0,
                                              comments='Ni ! Ni!',
                                              priority=1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in rucio_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
        assert len(rules) == 2
        if rules[0]['source_replica_expression']:
            rules.reverse()
        assert rules[0]['rse_expression'] in [rse1, rse2]
        if rules[0]['rse_expression'] == rse1:
            assert rules[1]['source_replica_expression'] == rse1
            assert rules[1]['rse_expression'] == rse4
        if rules[0]['rse_expression'] == rse2:
            assert rules[1]['source_replica_expression'] == rse2
            assert rules[1]['rse_expression'] == rse6

    def test_skip_subscription_bad_rse_expression(self, rse_factory, vo, rucio_client, root_account):
        """ SUBSCRIPTION (DAEMON): Check that the subscriptions with bad RSE expression are skipped"""
        _, _ = rse_factory.make_mock_rse()
        rse_expression = rse_name_generator()
        tmp_scope = InternalScope('mock_' + uuid()[:8], vo=vo)
        add_scope(tmp_scope, root_account)
        subscription_name = uuid()
        dsn_prefix = did_name_generator('dataset')
        dsn = '%sdataset-%s' % (dsn_prefix, uuid())

        add_did(scope=tmp_scope, name=dsn, did_type=DIDType.DATASET, account=root_account)
        rule = {'rse_expression': rse_expression,
                'copies': 1,
                'activity': 'Data Brokering',
                'rse_expression': rse_expression}

        rucio_client.add_subscription(name=subscription_name,
                                      account=root_account.external,
                                      filter_={'scope': [tmp_scope.external, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': True, 'did_type': ['DATASET', ]},
                                      replication_rules=[rule],
                                      lifetime=None,
                                      retroactive=0,
                                      dry_run=0,
                                      comments='Ni ! Ni!',
                                      priority=1)
        for sub in get_subscriptions():
            for rule in loads(sub["replication_rules"]):
                assert rule["rse_expression"] != rse_expression

    def test_run_transmogrifier_wildcard_copies(self, rse_factory, vo, rucio_client, root_account):
        """ SUBSCRIPTION (DAEMON): Test the transmogrifier with wildcard copies """
        rse_attribute = uuid()[:8]
        rses = {'no_tag': [], rse_attribute: []}
        for cnt in range(5):
            rse, rse_id = rse_factory.make_mock_rse()
            rses['no_tag'].append(rse)
        for cnt in range(5):
            rse, rse_id = rse_factory.make_mock_rse()
            add_rse_attribute(rse_id=rse_id, key=rse_attribute, value=True)
            rses[rse_attribute].append(rse)
        rse_expression = rse_attribute
        tmp_scope = InternalScope('mock_' + uuid()[:8], vo=vo)
        add_scope(tmp_scope, root_account)

        # Check without split rule
        subscription_name = uuid()
        dsn_prefix = did_name_generator('dataset')
        dsn = '%sdataset-%s' % (dsn_prefix, uuid())

        add_did(scope=tmp_scope, name=dsn, did_type=DIDType.DATASET, account=root_account)
        rule = {'rse_expression': rse_expression,
                'copies': '*',
                'activity': 'Data Brokering',
                'rse_expression': rse_expression}

        subid = rucio_client.add_subscription(name=subscription_name,
                                              account=root_account.external,
                                              filter_={'scope': [tmp_scope.external, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': True, 'did_type': ['DATASET', ]},
                                              replication_rules=[rule],
                                              lifetime=None,
                                              retroactive=0,
                                              dry_run=0,
                                              comments='Ni ! Ni!',
                                              priority=1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in rucio_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]

        # Check with split rule
        subscription_name = uuid()
        dsn_prefix = did_name_generator('dataset')
        dsn = '%sdataset-%s' % (dsn_prefix, uuid())

        add_did(scope=tmp_scope, name=dsn, did_type=DIDType.DATASET, account=root_account)
        rule = {'rse_expression': rse_expression,
                'copies': '*',
                'activity': 'Data Brokering',
                'rse_expression': rse_expression}

        subid = rucio_client.add_subscription(name=subscription_name,
                                              account=root_account.external,
                                              filter_={'scope': [tmp_scope.external, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': False, 'did_type': ['DATASET', ]},
                                              replication_rules=[rule],
                                              lifetime=None,
                                              retroactive=0,
                                              dry_run=0,
                                              comments='Ni ! Ni!',
                                              priority=1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in rucio_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
        assert len(rules) == 1
        assert rules[0]['copies'] == 5

    def test_run_transmogrifier_delayed_subscription(self, rse_factory, vo, rucio_client, root_account, mock_scope):
        """ SUBSCRIPTION (DAEMON): Test the transmogrifier with delayed subscription """
        nbfiles = 3
        rse1, _ = rse_factory.make_mock_rse()
        rse2, rse2_id = rse_factory.make_mock_rse()
        rse3, _ = rse_factory.make_mock_rse()
        rse_expression = rse1
        subscription_name = uuid()
        dsn_prefix = did_name_generator('dataset')
        dsn = '%sdataset-%s' % (dsn_prefix, uuid())

        files = [{'scope': mock_scope, 'name': did_name_generator('file'), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        add_did(scope=mock_scope, name=dsn, did_type=DIDType.DATASET, account=root_account)
        attach_dids(scope=mock_scope, name=dsn, rse_id=rse2_id, dids=files, account=root_account)
        rule = {'rse_expression': rse_expression,
                'copies': 1,
                'activity': 'Data Brokering',
                'delay_injection': 86500}

        subid = rucio_client.add_subscription(name=subscription_name,
                                              account=root_account.external,
                                              filter_={'scope': [mock_scope.external, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': True, 'did_type': ['DATASET', ]},
                                              replication_rules=[rule],
                                              lifetime=None,
                                              retroactive=0,
                                              dry_run=0,
                                              comments='Ni ! Ni!',
                                              priority=1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in rucio_client.list_did_rules(scope=mock_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
        print(rules)
        assert rules[0]['rse_expression'] == rse_expression
        assert rules[0]['state'] == RuleState.INJECT.name
        assert (rules[0]['created_at'] - datetime.now()).days == 1
