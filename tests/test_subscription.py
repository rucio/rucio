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

import time
from datetime import datetime
from json import loads
from json.decoder import JSONDecodeError

import pytest
from sqlalchemy import select

from rucio.common.constants import RseAttr
from rucio.common.exception import InvalidObject, SubscriptionDuplicate, SubscriptionNotFound
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid as uuid
from rucio.core import subscription as subscription_core
from rucio.core.account import add_account
from rucio.core.did import add_did, attach_dids, list_new_dids, set_new_dids, set_status
from rucio.core.rse import add_rse_attribute, update_rse
from rucio.core.rule import add_rule
from rucio.core.scope import add_scope
from rucio.daemons.transmogrifier.transmogrifier import get_subscriptions, run
from rucio.db.sqla import models
from rucio.db.sqla.constants import AccountType, DatabaseOperationType, DIDType, RuleState
from rucio.db.sqla.session import db_session, read_session
from rucio.gateway.subscription import add_subscription, get_subscription_by_id, list_subscription_rule_states, list_subscriptions, update_subscription
from rucio.tests.common import auth, did_name_generator, headers, rse_name_generator


@read_session
def get_subscription_history(subscription_name, *, session=None):
    stmt = select(models.SubscriptionHistory).where(models.SubscriptionHistory.name == subscription_name).order_by(models.SubscriptionHistory.updated_at)
    return [hist[0] for hist in session.execute(stmt)]


class TestSubscriptionCoreGateway:
    projects = ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV']
    pattern1 = r'(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).* \
                \.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)'
    activity = "Staging"

    def test_create_and_update_and_list_subscription(self, vo, rse_factory):
        """ SUBSCRIPTION (Gateway): Test the creation of a new subscription, update it, list it """
        rse1, _ = rse_factory.make_mock_rse()
        rse2, _ = rse_factory.make_mock_rse()
        rse_expression = '%s|%s' % (rse1, rse2)
        subscription_name = uuid()
        with pytest.raises(InvalidObject):
            add_subscription(name=subscription_name,
                             account='root',
                             filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                             replication_rules=[{'rse_expression': rse_expression, 'copies': 2, 'activity': 'noactivity'}],
                             lifetime=100000,
                             retroactive=False,
                             dry_run=False,
                             comments='This is a comment',
                             issuer='root',
                             vo=vo)

        sub_id = add_subscription(name=subscription_name,
                                  account='root',
                                  filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                  replication_rules=[{'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}],
                                  lifetime=100000,
                                  retroactive=False,
                                  dry_run=False,
                                  comments='This is a comment',
                                  issuer='root',
                                  vo=vo)

        with pytest.raises(TypeError):
            result = update_subscription(name=subscription_name, account='root', metadata={'filter': 'toto'}, issuer='root', vo=vo)
        with pytest.raises(InvalidObject):
            result = update_subscription(name=subscription_name, account='root', metadata={'filter': {'project': 'toto'}}, issuer='root', vo=vo)
        result = update_subscription(name=subscription_name, account='root', metadata={'filter': {'project': ['toto', ]}}, issuer='root', vo=vo)
        assert result is None
        result = list_subscriptions(name=subscription_name, account='root', vo=vo)
        sub = []
        for res in result:
            sub.append(res)
        assert len(sub) == 1
        assert loads(sub[0]['filter'])['project'][0] == 'toto'
        subscription_core.delete_subscription(sub_id)
        with pytest.raises(SubscriptionNotFound):
            get_subscription_by_id(sub_id, vo=vo)

    @pytest.mark.dirty
    @pytest.mark.parametrize("file_config_mock", [
        {"overrides": [('subscriptions', 'keep_history', 'True')]},
    ], indirect=True)
    def test_keep_history_subscription(self, vo, rse_factory, file_config_mock):
        """ SUBSCRIPTION (CLIENT): Test the keep_history option """
        subscription_name = uuid()
        rse1, _ = rse_factory.make_mock_rse()
        rse2, _ = rse_factory.make_mock_rse()
        rse_expression = '%s|%s' % (rse1, rse2)
        sub_id = add_subscription(name=subscription_name,
                                  account='root',
                                  filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                  replication_rules=[{'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}],
                                  lifetime=100000,
                                  retroactive=False,
                                  dry_run=False,
                                  comments='This is a comment',
                                  issuer='root',
                                  vo=vo)
        result = [sub['id'] for sub in list_subscriptions(name=subscription_name, account='root', vo=vo)]
        assert sub_id == result[0]
        time.sleep(1)
        result = update_subscription(name=subscription_name, account='root', metadata={'filter': {'project': ['toto', ]}}, issuer='root', vo=vo)
        assert result is None
        result = list_subscriptions(name=subscription_name, account='root', vo=vo)
        sub = []
        for res in result:
            sub.append(res)
        assert len(sub) == 1
        assert loads(sub[0]['filter'])['project'][0] == 'toto'
        # Check that the history was properly updated
        history = get_subscription_history(subscription_name)
        assert len(history) == 2
        assert history[0]['updated_at'] < history[1]['updated_at']
        assert (loads(history[0]['filter'])['project']) == self.projects
        assert (loads(history[1]['filter'])['project']) == ['toto', ]

    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_create_list_subscription_by_id(self, vo, rse_factory):
        """ SUBSCRIPTION (Gateway): Test the creation of a new subscription and list it by id """
        rse1, _ = rse_factory.make_mock_rse()
        rse2, _ = rse_factory.make_mock_rse()
        rse_expression = '%s|%s' % (rse1, rse2)
        subscription_name = uuid()
        subscription_id = add_subscription(name=subscription_name,
                                           account='root',
                                           filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                           replication_rules=[{'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}],
                                           lifetime=100000,
                                           retroactive=False,
                                           dry_run=False,
                                           comments='This is a comment',
                                           issuer='root',
                                           vo=vo)

        subscription_info = get_subscription_by_id(subscription_id, vo=vo)
        assert loads(subscription_info['filter'])['project'] == self.projects

    def test_create_existing_subscription(self, vo, rse_factory):
        """ SUBSCRIPTION (Gateway): Test the creation of a existing subscription """
        subscription_name = uuid()
        rse1, _ = rse_factory.make_mock_rse()
        rse2, _ = rse_factory.make_mock_rse()
        rse_expression = '%s|%s' % (rse1, rse2)

        def genkwargs(rse_expression):
            kwargs = {
                'name': subscription_name,
                'account': 'root',
                'filter_': {'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                'replication_rules': [{'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}],
                'lifetime': 100000,
                'retroactive': 0,
                'dry_run': 0,
                'comments': 'This is a comment',
                'issuer': 'root'
            }
            kwargs.update({'vo': vo})
            return kwargs

        add_subscription(**genkwargs(rse_expression))

        with pytest.raises(SubscriptionDuplicate):
            add_subscription(**genkwargs(rse_expression))

    def test_update_nonexisting_subscription(self, vo):
        """ SUBSCRIPTION (Gateway): Test the update of a non-existing subscription """
        subscription_name = uuid()
        with pytest.raises(SubscriptionNotFound):
            update_subscription(name=subscription_name, account='root', metadata={'filter': {'project': ['toto', ]}}, issuer='root', vo=vo)

    def test_list_rules_states(self, vo, rse_factory, root_account):
        """ SUBSCRIPTION (Gateway): Test listing of rule states for subscription """
        tmp_scope = InternalScope('mock_' + uuid()[:8], vo=vo)
        with db_session(DatabaseOperationType.WRITE) as session:
            add_scope(tmp_scope, root_account, session=session)
        rse1, _ = rse_factory.make_mock_rse()
        rse2, _ = rse_factory.make_mock_rse()
        rse_expression = '%s|%s' % (rse1, rse2)

        rse3, _ = rse_factory.make_mock_rse()
        rse4, _ = rse_factory.make_mock_rse()

        # add a new dataset
        dsn = did_name_generator('dataset')
        add_did(scope=tmp_scope, name=dsn,
                did_type=DIDType.DATASET, account=root_account)

        subscription_name = uuid()
        subid = add_subscription(name=subscription_name,
                                 account='root',
                                 filter_={'account': ['root', ], 'scope': [tmp_scope.external, ]},
                                 replication_rules=[{'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}],
                                 lifetime=100000,
                                 retroactive=False,
                                 dry_run=False,
                                 comments='This is a comment',
                                 issuer='root',
                                 vo=vo)

        # Add two rules
        add_rule(dids=[{'scope': tmp_scope, 'name': dsn}], account=root_account, copies=1, rse_expression=rse3, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=subid)
        add_rule(dids=[{'scope': tmp_scope, 'name': dsn}], account=root_account, copies=1, rse_expression=rse4, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=subid)

        for rule in list_subscription_rule_states(account='root', name=subscription_name, vo=vo):
            assert rule[3] == 2


def test_create_and_update_and_list_subscription(rse_factory, rest_client, auth_token):
    """ SUBSCRIPTION (REST): Test the creation of a new subscription, update it, list it """
    subscription_name = uuid()
    activity = "Staging"
    rse1, _ = rse_factory.make_mock_rse()
    rse2, _ = rse_factory.make_mock_rse()
    rse_expression = '%s|%s' % (rse1, rse2)
    projects = ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV']
    pattern1 = r'(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).* \
                 \.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)'
    data = {'options': {'filter': {'project': projects, 'datatype': ['AOD', ], 'excluded_pattern': pattern1, 'account': ['tier0', ]},
                        'replication_rules': [{'rse_expression': rse_expression, 'copies': 2, 'activity': activity}],
                        'lifetime': 100000, 'retroactive': 0, 'dry_run': 0, 'comments': 'blahblah'}}
    response = rest_client.post('/subscriptions/root/' + subscription_name, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    data = {'options': {'filter': {'project': ['toto', ]}}}
    response = rest_client.put('/subscriptions/root/' + subscription_name, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    response = rest_client.get('/subscriptions/root/' + subscription_name, headers=headers(auth(auth_token)))
    assert response.status_code == 200
    response_data = loads(response.get_data(as_text=True))
    assert loads(response_data['filter'])['project'][0] == 'toto'
    assert response_data['state'] != 'INACTIVE'  # Verify the subscription can be updated to inactive after creation

    # Set the subscription as inactive
    data = {'options': {'state': 'I'}}
    response = rest_client.put('/subscriptions/root/' + subscription_name, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    response = rest_client.get('/subscriptions/root/' + subscription_name, headers=headers(auth(auth_token)))
    assert response.status_code == 200
    assert loads(response.get_data(as_text=True))['state'] == 'INACTIVE'


def test_create_and_list_subscription_by_id(rse_factory, rest_client, auth_token):
    """ SUBSCRIPTION (REST): Test the creation of a new subscription and get by subscription id """
    subscription_name = uuid()
    activity = "Staging"
    rse1, _ = rse_factory.make_mock_rse()
    rse2, _ = rse_factory.make_mock_rse()
    rse_expression = '%s|%s' % (rse1, rse2)
    projects = ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV']
    pattern1 = r'(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).* \
                 \.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)'
    data = {'options': {'filter': {'project': projects, 'datatype': ['AOD', ], 'excluded_pattern': pattern1, 'account': ['tier0', ]},
                        'replication_rules': [{'rse_expression': rse_expression, 'copies': 2, 'activity': activity}],
                        'lifetime': 100000, 'retroactive': 0, 'dry_run': 0, 'comments': 'blahblah'}}
    response = rest_client.post('/subscriptions/root/' + subscription_name, headers=headers(auth(auth_token)), json=data)
    assert response.status_code == 201

    subscription_id = response.get_data(as_text=True)
    response = rest_client.get('/subscriptions/id/' + subscription_id, headers=headers(auth(auth_token)))
    assert response.status_code == 200
    assert loads(loads(response.get_data(as_text=True))['filter'])['project'][0] == 'data12_900GeV'


def test_create_existing_subscription(rse_factory, rest_client, auth_token):
    """ SUBSCRIPTION (REST): Test the creation of a existing subscription """
    subscription_name = uuid()
    activity = "Staging"
    rse1, _ = rse_factory.make_mock_rse()
    rse2, _ = rse_factory.make_mock_rse()
    rse_expression = '%s|%s' % (rse1, rse2)
    projects = ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV']
    pattern1 = r'(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).* \
                 \.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)'
    data = {'options': {'name': subscription_name, 'filter': {'project': projects, 'datatype': ['AOD', ], 'excluded_pattern': pattern1, 'account': ['tier0', ]},
                        'replication_rules': [{'rse_expression': rse_expression, 'copies': 2, 'activity': activity}],
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
def test_list_rules_states(vo, rse_factory, rest_client, auth_token, root_account):
    """ SUBSCRIPTION (REST): Test listing of rule states for subscription """
    tmp_scope = InternalScope('mock_' + uuid()[:8], vo=vo)
    with db_session(DatabaseOperationType.WRITE) as session:
        add_scope(tmp_scope, root_account, session=session)
    activity = "Staging"
    rse1, _ = rse_factory.make_mock_rse()
    rse2, _ = rse_factory.make_mock_rse()
    rse_expression = '%s|%s' % (rse1, rse2)

    rse3, _ = rse_factory.make_mock_rse()
    rse4, _ = rse_factory.make_mock_rse()

    # add a new dataset
    dsn = 'dataset-%s' % uuid()
    add_did(scope=tmp_scope, name=dsn,
            did_type=DIDType.DATASET, account=root_account)

    subscription_name = uuid()
    subid = add_subscription(name=subscription_name,
                             account='root',
                             filter_={'account': ['root', ], 'scope': [tmp_scope.external, ]},
                             replication_rules=[{'rse_expression': rse_expression, 'copies': 2, 'activity': activity}],
                             lifetime=100000,
                             retroactive=False,
                             dry_run=False,
                             comments='We want a shrubbery',
                             issuer='root',
                             vo=vo)

    # Add two rules
    add_rule(dids=[{'scope': tmp_scope, 'name': dsn}], account=root_account, copies=1, rse_expression=rse3, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=subid)
    add_rule(dids=[{'scope': tmp_scope, 'name': dsn}], account=root_account, copies=1, rse_expression=rse4, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=subid)

    response = rest_client.get('/subscriptions/%s/%s/rules/states' % ('root', subscription_name), headers=headers(auth(auth_token)))
    assert response.status_code == 200

    rulestates = None
    for line in response.get_data(as_text=True).split('\n'):
        if line:
            rulestates = loads(line)
            if rulestates[1] == subscription_name:
                break
    assert rulestates is not None
    assert rulestates[3] == 2


class TestSubscriptionClient:

    projects = ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV']
    pattern1 = r'(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).* \
                 \.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)'
    activity = "Staging"

    @pytest.mark.noparallel(reason='uses pre-defined RSE')
    def test_create_and_update_and_list_subscription(self, vo, rse_factory, rucio_client):
        """ SUBSCRIPTION (CLIENT): Test the creation of a new subscription, update it, list it """
        subscription_name = uuid()
        rse1, _ = rse_factory.make_mock_rse()
        rse2, _ = rse_factory.make_mock_rse()
        rse_expression = '%s|%s' % (rse1, rse2)
        with pytest.raises(InvalidObject):
            subid = rucio_client.add_subscription(name=subscription_name, account='root', filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                                  replication_rules=[{'rse_expression': rse_expression, 'copies': 2, 'activity': 'noactivity'}], lifetime=100000, retroactive=False, dry_run=False, comments='Ni ! Ni!')
        subid = rucio_client.add_subscription(name=subscription_name, account='root', filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                              replication_rules=[{'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}], lifetime=100000, retroactive=False, dry_run=False, comments='Ni ! Ni!')
        result = [sub['id'] for sub in list_subscriptions(name=subscription_name, account='root', vo=vo)]
        assert subid == result[0]
        with pytest.raises(TypeError):
            result = rucio_client.update_subscription(name=subscription_name, account='root', filter_='toto')
        result = rucio_client.update_subscription(name=subscription_name, account='root', filter_={'project': ['toto', ]})
        assert result
        result = list_subscriptions(name=subscription_name, account='root', vo=vo)
        sub = []
        for res in result:
            sub.append(res)
        assert len(sub) == 1
        assert loads(sub[0]['filter'])['project'][0] == 'toto'

    def test_create_existing_subscription(self, rse_factory, rucio_client):
        """ SUBSCRIPTION (CLIENT): Test the creation of a existing subscription """
        subscription_name = uuid()
        rse1, _ = rse_factory.make_mock_rse()
        rse2, _ = rse_factory.make_mock_rse()
        rse_expression = '%s|%s' % (rse1, rse2)
        result = rucio_client.add_subscription(name=subscription_name, account='root', filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                               replication_rules=[{'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}], lifetime=100000, retroactive=False, dry_run=False, comments='Ni ! Ni!')
        assert result
        with pytest.raises(SubscriptionDuplicate):
            rucio_client.add_subscription(name=subscription_name, account='root', filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                          replication_rules=[{'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}], lifetime=100000, retroactive=False, dry_run=False, comments='Ni ! Ni!')

    def test_update_nonexisting_subscription(self, rucio_client):
        """ SUBSCRIPTION (CLIENT): Test the update of a non-existing subscription """
        subscription_name = uuid()
        with pytest.raises(SubscriptionNotFound):
            rucio_client.update_subscription(name=subscription_name, filter_={'project': ['toto', ]})

    def test_create_and_list_subscription_by_account(self, vo, rse_factory, rucio_client):
        """ SUBSCRIPTION (CLIENT): Test retrieval of subscriptions for an account """
        subscription_name = uuid()
        rse1, _ = rse_factory.make_mock_rse()
        rse2, _ = rse_factory.make_mock_rse()
        rse_expression = '%s|%s' % (rse1, rse2)
        account_name = uuid()[:10]
        add_account(InternalAccount(account_name, vo=vo), AccountType.USER, 'rucio@email.com')
        subid = rucio_client.add_subscription(name=subscription_name, account=account_name, filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                              replication_rules=[{'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}], lifetime=100000, retroactive=False, dry_run=False, comments='Ni ! Ni!')
        result = [sub['id'] for sub in rucio_client.list_subscriptions(account=account_name)]
        assert subid == result[0]

    def test_create_and_list_subscription_by_name(self, rse_factory, rucio_client):
        """ SUBSCRIPTION (CLIENT): Test retrieval of subscriptions for an account """
        subscription_name = uuid()
        rse1, _ = rse_factory.make_mock_rse()
        rse2, _ = rse_factory.make_mock_rse()
        rse_expression = '%s|%s' % (rse1, rse2)
        subid = rucio_client.add_subscription(name=subscription_name, account='root', filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                              replication_rules=[{'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}], lifetime=100000, retroactive=False, dry_run=False, comments='Ni ! Ni!')
        result = [sub['id'] for sub in rucio_client.list_subscriptions(name=subscription_name)]
        assert subid == result[0]

    @pytest.mark.noparallel(reason='runs transmogrifier. Cannot be run at the same time with other tests running it')
    def test_run_transmogrifier(self, vo, rse_factory, rucio_client, root_account):
        """ SUBSCRIPTION (DAEMON): Test the transmogrifier and the split_rule mode """
        new_dids = [did for did in list_new_dids(did_type=None, thread=None, total_threads=None, chunk_size=100000, session=None)]
        set_new_dids(new_dids, None)

        rse1, _ = rse_factory.make_mock_rse()
        rse2, _ = rse_factory.make_mock_rse()
        rse3, _ = rse_factory.make_mock_rse()
        rse_expression = '%s|%s|%s' % (rse1, rse2, rse3)
        tmp_scope = InternalScope('mock_' + uuid()[:8], vo=vo)
        with db_session(DatabaseOperationType.WRITE) as session:
            add_scope(tmp_scope, root_account, session=session)
        subscription_name = uuid()
        dsn_prefix = did_name_generator('dataset')
        dsn = '%sdataset-%s' % (dsn_prefix, uuid())
        add_did(scope=tmp_scope, name=dsn, did_type=DIDType.DATASET, account=root_account)

        subid = rucio_client.add_subscription(name=subscription_name, account='root', filter_={'scope': [tmp_scope.external, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': True},
                                              replication_rules=[{'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}],
                                              lifetime=None, retroactive=False, dry_run=False, comments='Ni ! Ni!', priority=1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in rucio_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
        assert len(rules) == 2
        set_new_dids([{'scope': tmp_scope, 'name': dsn}, ], 1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in rucio_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
        assert len(rules) == 2

    @pytest.mark.noparallel(reason='runs transmogrifier. Cannot be run at the same time with other tests running it')
    def test_run_transmogrifier_did_type(self, vo, rse_factory, rucio_client, root_account):
        """ SUBSCRIPTION (DAEMON): Test the transmogrifier with did_type subscriptions """
        new_dids = [did for did in list_new_dids(did_type=None, thread=None, total_threads=None, chunk_size=100000, session=None)]
        set_new_dids(new_dids, None)
        rse1, _ = rse_factory.make_mock_rse()
        rse2, _ = rse_factory.make_mock_rse()
        rse3, _ = rse_factory.make_mock_rse()
        rse_expression = '%s|%s|%s' % (rse1, rse2, rse3)
        tmp_scope = InternalScope('mock_' + uuid()[:8], vo=vo)
        with db_session(DatabaseOperationType.WRITE) as session:
            add_scope(tmp_scope, root_account, session=session)
        subscription_name = uuid()
        dsn_prefix = did_name_generator('dataset')
        dsn = '%sdataset-%s' % (dsn_prefix, uuid())
        add_did(scope=tmp_scope, name=dsn, did_type=DIDType.DATASET, account=root_account)

        subid = rucio_client.add_subscription(name=subscription_name, account='root', filter_={'scope': [tmp_scope.external, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': True, 'did_type': ['DATASET', ]},
                                              replication_rules=[{'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}],
                                              lifetime=None, retroactive=False, dry_run=False, comments='Ni ! Ni!', priority=1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in rucio_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
        assert len(rules) == 2
        set_new_dids([{'scope': tmp_scope, 'name': dsn}, ], 1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in rucio_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
        assert len(rules) == 2

    def test_deactivate_subscription(self, rse_factory, rucio_client, vo):
        """SUBSCRIPTION (CLIENT): Verify a subscription can be marked as inactive"""
        subscription_name = uuid()
        rse1, _ = rse_factory.make_mock_rse()
        rse2, _ = rse_factory.make_mock_rse()
        rse_expression = '%s|%s' % (rse1, rse2)
        account_name = uuid()[:10]
        add_account(InternalAccount(account_name, vo=vo), AccountType.USER, 'rucio@email.com')
        rucio_client.add_subscription(
            name=subscription_name, account=account_name, filter_={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
            replication_rules=[{'rse_expression': rse_expression, 'copies': 2, 'activity': self.activity}], lifetime=100000, retroactive=False, dry_run=False, comments='Ni ! Ni!')
        states = [r['state'] for r in rucio_client.list_subscriptions(name=subscription_name, account=account_name)]
        assert states[0] != 'INACTIVE'

        rucio_client.deactivate_subscription(name=subscription_name, account=account_name)
        states = [r['state'] for r in rucio_client.list_subscriptions(name=subscription_name, account=account_name)]
        assert states[0] == 'INACTIVE'


@pytest.mark.noparallel(reason='uses daemon')
class TestDaemon:
    def test_run_transmogrifier_chained_subscription_associated_sites_algo(self, rse_factory, vo, rucio_client, root_account):
        """ SUBSCRIPTION (DAEMON): Test the transmogrifier with chained subscriptions and associated_sites algorithm"""
        activity = "Staging"
        rse1, rse1_id = rse_factory.make_mock_rse()
        rse2, rse2_id = rse_factory.make_mock_rse()
        rse3, _ = rse_factory.make_mock_rse()
        rse4, _ = rse_factory.make_mock_rse()
        rse5, _ = rse_factory.make_mock_rse()
        rse6, _ = rse_factory.make_mock_rse()
        add_rse_attribute(rse_id=rse1_id, key=RseAttr.ASSOCIATED_SITES, value='%s,%s' % (rse3, rse4))
        add_rse_attribute(rse_id=rse2_id, key=RseAttr.ASSOCIATED_SITES, value='%s,%s' % (rse5, rse6))
        rses = []
        for cnt in range(5):
            rse, _ = rse_factory.make_mock_rse()
            rses.append(rse)
        rse_expression = '%s|%s' % (rse1, rse2)
        tmp_scope = InternalScope('mock_' + uuid()[:8], vo=vo)
        with db_session(DatabaseOperationType.WRITE) as session:
            add_scope(tmp_scope, root_account, session=session)
        subscription_name = uuid()
        dsn_prefix = did_name_generator('dataset')
        dsn = '%sdataset-%s' % (dsn_prefix, uuid())

        add_did(scope=tmp_scope, name=dsn, did_type=DIDType.DATASET, account=root_account)
        rule1 = {'rse_expression': rse_expression,
                 'copies': 1,
                 'activity': activity}
        rule2 = {'rse_expression': '*',
                 'copies': 1,
                 'activity': activity,
                 'algorithm': 'associated_site',
                 'chained_idx': 1,
                 'associated_site_idx': 2}

        subid = rucio_client.add_subscription(name=subscription_name,
                                              account=root_account.external,
                                              filter_={'scope': [tmp_scope.external, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': True, 'did_type': ['DATASET', ]},
                                              replication_rules=[rule1, rule2],
                                              lifetime=None,
                                              retroactive=False,
                                              dry_run=False,
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
        activity = "Staging"
        _, _ = rse_factory.make_mock_rse()
        rse_expression = rse_name_generator()
        tmp_scope = InternalScope('mock_' + uuid()[:8], vo=vo)
        with db_session(DatabaseOperationType.WRITE) as session:
            add_scope(tmp_scope, root_account, session=session)
        subscription_name = uuid()
        dsn_prefix = did_name_generator('dataset')
        dsn = '%sdataset-%s' % (dsn_prefix, uuid())

        add_did(scope=tmp_scope, name=dsn, did_type=DIDType.DATASET, account=root_account)
        rule = {'rse_expression': rse_expression,
                'copies': 1,
                'activity': activity}

        rucio_client.add_subscription(name=subscription_name,
                                      account=root_account.external,
                                      filter_={'scope': [tmp_scope.external, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': True, 'did_type': ['DATASET', ]},
                                      replication_rules=[rule],
                                      lifetime=None,
                                      retroactive=False,
                                      dry_run=False,
                                      comments='Ni ! Ni!',
                                      priority=1)
        for sub in get_subscriptions():
            for rule in loads(sub["replication_rules"]):
                assert rule["rse_expression"] != rse_expression

    def test_run_transmogrifier_wildcard_copies(self, rse_factory, vo, rucio_client, root_account):
        """ SUBSCRIPTION (DAEMON): Test the transmogrifier with wildcard copies """
        activity = "Staging"
        rse_attribute = uuid()[:8]
        rses = {'no_tag': [], rse_attribute: []}
        nb_rses = 5
        for cnt in range(nb_rses):
            rse, rse_id = rse_factory.make_mock_rse()
            rses['no_tag'].append(rse)
        for cnt in range(nb_rses):
            rse, rse_id = rse_factory.make_mock_rse()
            add_rse_attribute(rse_id=rse_id, key=rse_attribute, value=True)
            rses[rse_attribute].append(rse)
        rse_expression = rse_attribute
        tmp_scope = InternalScope('mock_' + uuid()[:8], vo=vo)
        with db_session(DatabaseOperationType.WRITE) as session:
            add_scope(tmp_scope, root_account, session=session)

        # Check with split rule
        subscription_name = uuid()
        dsn_prefix = did_name_generator('dataset')
        dsn = '%sdataset-%s' % (dsn_prefix, uuid())

        add_did(scope=tmp_scope, name=dsn, did_type=DIDType.DATASET, account=root_account)
        rule = {'rse_expression': rse_expression,
                'copies': '*',
                'activity': activity}

        subid = rucio_client.add_subscription(name=subscription_name,
                                              account=root_account.external,
                                              filter_={'scope': [tmp_scope.external, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': True, 'did_type': ['DATASET', ]},
                                              replication_rules=[rule],
                                              lifetime=None,
                                              retroactive=False,
                                              dry_run=False,
                                              comments='Ni ! Ni!',
                                              priority=1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in rucio_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
        assert len(rules) == nb_rses

        # Check without split rule
        subscription_name = uuid()
        dsn_prefix = did_name_generator('dataset')
        dsn = '%sdataset-%s' % (dsn_prefix, uuid())

        add_did(scope=tmp_scope, name=dsn, did_type=DIDType.DATASET, account=root_account)
        rule = {'rse_expression': rse_expression,
                'copies': '*',
                'activity': activity}

        subid = rucio_client.add_subscription(name=subscription_name,
                                              account=root_account.external,
                                              filter_={'scope': [tmp_scope.external, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': False, 'did_type': ['DATASET', ]},
                                              replication_rules=[rule],
                                              lifetime=None,
                                              retroactive=False,
                                              dry_run=False,
                                              comments='Ni ! Ni!',
                                              priority=1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in rucio_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
        assert len(rules) == 1
        assert rules[0]['copies'] == nb_rses

    def test_run_transmogrifier_delayed_subscription(self, rse_factory, vo, rucio_client, root_account, mock_scope):
        """ SUBSCRIPTION (DAEMON): Test the transmogrifier with delayed subscription """
        activity = "Staging"
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
                'activity': activity,
                'delay_injection': 86500}

        subid = rucio_client.add_subscription(name=subscription_name,
                                              account=root_account.external,
                                              filter_={'scope': [mock_scope.external, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': True, 'did_type': ['DATASET', ]},
                                              replication_rules=[rule],
                                              lifetime=None,
                                              retroactive=False,
                                              dry_run=False,
                                              comments='Ni ! Ni!',
                                              priority=1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in rucio_client.list_did_rules(scope=mock_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
        print(rules)
        assert rules[0]['rse_expression'] == rse_expression
        assert rules[0]['state'] == RuleState.INJECT.name
        assert (rules[0]['created_at'] - datetime.now()).days == 1

    def test_run_transmogrifier_invalid_subscription(self, rse_factory, vo, rucio_client, root_account, mock_scope):
        """ SUBSCRIPTION (DAEMON): Test the transmogrifier with invalid subscription """
        activity = "Staging"
        nbfiles = 3
        rse1, _ = rse_factory.make_mock_rse()
        rse2, rse2_id = rse_factory.make_mock_rse()
        rse3, _ = rse_factory.make_mock_rse()
        rse_expression = rse1
        subscription_name = uuid()
        dsn_prefix = did_name_generator('dataset')
        dsn = '%sdataset-%s' % (dsn_prefix, uuid())

        new_dids = [did for did in list_new_dids(did_type=None, thread=None, total_threads=None, chunk_size=100000, session=None)]
        set_new_dids(new_dids, None)

        files = [{'scope': mock_scope, 'name': did_name_generator('file'), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
        add_did(scope=mock_scope, name=dsn, did_type=DIDType.DATASET, account=root_account)
        attach_dids(scope=mock_scope, name=dsn, rse_id=rse2_id, dids=files, account=root_account)
        rule = {'rse_expression': rse_expression,
                'copies': 1,
                'activity': activity,
                'delay_injection': 86500}

        sub_id = subscription_core.add_subscription(name=subscription_name,
                                                    account=root_account,
                                                    filter_='{[',
                                                    replication_rules='{]',
                                                    lifetime=None,
                                                    retroactive=False,
                                                    dry_run=False,
                                                    comments='Ni ! Ni!',
                                                    priority=1)
        # Since the subscription is wrongly defined, the new DIDs should not be processed
        with pytest.raises(JSONDecodeError):
            run(threads=1, bulk=1000000, once=True)
        new_dids = [did for did in list_new_dids(did_type=None, thread=None, total_threads=None, chunk_size=100000, session=None)]
        assert {'scope': mock_scope, 'name': dsn, 'did_type': DIDType.DATASET} in new_dids
        for file_ in files:
            assert {'scope': file_['scope'], 'name': file_['name'], 'did_type': DIDType.FILE} in new_dids
        subscription_core.update_subscription(name=subscription_name, account=root_account, metadata={'filter_': {'scope': [mock_scope, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': True, 'did_type': ['DATASET', ]}, 'replication_rules': [rule]})
        run(threads=1, bulk=1000000, once=True)
        new_dids = [did for did in list_new_dids(did_type=None, thread=None, total_threads=None, chunk_size=100000, session=None)]
        assert new_dids == []
        subscription_core.delete_subscription(sub_id)

    @pytest.mark.dirty
    @pytest.mark.parametrize("file_config_mock", [
        {"overrides": [('subscriptions', 'reevaluate_dids_at_close', 'True')]},
    ], indirect=True)
    def test_avg_file_size_filtering(self, rse_factory, vo, rucio_client, root_account, mock_scope, file_config_mock):
        """ SUBSCRIPTION (DAEMON): Test that the transmogrifier can handle min_avg_file_size and max_avg_file_size"""
        activity = "Staging"
        nbfiles = 3
        file_size_threshold = 500
        min_file_size = 100
        max_file_size = 1000
        rse1, _ = rse_factory.make_mock_rse()
        rse2, _ = rse_factory.make_mock_rse()
        rse3, rse3_id = rse_factory.make_mock_rse()
        dsn_prefix = did_name_generator('dataset')
        subscription_name = uuid()

        subid1 = rucio_client.add_subscription(name=subscription_name + 'min_avg_file_size',
                                               account=root_account.external,
                                               filter_={'scope': [mock_scope.external, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': False, 'did_type': ['DATASET', ], 'min_avg_file_size': file_size_threshold},
                                               replication_rules=[{'rse_expression': rse1, 'copies': 1, 'activity': activity}],
                                               lifetime=None,
                                               retroactive=False,
                                               dry_run=False,
                                               comments='Test min_avg_file_size filtering',
                                               priority=1)
        subid2 = rucio_client.add_subscription(name=subscription_name + 'max_avg_file_size',
                                               account=root_account.external,
                                               filter_={'scope': [mock_scope.external, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': False, 'did_type': ['DATASET', ], 'max_avg_file_size': file_size_threshold},
                                               replication_rules=[{'rse_expression': rse2, 'copies': 1, 'activity': activity}],
                                               lifetime=None,
                                               retroactive=False,
                                               dry_run=False,
                                               comments='Test max_avg_file_size filtering',
                                               priority=1)

        # First run, the DIDs are not closed, so avg_file_size cannot be computed
        # min_avg_file_size and max_avg_file_size are ignored
        # For each DID 2 rules are generated for the 2 subscriptions
        dsn = []
        for file_size in [min_file_size, max_file_size]:
            dsn.append('%sdataset-%s' % (dsn_prefix, uuid()))
            files = [{'scope': mock_scope, 'name': did_name_generator('file'), 'bytes': file_size, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
            add_did(scope=mock_scope, name=dsn[-1], did_type=DIDType.DATASET, account=root_account)
            attach_dids(scope=mock_scope, name=dsn[-1], rse_id=rse3_id, dids=files, account=root_account)

        run(threads=1, bulk=1000000, once=True)
        rule_min_size = [rule for rule in rucio_client.list_did_rules(scope=mock_scope.external, name=dsn[0])]
        assert len(rule_min_size) == 2
        rule_max_size = [rule for rule in rucio_client.list_did_rules(scope=mock_scope.external, name=dsn[1])]
        assert len(rule_max_size) == 2

        # Now the DIDs are closed and avg_file_size is known
        # min_avg_file_size and max_avg_file_size are taken into account in the filtering
        dsn = []
        for file_size in [min_file_size, max_file_size]:
            dsn.append('%sdataset-%s' % (dsn_prefix, uuid()))
            files = [{'scope': mock_scope, 'name': did_name_generator('file'), 'bytes': file_size, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
            add_did(scope=mock_scope, name=dsn[-1], did_type=DIDType.DATASET, account=root_account)
            attach_dids(scope=mock_scope, name=dsn[-1], rse_id=rse3_id, dids=files, account=root_account)
            set_status(mock_scope, dsn[-1], open=False)

        run(threads=1, bulk=1000000, once=True)
        rule_min_size = [rule for rule in rucio_client.list_did_rules(scope=mock_scope.external, name=dsn[0])]
        assert len(rule_min_size) == 1
        assert rule_min_size[0]['subscription_id'] == str(subid2)
        rule_max_size = [rule for rule in rucio_client.list_did_rules(scope=mock_scope.external, name=dsn[1])]
        assert len(rule_max_size) == 1
        assert rule_max_size[0]['subscription_id'] == str(subid1)

    def test_run_transmogrifier_chained_subscription_exclude_site_algo(self, rse_factory, vo, rucio_client, root_account):
        """ SUBSCRIPTION (DAEMON): Test the transmogrifier with chained subscriptions and exclude_site algorithm"""
        activity = "Staging"
        tag_test = uuid()[:8]
        dict_rse = {}
        sites = [uuid() for _ in range(3)]
        for cnt in range(6):
            rse, rse_id = rse_factory.make_mock_rse()
            site = sites[cnt // 2]
            if cnt % 2:
                rse_type = 'disk'
            else:
                rse_type = 'tape'
            add_rse_attribute(rse_id=rse_id, key='tag', value=tag_test)
            add_rse_attribute(rse_id=rse_id, key=rse_type, value='True')
            add_rse_attribute(rse_id=rse_id, key=RseAttr.SITE, value=site)
            dict_rse[rse] = {'rse_id': rse_id, 'rse_type': rse_type, 'site': site}

        tmp_scope = InternalScope('mock_' + uuid()[:8], vo=vo)
        with db_session(DatabaseOperationType.WRITE) as session:
            add_scope(tmp_scope, root_account, session=session)
        subscription_name = uuid()
        dsn_prefix = did_name_generator('dataset')

        rule1 = {'rse_expression': 'tag=%s&disk=True' % tag_test,
                 'copies': 1,
                 'activity': activity}
        rule2 = {'rse_expression': 'tag=%s&tape=True' % tag_test,
                 'copies': 1,
                 'activity': activity,
                 'algorithm': 'exclude_site',
                 'chained_idx': 1,
                 'associated_site_idx': 2}

        subid = rucio_client.add_subscription(name=subscription_name,
                                              account=root_account.external,
                                              filter_={'scope': [tmp_scope.external, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': True, 'did_type': ['DATASET', ]},
                                              replication_rules=[rule1, rule2],
                                              lifetime=None,
                                              retroactive=False,
                                              dry_run=False,
                                              comments='Test exclude_site algorithm',
                                              priority=1)

        # Run a few times to check the site is always properly chosen
        for _ in range(5):
            dsn = '%sdataset-%s' % (dsn_prefix, uuid())
            add_did(scope=tmp_scope, name=dsn, did_type=DIDType.DATASET, account=root_account)
            run(threads=1, bulk=1000000, once=True)
            rules = [rule for rule in rucio_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]
            if rules[0]['source_replica_expression']:
                rules.reverse()
            print(rules, dict_rse)
            assert len(rules) == 2
            chosen_rse = rules[0]['rse_expression']
            chosen_site = dict_rse[chosen_rse]['site']
            chosen_rse_type = dict_rse[chosen_rse]['rse_type']
            assert chosen_rse_type == 'disk'

            chained_rse = rules[1]['rse_expression']
            chained_site = dict_rse[chained_rse]['site']
            chained_rse_type = dict_rse[chained_rse]['rse_type']
            assert chained_rse_type == 'tape'
            assert chained_site != chosen_site

    def test_run_transmogrifier_wildcard_copies_blocklisted_rse(self, rse_factory, vo, rucio_client, root_account):
        """ SUBSCRIPTION (DAEMON): Test the transmogrifier with wildcard copies and blocklisted RSE"""
        activity = "Staging"
        rse_attribute = uuid()[:8]
        rses = {'no_tag': [], rse_attribute: []}
        nb_rses = 5
        for cnt in range(nb_rses):
            rse, rse_id = rse_factory.make_mock_rse()
            rses['no_tag'].append(rse)
        for cnt in range(nb_rses):
            rse, rse_id = rse_factory.make_mock_rse()
            add_rse_attribute(rse_id=rse_id, key=rse_attribute, value=True)
            rses[rse_attribute].append(rse)
            if cnt in [0, 1]:
                update_rse(rse_id, {'availability_write': False})
        rse_expression = rse_attribute
        tmp_scope = InternalScope('mock_' + uuid()[:8], vo=vo)
        with db_session(DatabaseOperationType.WRITE) as session:
            add_scope(tmp_scope, root_account, session=session)

        # Check with split rule
        subscription_name = uuid()
        dsn_prefix = did_name_generator('dataset')
        dsn = '%sdataset-%s' % (dsn_prefix, uuid())

        add_did(scope=tmp_scope, name=dsn, did_type=DIDType.DATASET, account=root_account)
        rule = {'rse_expression': rse_expression,
                'copies': '*',
                'activity': activity}

        subid = rucio_client.add_subscription(name=subscription_name,
                                              account=root_account.external,
                                              filter_={'scope': [tmp_scope.external, ], 'pattern': '%s.*' % dsn_prefix, 'split_rule': True, 'did_type': ['DATASET', ]},
                                              replication_rules=[rule],
                                              lifetime=None,
                                              retroactive=False,
                                              dry_run=False,
                                              comments='Ni ! Ni!',
                                              priority=1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in rucio_client.list_did_rules(scope=tmp_scope.external, name=dsn) if str(rule['subscription_id']) == str(subid)]

        assert len(rules) == nb_rses - 2
