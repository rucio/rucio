# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2015, 2017
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014
# - Martin Barisits, <martin.barisits@cern.ch>, 2015-2016

from json import dumps, loads

from nose.tools import assert_equal, assert_true, raises, assert_raises
from paste.fixture import TestApp

from rucio.api.subscription import list_subscriptions, add_subscription, update_subscription, list_subscription_rule_states, get_subscription_by_id
from rucio.client.subscriptionclient import SubscriptionClient
from rucio.client.didclient import DIDClient
from rucio.common.exception import InvalidObject, SubscriptionNotFound, SubscriptionDuplicate
from rucio.common.utils import generate_uuid as uuid
from rucio.core.account_limit import set_account_limit
from rucio.core.did import add_did, set_new_dids
from rucio.core.rse import add_rse, get_rse_id
from rucio.core.rule import add_rule
from rucio.core.scope import add_scope
from rucio.daemons.transmogrifier import run
from rucio.db.sqla.constants import DIDType
from rucio.web.rest.authentication import APP as auth_app
from rucio.web.rest.subscription import APP as subs_app


class TestSubscriptionCoreApi():

    @classmethod
    def setUpClass(cls):
        cls.projects = ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV']
        cls.pattern1 = r'(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).* \
                        \.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)'

    @classmethod
    def tearDownClass(cls):
        pass

    def test_create_and_update_and_list_subscription(self):
        """ SUBSCRIPTION (API): Test the creation of a new subscription, update it, list it """
        subscription_name = uuid()
        with assert_raises(InvalidObject):
            result = add_subscription(name=subscription_name, account='root', filter={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                      replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'noactivity'}], lifetime=100000, retroactive=0, dry_run=0, comments='This is a comment', issuer='root')

        result = add_subscription(name=subscription_name, account='root', filter={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                  replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}], lifetime=100000, retroactive=0, dry_run=0, comments='This is a comment', issuer='root')
        with assert_raises(TypeError):
            result = update_subscription(name=subscription_name, account='root', filter='toto', issuer='root')
        with assert_raises(InvalidObject):
            result = update_subscription(name=subscription_name, account='root', filter={'project': 'toto'}, issuer='root')
        result = update_subscription(name=subscription_name, account='root', filter={'project': ['toto', ]}, issuer='root')
        assert_equal(result, None)
        result = list_subscriptions(name=subscription_name, account='root')
        sub = []
        for res in result:
            sub.append(res)
        assert_equal(len(sub), 1)
        assert_equal(loads(sub[0]['filter'])['project'][0], 'toto')

    def test_create_list_subscription_by_id(self):
        """ SUBSCRIPTION (API): Test the creation of a new subscription and list it by id """
        subscription_name = uuid()
        subscription_id = add_subscription(name=subscription_name, account='root', filter={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                           replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}], lifetime=100000, retroactive=0, dry_run=0, comments='This is a comment', issuer='root')
        subscription_info = get_subscription_by_id(subscription_id)
        assert_equal(loads(subscription_info['filter'])['project'], self.projects)

    @raises(SubscriptionDuplicate)
    def test_create_existing_subscription(self):
        """ SUBSCRIPTION (API): Test the creation of a existing subscription """
        subscription_name = uuid()
        add_subscription(name=subscription_name, account='root', filter={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                         replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}], lifetime=100000, retroactive=0, dry_run=0, comments='This is a comment', issuer='root')
        add_subscription(name=subscription_name, account='root', filter={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                         replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}], lifetime=100000, retroactive=0, dry_run=0, comments='This is a comment', issuer='root')

    @raises(SubscriptionNotFound)
    def test_update_nonexisting_subscription(self):
        """ SUBSCRIPTION (API): Test the update of a non-existing subscription """
        subscription_name = uuid()
        update_subscription(name=subscription_name, account='root', filter={'project': ['toto', ]}, issuer='root')

    def test_list_rules_states(self):
        """ SUBSCRIPTION (API): Test listing of rule states for subscription """
        tmp_scope = 'mock_' + uuid()[:8]
        add_scope(tmp_scope, 'root')
        site_a = 'RSE%s' % uuid().upper()
        site_b = 'RSE%s' % uuid().upper()

        add_rse(site_a)
        add_rse(site_b)

        # Add quota
        set_account_limit('root', get_rse_id(site_a), -1)
        set_account_limit('root', get_rse_id(site_b), -1)

        # add a new dataset
        dsn = 'dataset-%s' % uuid()
        add_did(scope=tmp_scope, name=dsn,
                type=DIDType.DATASET, account='root')

        subscription_name = uuid()
        subid = add_subscription(name=subscription_name, account='root', filter={'account': ['root', ], 'scope': [tmp_scope, ]},
                                 replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}], lifetime=100000, retroactive=0, dry_run=0, comments='This is a comment', issuer='root')

        # Add two rules
        add_rule(dids=[{'scope': tmp_scope, 'name': dsn}], account='root', copies=1, rse_expression=site_a, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=subid)
        add_rule(dids=[{'scope': tmp_scope, 'name': dsn}], account='root', copies=1, rse_expression=site_b, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=subid)

        for rule in list_subscription_rule_states(account='root', name=subscription_name):
            assert_equal(rule[3], 2)


class TestSubscriptionRestApi():

    @classmethod
    def setUpClass(cls):
        cls.projects = ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV']
        cls.pattern1 = r'(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).* \
                         \.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)'

    @classmethod
    def tearDownClass(cls):
        pass

    def test_create_and_update_and_list_subscription(self):
        """ SUBSCRIPTION (REST): Test the creation of a new subscription, update it, list it """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))

        subscription_name = uuid()
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'options': {'filter': {'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                      'replication_rules': [{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}], 'lifetime': 100000, 'retroactive': 0, 'dry_run': 0, 'comments': 'blahblah'}})
        res2 = TestApp(subs_app.wsgifunc(*mw)).post('/root/%s' % (subscription_name), headers=headers2, params=data, expect_errors=True)
        assert_equal(res2.status, 201)

        data = dumps({'options': {'filter': {'project': ['toto', ]}}})
        res3 = TestApp(subs_app.wsgifunc(*mw)).put('/root/%s' % (subscription_name), headers=headers2, params=data, expect_errors=True)
        assert_equal(res3.status, 201)

        res4 = TestApp(subs_app.wsgifunc(*mw)).get('/root/%s' % (subscription_name), headers=headers2, expect_errors=True)
        assert_equal(res4.status, 200)
        assert_equal(loads(loads(res4.body)['filter'])['project'][0], 'toto')

    def test_create_and_list_subscription_by_id(self):
        """ SUBSCRIPTION (REST): Test the creation of a new subscription and get by subscription id """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))

        subscription_name = uuid()
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'options': {'filter': {'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                      'replication_rules': [{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}], 'lifetime': 100000, 'retroactive': 0, 'dry_run': 0, 'comments': 'blahblah'}})
        res2 = TestApp(subs_app.wsgifunc(*mw)).post('/root/%s' % (subscription_name), headers=headers2, params=data, expect_errors=True)
        assert_equal(res2.status, 201)

        subscription_id = res2.body
        res3 = TestApp(subs_app.wsgifunc(*mw)).get('/Id/%s' % (subscription_id), headers=headers2, expect_errors=True)
        assert_equal(res3.status, 200)
        assert_equal(loads(loads(res3.body)['filter'])['project'][0], 'data12_900GeV')

    def test_create_existing_subscription(self):
        """ SUBSCRIPTION (REST): Test the creation of a existing subscription """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))

        subscription_name = uuid()
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'options': {'name': subscription_name, 'filter': {'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                      'replication_rules': [{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}], 'lifetime': 100000, 'retroactive': 0, 'dry_run': 0, 'comments': 'We are the knights who say Ni !'}})
        res2 = TestApp(subs_app.wsgifunc(*mw)).post('/root/' + subscription_name, headers=headers2, params=data, expect_errors=True)
        assert_equal(res2.status, 201)

        res3 = TestApp(subs_app.wsgifunc(*mw)).post('/root/' + subscription_name, headers=headers2, params=data, expect_errors=True)
        assert_equal(res3.header('ExceptionClass'), 'SubscriptionDuplicate')
        assert_equal(res3.status, 409)

    def test_update_nonexisting_subscription(self):
        """ SUBSCRIPTION (REST): Test the update of a non-existing subscription """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))

        subscription_name = uuid()
        headers2 = {'X-Rucio-Auth-Token': str(token)}

        data = dumps({'options': {'filter': {'project': ['toto', ]}}})
        res2 = TestApp(subs_app.wsgifunc(*mw)).put('/root/' + subscription_name, headers=headers2, params=data, expect_errors=True)
        assert_equal(res2.status, 404)
        assert_equal(res2.header('ExceptionClass'), 'SubscriptionNotFound')

    def test_list_rules_states(self):
        """ SUBSCRIPTION (REST): Test listing of rule states for subscription """
        tmp_scope = 'mock_' + uuid()[:8]
        add_scope(tmp_scope, 'root')
        mw = []
        site_a = 'RSE%s' % uuid().upper()
        site_b = 'RSE%s' % uuid().upper()

        add_rse(site_a)
        add_rse(site_b)

        # Add quota
        set_account_limit('root', get_rse_id(site_a), -1)
        set_account_limit('root', get_rse_id(site_b), -1)

        # add a new dataset
        dsn = 'dataset-%s' % uuid()
        add_did(scope=tmp_scope, name=dsn,
                type=DIDType.DATASET, account='root')

        subscription_name = uuid()
        subid = add_subscription(name=subscription_name, account='root', filter={'account': ['root', ], 'scope': [tmp_scope, ]},
                                 replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}], lifetime=100000, retroactive=0, dry_run=0, comments='We want a shrubbery', issuer='root')

        # Add two rules
        add_rule(dids=[{'scope': tmp_scope, 'name': dsn}], account='root', copies=1, rse_expression=site_a, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=subid)
        add_rule(dids=[{'scope': tmp_scope, 'name': dsn}], account='root', copies=1, rse_expression=site_b, grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=subid)

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        res1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(res1.status, 200)
        token = str(res1.header('X-Rucio-Auth-Token'))

        headers2 = {'X-Rucio-Auth-Token': str(token)}
        res2 = TestApp(subs_app.wsgifunc(*mw)).get('/%s/%s/Rules/States' % ('root', subscription_name), headers=headers2, expect_errors=True)

        for line in res2.body.split('\n'):
            print line
            rs = loads(line)
            if rs[1] == subscription_name:
                break
        assert_equal(rs[3], 2)


class TestSubscriptionClient():

    @classmethod
    def setUpClass(cls):
        cls.sub_client = SubscriptionClient()
        cls.did_client = DIDClient()
        cls.projects = ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV']
        cls.pattern1 = r'(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).* \
                         \.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)'

    @classmethod
    def tearDownClass(cls):
        pass

    def test_create_and_update_and_list_subscription(self):
        """ SUBSCRIPTION (CLIENT): Test the creation of a new subscription, update it, list it """
        subscription_name = uuid()
        with assert_raises(InvalidObject):
            subid = self.sub_client.add_subscription(name=subscription_name, account='root', filter={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                                     replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'noactivity'}], lifetime=100000, retroactive=0, dry_run=0, comments='Ni ! Ni!')
        subid = self.sub_client.add_subscription(name=subscription_name, account='root', filter={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                                 replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}], lifetime=100000, retroactive=0, dry_run=0, comments='Ni ! Ni!')
        result = [sub['id'] for sub in list_subscriptions(name=subscription_name, account='root')]
        assert_equal(subid, result[0])
        with assert_raises(TypeError):
            result = self.sub_client.update_subscription(name=subscription_name, account='root', filter='toto')
        result = self.sub_client.update_subscription(name=subscription_name, account='root', filter={'project': ['toto', ]})
        assert_true(result)
        result = list_subscriptions(name=subscription_name, account='root')
        sub = []
        for res in result:
            sub.append(res)
        assert_equal(len(sub), 1)
        assert_equal(loads(sub[0]['filter'])['project'][0], 'toto')

    @raises(SubscriptionDuplicate)
    def test_create_existing_subscription(self):
        """ SUBSCRIPTION (CLIENT): Test the creation of a existing subscription """
        subscription_name = uuid()
        result = self.sub_client.add_subscription(name=subscription_name, account='root', filter={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                                  replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}], lifetime=100000, retroactive=0, dry_run=0, comments='Ni ! Ni!')
        assert_true(result)
        result = self.sub_client.add_subscription(name=subscription_name, account='root', filter={'project': self.projects, 'datatype': ['AOD', ], 'excluded_pattern': self.pattern1, 'account': ['tier0', ]},
                                                  replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK|MOCK2', 'copies': 2, 'activity': 'Data Brokering'}], lifetime=100000, retroactive=0, dry_run=0, comments='Ni ! Ni!')

    @raises(SubscriptionNotFound)
    def test_update_nonexisting_subscription(self):
        """ SUBSCRIPTION (CLIENT): Test the update of a non-existing subscription """
        subscription_name = uuid()
        self.sub_client.update_subscription(name=subscription_name, filter={'project': ['toto', ]})

    def test_run_transmogrifier(self):
        """ SUBSCRIPTION (DAEMON): Test the transmogrifier and the split_rule mode """
        tmp_scope = 'mock_' + uuid()[:8]
        add_scope(tmp_scope, 'root')
        subscription_name = uuid()
        dsn = 'dataset-%s' % uuid()
        add_did(scope=tmp_scope, name=dsn, type=DIDType.DATASET, account='root')

        subid = self.sub_client.add_subscription(name=subscription_name, account='root', filter={'scope': [tmp_scope, ], 'pattern': 'dataset-.*', 'split_rule': True},
                                                 replication_rules=[{'lifetime': 86400, 'rse_expression': 'MOCK-POSIX|MOCK2|MOCK3', 'copies': 2, 'activity': 'Data Brokering'}],
                                                 lifetime=None, retroactive=0, dry_run=0, comments='Ni ! Ni!', priority=1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in self.did_client.list_did_rules(scope=tmp_scope, name=dsn) if str(rule['subscription_id']) == str(subid)]
        assert_equal(len(rules), 2)
        set_new_dids([{'scope': tmp_scope, 'name': dsn}, ], 1)
        run(threads=1, bulk=1000000, once=True)
        rules = [rule for rule in self.did_client.list_did_rules(scope=tmp_scope, name=dsn) if str(rule['subscription_id']) == str(subid)]
        assert_equal(len(rules), 2)
