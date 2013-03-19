# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013

from json import dumps, loads

from nose.tools import assert_equal, assert_true, raises
from paste.fixture import TestApp

from rucio.api.subscription import list_subscriptions, add_subscription, update_subscription
from rucio.client.subscriptionclient import SubscriptionClient
from rucio.common.exception import SubscriptionNotFound, SubscriptionDuplicate
from rucio.common.utils import generate_uuid as uuid
from rucio.web.rest.authentication import app as auth_app
from rucio.web.rest.subscription import app as subs_app


class TestSubscriptionCoreApi():

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_create_and_update_and_list_subscription(self):
        """ SUBSCRIPTION (API): Test the creation of a new subscription, update it, list it """
        subscription_name = uuid()
        result = add_subscription(name=subscription_name, account='root', filter="{'project': ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV'], 'datatype': ['AOD',], 'excluded_pattern': \
        '(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).*\.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)',\
        'account':'tier0'}", replication_rules="[(2, 'T1_DATATAPE', True, True), (1, 'T1_DATADISK', False, True)]", lifetime=100000, retroactive=0, dry_run=0, subscription_policy='tier0')
        assert_equal(result, None)
        result = update_subscription(name=subscription_name, account='root', filter='toto')
        assert_equal(result, None)
        result = list_subscriptions(name=subscription_name, account='root')
        sub = []
        for r in result:
            sub.append(r)
        assert_equal(len(sub), 1)
        assert_equal(sub[0]['filter'], 'toto')

    @raises(SubscriptionDuplicate)
    def test_create_existing_subscription(self):
        """ SUBSCRIPTION (API): Test the creation of a existing subscription """
        subscription_name = uuid()
        result = add_subscription(name=subscription_name, account='root', filter="{'project': ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV'], 'datatype': ['AOD',], 'excluded_pattern': \
        '(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).*\.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)',\
        'account':'tier0'}", replication_rules="[(2, 'T1_DATATAPE', True, True), (1, 'T1_DATADISK', False, True)]", lifetime=100000, retroactive=0, dry_run=0, subscription_policy='tier0')
        assert_equal(result, None)
        result = add_subscription(name=subscription_name, account='root', filter="{'project': ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV'], 'datatype': ['AOD',], 'excluded_pattern': \
        '(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).*\.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)',\
        'account':'tier0'}", replication_rules="[(2, 'T1_DATATAPE', True, True), (1, 'T1_DATADISK', False, True)]", lifetime=100000, retroactive=0, dry_run=0, subscription_policy='tier0')

    @raises(SubscriptionNotFound)
    def test_update_nonexisting_subscription(self):
        """ SUBSCRIPTION (API): Test the update of a non-existing subscription """
        subscription_name = uuid()
        update_subscription(name=subscription_name, account='root', filter='toto')


class TestSubscriptionRestApi():

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def test_create_and_update_and_list_subscription(self):
        """ SUBSCRIPTION (REST): Test the creation of a new subscription, update it, list it """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('X-Rucio-Auth-Token'))

        subscription_name = uuid()
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'name': subscription_name, 'filter': "{'project': ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV'], 'datatype': ['AOD',], 'excluded_pattern': \
        '(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).*\.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)',\
        'account': 'tier0'}", 'replication_rules': "[(2, 'T1_DATATAPE', True, True), (1, 'T1_DATADISK', False, True)]", 'lifetime': 100000, 'retroactive': 0, 'dry_run': 0, 'subscription_policy': 'tier0'})
        r2 = TestApp(subs_app.wsgifunc(*mw)).post('/%s' % (subscription_name), headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        #data = dumps({'name': subscription_name, 'filter': "toto"})
        data = dumps({'filter': "toto"})
        r3 = TestApp(subs_app.wsgifunc(*mw)).put('/%s' % (subscription_name), headers=headers2, params=data, expect_errors=True)
        assert_equal(r3.status, 201)

        r4 = TestApp(subs_app.wsgifunc(*mw)).get('/root/%s' % (subscription_name), headers=headers2, expect_errors=True)
        print r4
        print type(loads(r4.body))
        assert_equal(r4.status, 200)
        assert_equal(loads(r4.body)['filter'], 'toto')

    def test_create_existing_subscription(self):
        """ SUBSCRIPTION (REST): Test the creation of a existing subscription """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('X-Rucio-Auth-Token'))

        subscription_name = uuid()
        headers2 = {'X-Rucio-Auth-Token': str(token)}
        data = dumps({'name': subscription_name, 'filter': "{'project': ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV'], 'datatype': ['AOD',], 'excluded_pattern': \
        '(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).*\.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)',\
        'account': 'tier0'}", 'replication_rules': "[(2, 'T1_DATATAPE', True, True), (1, 'T1_DATADISK', False, True)]", 'lifetime': 100000, 'retroactive': 0, 'dry_run': 0, 'subscription_policy': 'tier0'})
        r2 = TestApp(subs_app.wsgifunc(*mw)).post('/subscriptions' + subscription_name, headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.status, 201)

        r3 = TestApp(subs_app.wsgifunc(*mw)).post('/subscriptions' + subscription_name, headers=headers2, params=data, expect_errors=True)
        assert_equal(r3.header('ExceptionClass'), 'SubscriptionDuplicate')
        assert_equal(r3.status, 409)

    def test_update_nonexisting_subscription(self):
        """ SUBSCRIPTION (REST): Test the update of a non-existing subscription """
        mw = []

        headers1 = {'X-Rucio-Account': 'root', 'X-Rucio-Username': 'ddmlab', 'X-Rucio-Password': 'secret'}
        r1 = TestApp(auth_app.wsgifunc(*mw)).get('/userpass', headers=headers1, expect_errors=True)

        assert_equal(r1.status, 200)
        token = str(r1.header('X-Rucio-Auth-Token'))

        subscription_name = uuid()
        headers2 = {'X-Rucio-Auth-Token': str(token)}

        data = dumps({'name': subscription_name, 'filter': 'toto'})
        r2 = TestApp(subs_app.wsgifunc(*mw)).put('/subscriptions' + subscription_name, headers=headers2, params=data, expect_errors=True)
        assert_equal(r2.header('ExceptionClass'), 'SubscriptionNotFound')
        assert_equal(r2.status, 404)


class TestSubscriptionClient():

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.client = SubscriptionClient()

    def test_create_and_update_and_list_subscription(self):
        """ SUBSCRIPTION (CLIENT): Test the creation of a new subscription, update it, list it """
        subscription_name = uuid()
        result = self.client.add_subscription(name=subscription_name, filter="{'project': ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV'], 'datatype': ['AOD',], 'excluded_pattern': \
        '(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).*\.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)',\
        'account':'tier0'}", replication_rules="[(2, 'T1_DATATAPE', True, True), (1, 'T1_DATADISK', False, True)]", lifetime=100000, retroactive=0, dry_run=0, subscription_policy='tier0')
        assert_true(result)
        result = self.client.update_subscription(name=subscription_name, filter='toto')
        assert_true(result)
        result = self.client.list_subscriptions(name=subscription_name, account='root')
        sub = []
        for r in result:
            sub.append(r)
        assert_equal(len(sub), 1)
        assert_equal(sub[0]['filter'], 'toto')

    @raises(SubscriptionDuplicate)
    def test_create_existing_subscription(self):
        """ SUBSCRIPTION (CLIENT): Test the creation of a existing subscription """
        subscription_name = uuid()
        result = self.client.add_subscription(name=subscription_name, filter="{'project': ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV'], 'datatype': ['AOD',], 'excluded_pattern': \
        '(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).*\.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)',\
        'account':'tier0'}", replication_rules="[(2, 'T1_DATATAPE', True, True), (1, 'T1_DATADISK', False, True)]", lifetime=100000, retroactive=0, dry_run=0, subscription_policy='tier0')
        assert_true(result)
        result = self.client.add_subscription(name=subscription_name, filter="{'project': ['data12_900GeV', 'data12_8TeV', 'data13_900GeV', 'data13_8TeV'], 'datatype': ['AOD',], 'excluded_pattern': \
        '(_tid|physics_(Muons|JetTauEtmiss|Egamma)\..*\.ESD|express_express(?!.*NTUP|.*\.ESD|.*RAW)|(physics|express)(?!.*NTUP).*\.x|physics_WarmStart|calibration(?!_PixelBeam.merge.(NTUP_IDVTXLUMI|AOD))|merge.HIST|NTUP_MUONCALIB|NTUP_TRIG)',\
        'account':'tier0'}", replication_rules="[(2, 'T1_DATATAPE', True, True), (1, 'T1_DATADISK', False, True)]", lifetime=100000, retroactive=0, dry_run=0, subscription_policy='tier0')

    @raises(SubscriptionNotFound)
    def test_update_nonexisting_subscription(self):
        """ SUBSCRIPTION (CLIENT): Test the update of a non-existing subscription """
        subscription_name = uuid()
        self.client.update_subscription(name=subscription_name, filter='toto')
