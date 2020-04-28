# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2013
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2015
# - Joaquin Bogado, <joaquin.bogado@cern.ch>, 2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2015, 2017
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick, <eli.chadwick@stfc.ac.uk>, 2020
#
# PY3K COMPATIBLE

import random
import string

from nose.tools import assert_equal, assert_in, assert_not_in

from rucio.api.account import add_account, get_account_info, list_accounts
import rucio.api.account_limit as api_acc_lim
from rucio.api.scope import add_scope
from rucio.common.config import config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import api_update_return_dict, api_update_rse_expression
from rucio.core.rse import get_rse_id


class TestApiExternalRepresentation():

    @classmethod
    def setUpClass(cls):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            cls.vo = {'vo': 'tst'}
            cls.multi_vo = True
        else:
            cls.vo = {}
            cls.multi_vo = False

        # Add test account
        cls.account_name = ''.join(random.choice(string.ascii_lowercase) for x in range(10))
        add_account(account=cls.account_name, type='user', email='rucio@email.com', issuer='root', **cls.vo)
        cls.account = InternalAccount(cls.account_name, **cls.vo)

        # Add test scope
        cls.scope_name = ''.join(random.choice(string.ascii_lowercase) for x in range(10))
        add_scope(scope=cls.scope_name, account=cls.account_name, issuer='root', **cls.vo)
        cls.scope = InternalScope(cls.scope_name, **cls.vo)

        # Add test RSE
        cls.rse_name = 'MOCK'
        cls.rse_id = get_rse_id(rse=cls.rse_name, **cls.vo)
        cls.rse2_name = 'MOCK2'
        cls.rse2_id = get_rse_id(rse=cls.rse2_name, **cls.vo)

    def test_api_update_return_dict(self):
        """ API: Test the conversion of dictionaries to external representation """
        test_dict = {'rse_id': self.rse_id,
                     'account': self.account,
                     'scope': self.scope,
                     'rse_expression': 'vo=tst&(MOCK|MOCK2)'}
        out = api_update_return_dict(test_dict)
        assert_equal({'rse_id': self.rse_id, 'rse': self.rse_name, 'account': self.account_name,
                      'scope': self.scope_name, 'rse_expression': 'MOCK|MOCK2'}, out)

    def test_api_update_rse_expression(self):
        """ API: Test the removal of VO from RSE expression """
        rse_expr = 'vo=tst&(MOCK|MOCK2)'
        assert_equal('MOCK|MOCK2', api_update_rse_expression(rse_expr))
        rse_expr = 'MOCK'
        assert_equal('MOCK', api_update_rse_expression(rse_expr))
        rse_expr = 'vo=tst'
        assert_equal('', api_update_rse_expression(rse_expr))

    def test_api_account(self):
        """ ACCOUNT (API): Test conversion of account information to external representation """
        out = get_account_info(self.account_name, **self.vo)
        assert_equal(self.account_name, out['account'])

        gen = list_accounts(**self.vo)
        out = []
        for acc in gen:
            out.append(acc['account'])
        assert_in(self.account_name, out)
        if self.multi_vo:
            assert_not_in(self.account.internal, out)
        assert_not_in('@', ' '.join(out))

    def test_api_account_limit(self):
        """ ACCOUNT_LIMIT (API): Test conversion of account limit information to external representation """
        # Add mock account limits
        rse_expr = '{}|{}'.format(self.rse_name, self.rse2_name)
        api_acc_lim.set_local_account_limit(self.account_name, self.rse_name, 1000, issuer='root', **self.vo)
        api_acc_lim.set_global_account_limit(self.account_name, rse_expr, 2000, issuer='root', **self.vo)

        out = api_acc_lim.get_local_account_limits(self.account_name, **self.vo)
        assert_in(self.rse_name, out)
        assert_not_in(self.rse_id, out)

        out = api_acc_lim.get_local_account_limit(self.account_name, self.rse_name, **self.vo)
        assert_in(self.rse_name, out)
        assert_not_in(self.rse_id, out)

        out = api_acc_lim.get_global_account_limits(self.account_name, **self.vo)
        assert_in(rse_expr, out)
        if self.multi_vo:
            assert_not_in('vo={}&({})'.format(self.vo['vo'], rse_expr), out)

        out = api_acc_lim.get_global_account_limit(self.account_name, rse_expr, **self.vo)
        assert_in(rse_expr, out)
        if self.multi_vo:
            assert_not_in('vo={}&({})'.format(self.vo['vo'], rse_expr), out)

        out = api_acc_lim.get_local_account_usage(self.account_name, self.rse_name, issuer='root', **self.vo)
        for usage in out:
            if 'rse_id' in usage:
                assert_in('rse', usage)
                if usage['rse_id'] == self.rse_id:
                    assert_equal(self.rse_name, usage["rse"])

        out = api_acc_lim.get_global_account_usage(self.account_name, rse_expr, issuer='root', **self.vo)
        for usage in out:
            if 'rse_expression' in usage:
                assert_equal(rse_expr, usage['rse_expression'])
