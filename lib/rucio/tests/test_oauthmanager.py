# -*- coding: utf-8 -*-
# Copyright 2019-2021 CERN
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
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019-2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Simon Fayer <simon.fayer05@imperial.ac.uk>, 2021

import datetime
import json
import unittest
from time import sleep
from unittest.mock import MagicMock, patch

import pytest
from oic import rndstr
from sqlalchemy import and_, or_
from sqlalchemy.sql.expression import true

from rucio.api.account import add_account, del_account
from rucio.common.config import config_get_bool
from rucio.common.exception import Duplicate
from rucio.common.types import InternalAccount
from rucio.daemons.oauthmanager.oauthmanager import run, stop
from rucio.db.sqla import models
from rucio.db.sqla.session import get_session
from rucio.tests.common_server import get_vo

new_token_dict = {'access_token': '',
                  'expires_in': 3599,
                  'id_token': '',
                  'refresh_token': '',
                  'scope': 'openid offline_access',
                  'token_type': 'Bearer',
                  'audience': 'rucio'}


def save_oauth_session_params(account, lifetime=10, redirect_msg=None, created_at=None):
    session = get_session()
    user_session_state = rndstr()
    user_session_nonce = rndstr()
    expired_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=lifetime)
    oauth_session_params = models.OAuthRequest(account=account,
                                               state=user_session_state,
                                               nonce=user_session_nonce,
                                               expired_at=expired_at,
                                               redirect_msg=redirect_msg,
                                               created_at=created_at)
    oauth_session_params.save(session=session)
    session.commit()  # pylint: disable=no-member
    session.expunge(oauth_session_params)  # pylint: disable=no-member
    return None


def save_oidc_token(account, lifetime_access=0, lifetime_refresh=0, refresh_token=None, refresh=False, final_state=None):
    session = get_session()
    expired_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=lifetime_access)
    refresh_expired_at = None
    if lifetime_refresh > 0:
        refresh_expired_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=lifetime_refresh)
    if lifetime_refresh == 0 and refresh_token:
        refresh_expired_at = datetime.datetime.utcnow()

    new_token = models.Token(account=account,
                             token=rndstr(),
                             refresh_token=refresh_token,
                             refresh=refresh,
                             oidc_scope=json.dumps({'state': final_state}),
                             expired_at=expired_at,
                             refresh_expired_at=refresh_expired_at,
                             identity="SUB=myid, ISS=mockiss")
    new_token.save(session=session)
    session.commit()  # pylint: disable=no-member
    session.expunge(new_token)  # pylint: disable=no-member
    return None


def get_oauth_session_param_count(account):
    session = get_session()
    result = session.query(models.OAuthRequest).filter_by(account=account).all()  # pylint: disable=no-member
    return len(result)


def get_token_count(account):
    session = get_session()
    result = session.query(models.Token).filter_by(account=account).all()  # pylint: disable=no-member
    for token in result:
        print(token.token, token.expired_at, token.refresh_token, token.refresh_expired_at, token.oidc_scope)
    return len(result)


def get_token_count_with_refresh_true(account):
    session = get_session()
    result = session.query(models.Token.token).filter_by(account=account, refresh=true()).all()  # pylint: disable=no-member
    return len(result)


def check_deleted_tokens(account):
    session = get_session()
    result = session.query(models.Token).filter_by(account=account).all()  # pylint: disable=no-member
    all_deleted = True
    for elem in result:
        if elem.refresh_token is not None:
            if elem.refresh_token not in str(elem.oidc_scope):
                if 'deleted' in str(elem.oidc_scope):
                    all_deleted = False
    return all_deleted


def count_kept_tokens(account):
    session = get_session()
    result = session.query(models.Token).filter_by(account=account).all()  # pylint: disable=no-member
    count = 0
    for elem in result:
        if elem.refresh_token is not None:
            if elem.refresh_token not in str(elem.oidc_scope):
                if 'to_be_kept' in str(elem.oidc_scope):
                    count += 1
        else:
            if 'to_be_kept' in str(elem.oidc_scope):
                count += 1
    return count


def count_expired_tokens(account):
    session = get_session()
    result = session.query(models.Token).filter(and_(models.Token.account == account,  # pylint: disable=no-member
                                                     models.Token.expired_at <= datetime.datetime.utcnow()))\
                                        .all()
    count = len(result)
    return count


def count_refresh_tokens_expired_or_none(account):
    session = get_session()
    result = session.query(models.Token).filter(and_(models.Token.account == account))\
                                        .filter(or_(models.Token.refresh_expired_at.__eq__(None), models.Token.refresh_expired_at <= datetime.datetime.utcnow()))\
                                        .all()  # pylint: disable=no-member

    count = len(result)
    return count


def new_tokens_ok(account):
    session = get_session()
    result = session.query(models.Token).filter_by(account=account, refresh=true()).all()  # pylint: disable=no-member
    token_names_expected = ["10_original_refreshed_and_deleted",
                            "11_to_be_kept_and_refreshed",
                            "14_original_refreshed_and_deleted",
                            "17_to_be_kept_and_refreshed"]
    selection = []
    for elem in result:
        if elem.refresh_token is not None:
            if elem.refresh_token in str(elem.oidc_scope):
                selection.append(elem.refresh_token)
    return all(item in token_names_expected for item in selection)


class MockClientOIDC(MagicMock):

    @classmethod
    def do_access_token_refresh(self, state=None):
        new_token_dict['access_token'] = rndstr()
        new_token_dict['refresh_token'] = state
        return new_token_dict


def side_effect(token_object, token_type):
    return {'client': MockClientOIDC(), 'state': token_object.refresh_token}


@pytest.mark.dirty
class TestOAuthManager(unittest.TestCase):

    def setUp(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': get_vo()}
        else:
            self.vo = {}

        self.accountstring = 'test_' + rndstr()
        self.accountstring = self.accountstring.lower()
        self.account = InternalAccount(self.accountstring, **self.vo)
        try:
            add_account(self.accountstring, 'USER', 'rucio@email.com', 'root', **self.vo)
        except Duplicate:
            pass
        # create 2 sessions that expire in 5 min and 3 that expire 'now'
        save_oauth_session_params(self.account, 300)
        save_oauth_session_params(self.account, 300)
        save_oauth_session_params(self.account, 0)
        save_oauth_session_params(self.account, 0)
        save_oauth_session_params(self.account, 0)

        assert get_oauth_session_param_count(self.account) == 5

        # assuming daemon looprate of 10 min
        # test cases for access tokens without any refresh token
        save_oidc_token(self.account, 0, 0, None, False, '0_to_be_deleted')
        save_oidc_token(self.account, 300, 0, None, False, '00_to_be_kept')
        save_oidc_token(self.account, 1000, 0, None, False, '000_to_be_kept')

        # test cases for access token with refresh token
        save_oidc_token(self.account, 0, 300, "1_at_inval_rt_val_refresh_False_" + rndstr(), False, "1_to_be_kept_no_refresh")
        save_oidc_token(self.account, 300, 300, "2_at_val_rt_val_refresh_False_" + rndstr(), False, "2_to_be_kept_no_refresh")
        save_oidc_token(self.account, 0, 0, "3_at_inval_rt_inval_refresh_False_" + rndstr(), False, "3_to_be_deleted")
        save_oidc_token(self.account, 300, 0, "4_at_val_rt_inval_refresh_False_" + rndstr(), False, "4_to_be_kept_no_refresh")
        save_oidc_token(self.account, 0, 1000, "5_at_inval_rt_longval_refresh_False_" + rndstr(), False, "5_to_be_kept_no_refresh")
        save_oidc_token(self.account, 1000, 1000, "6_at_longval_rt_longval_refresh_False_" + rndstr(), False, "6_to_be_kept_no_refresh")
        save_oidc_token(self.account, 1000, 0, "7_at_longval_rt_inval_refresh_False_" + rndstr(), False, "7_to_be_kept_no_refresh")
        save_oidc_token(self.account, 300, 1000, "8_at_val_rt_longval_refresh_False_" + rndstr(), False, "8_to_be_kept_no_refresh")
        save_oidc_token(self.account, 1000, 300, "9_at_longval_rt_val_refresh_False_" + rndstr(), False, "9_to_be_kept_no_refresh")

        save_oidc_token(self.account, 0, 300, "10_at_inval_rt_val_refresh_True_" + rndstr(), True, "10_original_refreshed_and_deleted")
        save_oidc_token(self.account, 300, 300, "11_at_val_rt_val_refresh_True_" + rndstr(), True, "11_to_be_kept_and_refreshed")
        save_oidc_token(self.account, 0, 0, "12_at_inval_rt_inval_refresh_True_" + rndstr(), True, "12_to_be_deleted")
        save_oidc_token(self.account, 300, 0, "13_at_val_rt_inval_refresh_True_" + rndstr(), True, "13_to_be_kept_no_refresh")
        save_oidc_token(self.account, 0, 1000, "14_at_inval_rt_longval_refresh_True_" + rndstr(), True, "14_original_refreshed_and_deleted")
        save_oidc_token(self.account, 1000, 1000, "15_at_longval_rt_longval_refresh_True_" + rndstr(), True, "15_to_be_kept_no_refresh")
        save_oidc_token(self.account, 1000, 0, "16_at_longval_rt_inval_refresh_True_" + rndstr(), True, "16_to_be_kept_no_refresh")
        save_oidc_token(self.account, 300, 1000, "17_at_val_rt_longval_refresh_True_" + rndstr(), True, "17_to_be_kept_and_refreshed")
        save_oidc_token(self.account, 1000, 300, "18_at_longval_rt_val_refresh_True_" + rndstr(), True, "18_to_be_kept_no_refresh")

        assert get_token_count(self.account) == 21

        sleep(1)

    @patch('rucio.core.oidc.__get_init_oidc_client')
    def test_oauthmanager(self, mock_oidc_client):

        """ OAuth Manager: Testing deletion of expired tokens, session parameters and refresh of access tokens.
            Assumes that the OAuth manager first runs token refresh and only then
            attempts to delete expired tokens and session parameters.

            setUp function (above) is supposed to run first
            (nose does this automatically):

            - inserts several tokens and OAuth session parameters in the DB

            Runs the Test:

            - running oauthmanager

            End:

            - checks that only the expired session parameters
              and expired tokens (without or with expired refresh token) were deleted
            - checks if only the expected tokens were refreshed
        """
        mock_oidc_client.side_effect = side_effect

        # Run replica recoverer once
        try:
            run(once=True, max_rows=100, loop_rate=600)
        except KeyboardInterrupt:
            stop()

        # Checking the outcome
        assert get_oauth_session_param_count(self.account) == 2
        assert get_token_count(self.account) == 20
        assert check_deleted_tokens(self.account) is True
        assert count_kept_tokens(self.account) == 16
        assert get_token_count_with_refresh_true(self.account) == 8
        assert new_tokens_ok(self.account) is True
        assert count_expired_tokens(self.account) == 2
        assert count_refresh_tokens_expired_or_none(self.account) == 8
        # = 6 from the original setup + 2 original ones that were set expired after refresh
        del_account(self.accountstring, 'root', **self.vo)
