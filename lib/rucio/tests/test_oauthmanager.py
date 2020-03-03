# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Jaroslav Guenther, <jaroslav.guenther@cern.ch>, 2019

from __future__ import print_function

import datetime
import json
from time import sleep

from mock import MagicMock, patch
from nose.tools import assert_true
from oic import rndstr
from rucio.api.account import add_account, del_account
from rucio.common.exception import Duplicate
from rucio.common.types import InternalAccount
from rucio.daemons.oauthmanager.oauthmanager import run, stop
from rucio.db.sqla import models
from rucio.db.sqla.session import get_session
from sqlalchemy import and_, or_
from sqlalchemy.sql.expression import true

new_token_dict = {'access_token': '',
                  'expires_in': 3599,
                  'id_token': '',
                  'refresh_token': '',
                  'scope': 'openid offline_access',
                  'token_type': 'Bearer',
                  'audience': 'rucio'}


def save_oauth_session_params(accountstring, lifetime=10, redirect_msg=None, created_at=None):
    session = get_session()
    user_session_state = rndstr()
    user_session_nonce = rndstr()
    expired_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=lifetime)
    oauth_session_params = models.OAuthRequest(account=InternalAccount(accountstring),
                                               state=user_session_state,
                                               nonce=user_session_nonce,
                                               expired_at=expired_at,
                                               redirect_msg=redirect_msg,
                                               created_at=created_at)
    oauth_session_params.save(session=session)
    session.commit()  # pylint: disable=no-member
    session.expunge(oauth_session_params)  # pylint: disable=no-member
    return None


def save_oidc_token(accountstring, lifetime_access=0, lifetime_refresh=0, refresh_token=None, refresh=False, final_state=None):
    session = get_session()
    expired_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=lifetime_access)
    refresh_expired_at = None
    if lifetime_refresh > 0:
        refresh_expired_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=lifetime_refresh)
    if lifetime_refresh == 0 and refresh_token:
        refresh_expired_at = datetime.datetime.utcnow()

    new_token = models.Token(account=InternalAccount(accountstring),
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


def get_oauth_session_param_count(accountstring):
    session = get_session()
    result = session.query(models.OAuthRequest).filter_by(account=InternalAccount(accountstring)).all()  # pylint: disable=no-member
    return len(result)


def get_token_count(accountstring):
    session = get_session()
    result = session.query(models.Token).filter_by(account=InternalAccount(accountstring)).all()  # pylint: disable=no-member
    for token in result:
        print(token.token, token.expired_at, token.refresh_token, token.refresh_expired_at, token.oidc_scope)
    return len(result)


def get_token_count_with_refresh_true(accountstring):
    session = get_session()
    result = session.query(models.Token.token).filter_by(account=InternalAccount(accountstring), refresh=true()).all()  # pylint: disable=no-member
    return len(result)


def check_deleted_tokens(accountstring):
    session = get_session()
    result = session.query(models.Token).filter_by(account=InternalAccount(accountstring)).all()  # pylint: disable=no-member
    all_deleted = True
    for elem in result:
        if elem.refresh_token is not None:
            if elem.refresh_token not in str(elem.oidc_scope):
                if 'deleted' in str(elem.oidc_scope):
                    all_deleted = False
    return all_deleted


def count_kept_tokens(accountstring):
    session = get_session()
    result = session.query(models.Token).filter_by(account=InternalAccount(accountstring)).all()  # pylint: disable=no-member
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


def count_expired_tokens(accountstring):
    session = get_session()
    result = session.query(models.Token).filter(and_(models.Token.account == InternalAccount(accountstring),  # pylint: disable=no-member
                                                     models.Token.expired_at <= datetime.datetime.utcnow()))\
                                        .all()
    count = len(result)
    return count


def count_refresh_tokens_expired_or_none(accountstring):
    session = get_session()
    result = session.query(models.Token).filter(and_(models.Token.account == InternalAccount(accountstring)))\
                                        .filter(or_(models.Token.refresh_expired_at.__eq__(None), models.Token.refresh_expired_at <= datetime.datetime.utcnow()))\
                                        .all()  # pylint: disable=no-member

    count = len(result)
    return count


def new_tokens_ok(accountstring):
    session = get_session()
    result = session.query(models.Token).filter_by(account=InternalAccount(accountstring), refresh=true()).all()  # pylint: disable=no-member
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


class TestOAuthManager():

    def setUp(self):

        self.accountstring = 'test_' + rndstr()
        self.accountstring = self.accountstring.lower()
        try:
            add_account(self.accountstring, 'USER', 'rucio@email.com', 'root')
        except Duplicate:
            pass
        # create 2 sessions that expire in 5 min and 3 that expire 'now'
        save_oauth_session_params(self.accountstring, 300)
        save_oauth_session_params(self.accountstring, 300)
        save_oauth_session_params(self.accountstring, 0)
        save_oauth_session_params(self.accountstring, 0)
        save_oauth_session_params(self.accountstring, 0)

        assert_true(get_oauth_session_param_count(self.accountstring) == 5)

        # assuming daemon looprate of 10 min
        # test cases for access tokens without any refresh token
        save_oidc_token(self.accountstring, 0, 0, None, False, '0_to_be_deleted')
        save_oidc_token(self.accountstring, 300, 0, None, False, '00_to_be_kept')
        save_oidc_token(self.accountstring, 1000, 0, None, False, '000_to_be_kept')

        # test cases for access token with refresh token
        save_oidc_token(self.accountstring, 0, 300, "1_at_inval_rt_val_refresh_False_" + rndstr(), False, "1_to_be_kept_no_refresh")
        save_oidc_token(self.accountstring, 300, 300, "2_at_val_rt_val_refresh_False_" + rndstr(), False, "2_to_be_kept_no_refresh")
        save_oidc_token(self.accountstring, 0, 0, "3_at_inval_rt_inval_refresh_False_" + rndstr(), False, "3_to_be_deleted")
        save_oidc_token(self.accountstring, 300, 0, "4_at_val_rt_inval_refresh_False_" + rndstr(), False, "4_to_be_kept_no_refresh")
        save_oidc_token(self.accountstring, 0, 1000, "5_at_inval_rt_longval_refresh_False_" + rndstr(), False, "5_to_be_kept_no_refresh")
        save_oidc_token(self.accountstring, 1000, 1000, "6_at_longval_rt_longval_refresh_False_" + rndstr(), False, "6_to_be_kept_no_refresh")
        save_oidc_token(self.accountstring, 1000, 0, "7_at_longval_rt_inval_refresh_False_" + rndstr(), False, "7_to_be_kept_no_refresh")
        save_oidc_token(self.accountstring, 300, 1000, "8_at_val_rt_longval_refresh_False_" + rndstr(), False, "8_to_be_kept_no_refresh")
        save_oidc_token(self.accountstring, 1000, 300, "9_at_longval_rt_val_refresh_False_" + rndstr(), False, "9_to_be_kept_no_refresh")

        save_oidc_token(self.accountstring, 0, 300, "10_at_inval_rt_val_refresh_True_" + rndstr(), True, "10_original_refreshed_and_deleted")
        save_oidc_token(self.accountstring, 300, 300, "11_at_val_rt_val_refresh_True_" + rndstr(), True, "11_to_be_kept_and_refreshed")
        save_oidc_token(self.accountstring, 0, 0, "12_at_inval_rt_inval_refresh_True_" + rndstr(), True, "12_to_be_deleted")
        save_oidc_token(self.accountstring, 300, 0, "13_at_val_rt_inval_refresh_True_" + rndstr(), True, "13_to_be_kept_no_refresh")
        save_oidc_token(self.accountstring, 0, 1000, "14_at_inval_rt_longval_refresh_True_" + rndstr(), True, "14_original_refreshed_and_deleted")
        save_oidc_token(self.accountstring, 1000, 1000, "15_at_longval_rt_longval_refresh_True_" + rndstr(), True, "15_to_be_kept_no_refresh")
        save_oidc_token(self.accountstring, 1000, 0, "16_at_longval_rt_inval_refresh_True_" + rndstr(), True, "16_to_be_kept_no_refresh")
        save_oidc_token(self.accountstring, 300, 1000, "17_at_val_rt_longval_refresh_True_" + rndstr(), True, "17_to_be_kept_and_refreshed")
        save_oidc_token(self.accountstring, 1000, 300, "18_at_longval_rt_val_refresh_True_" + rndstr(), True, "18_to_be_kept_no_refresh")

        assert_true(get_token_count(self.accountstring) == 21)

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
        assert_true(get_oauth_session_param_count(self.accountstring) == 2)
        assert_true(get_token_count(self.accountstring) == 20)
        assert_true(check_deleted_tokens(self.accountstring) is True)
        assert_true(count_kept_tokens(self.accountstring) == 16)
        assert_true(get_token_count_with_refresh_true(self.accountstring) == 8)
        assert_true(new_tokens_ok(self.accountstring) is True)
        assert_true(count_expired_tokens(self.accountstring) == 2)
        assert_true(count_refresh_tokens_expired_or_none(self.accountstring) == 8)
        # = 6 from the original setup + 2 original ones that were set expired after refresh
        del_account(self.accountstring, 'root')
