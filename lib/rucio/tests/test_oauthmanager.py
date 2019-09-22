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
from time import sleep
import datetime

from nose.tools import assert_true

from rucio.db.sqla.session import get_session
from rucio.db.sqla import models
from rucio.api.account import add_account, del_account
from rucio.common.types import InternalAccount
from rucio.common.exception import Duplicate

from oic import rndstr

from rucio.daemons.oauthmanager.oauthmanager import run, stop


def save_oauth_session_params(accountstring, lifetime=10):
    session = get_session()
    user_session_state = rndstr()
    user_session_nonce = rndstr()
    expired_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=lifetime)
    oauth_session_params = models.OAuthRequest(account=InternalAccount(accountstring),
                                               state=user_session_state,
                                               nonce=user_session_nonce,
                                               expired_at=expired_at)
    oauth_session_params.save(session=session)
    session.commit()
    session.expunge(oauth_session_params)
    return None


def save_oidc_token(accountstring, lifetime_access=10, lifetime_refresh=10):
    session = get_session()
    user_test_token = rndstr()
    user_test_identity = rndstr()
    expired_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=lifetime_access)
    refresh_expired_at = None
    refresh_token = None
    if lifetime_refresh > 0:
        refresh_expired_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=lifetime_refresh)
        refresh_token = 'refresh_' + user_test_token,

    new_token = models.Token(account=InternalAccount(accountstring),
                             token=user_test_token,
                             refresh_token=refresh_token,
                             scope='scope_test',
                             refresh=False,
                             expired_at=expired_at,
                             refresh_expired_at=refresh_expired_at,
                             identity=user_test_identity)
    new_token.save(session=session)
    session.commit()
    session.expunge(new_token)
    return None


def get_oauth_session_param_count(accountstring):
    session = get_session()
    result = session.query(models.OAuthRequest.state).filter_by(account=InternalAccount(accountstring)).all()
    return len(result)


def get_token_count(accountstring):
    session = get_session()
    result = session.query(models.Token.token).filter_by(account=InternalAccount(accountstring)).all()
    return len(result)


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

        # create 6 tokens that expire in 5 min and 4 that expire 'now'
        # while 2 of the latter have still valid refresh token
        save_oidc_token(self.accountstring, 300, 10)
        save_oidc_token(self.accountstring, 300, 0)
        save_oidc_token(self.accountstring, 0, 300)
        save_oidc_token(self.accountstring, 0, 0)
        save_oidc_token(self.accountstring, 300, 600)
        assert_true(get_oauth_session_param_count(self.accountstring) == 5)
        assert_true(get_token_count(self.accountstring) == 5)
        sleep(1)

    def test_oauthmanager(self):

        """ OAuth Manager: Testing deletion of expired tokens and OAuth session parameters from the DB

            setUp function (above) is supposed to run first
            (nose does this automatically):

            - inserts several tokens and OAuth session parameters in the DB

            Runs the Test:

            - running oauthmanager

            End:

            - checks that only the expired session parameters and expired tokens (without or with expired refresh token) were deleted

        """

        # Run replica recoverer once
        try:
            run(once=True, maxrows=100)
        except KeyboardInterrupt:
            stop()

        # Checking the outcome
        assert_true(get_oauth_session_param_count(self.accountstring) == 2)
        assert_true(get_token_count(self.accountstring) == 4)
        del_account(self.accountstring, 'root')
