# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2014
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014

from django.shortcuts import render_to_response

from rucio import version
from rucio.api import authentication, identity
from rucio.common.exception import IdentityError


def __to_js(var, value):
    """
    Encapsulates django variable into a javascript var.

    :param var: The name of the javascript var.
    :param value: The value to set.
    """

    return '<script type="text/javascript">var %s = "%s";</script>' % (var, value)


def index(request):
    """ index.html """

    token = None
    js_token = None
    js_account = None
    accounts = None
    rucio_ui_version = version.version_string()

    if request.is_secure():
        renv = request.environ
        # try to get and check the rucio session token from cookie
        session_token = request.COOKIES.get('x-rucio-auth-token')
        validate_token = authentication.validate_auth_token(session_token)

        # if there is no session token or if invalid: get a new one.
        if validate_token is None:
            # get all accounts for an identity. Needed for account switcher in UI.
            accounts = identity.list_accounts_for_identity(renv['SSL_CLIENT_S_DN'], 'x509')
            try:
                try:
                    # try to get the default account for the identity.
                    def_account = identity.get_default_account(renv['SSL_CLIENT_S_DN'], 'x509')
                except IdentityError:
                    # if there is no default account used the first from the list off accounts.
                    def_account = accounts[0]

                token = authentication.get_auth_token_x509(def_account,
                                                           renv['SSL_CLIENT_S_DN'],
                                                           'webui',
                                                           renv['REMOTE_ADDR'])
            except:
                return render_to_response('problem.html', locals())

            # write the token and account to javascript variables, that will be used in the HTML templates.
            js_token = __to_js('token', token)
            js_account = __to_js('account', def_account)
        else:
            js_token = __to_js('token', session_token)
            js_account = __to_js('account', validate_token['account'])
            accounts = identity.list_accounts_for_identity(session_token.split('-')[1], 'x509')

    else:
        return render_to_response('problem.html', locals())

    response = render_to_response('index.html', locals())
    # if there was no valid session token write the new token to a cookie.
    if session_token is None:
        response.set_cookie('x-rucio-auth-token', value=token, max_age=3600)

    return response
