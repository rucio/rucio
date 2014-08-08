#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014

from os.path import dirname, join
from web import template, ctx, cookies, setcookie

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

    return join(dirname(file), 'templates/')


def check_token(rendered_tpl):
    token = None
    js_token = ""
    js_account = ""
    def_account = None
    accounts = None
    cookie_accounts = None
    rucio_ui_version = version.version_string()
    dn = ctx.env.get('SSL_CLIENT_S_DN')
    render = template.render(join(dirname(__file__), '../templates'))

    # try to get and check the rucio session token from cookie
    session_token = cookies().get('x-rucio-auth-token')
    validate_token = authentication.validate_auth_token(session_token)

    # if there is no session token or if invalid: get a new one.
    if validate_token is None:
        # get all accounts for an identity. Needed for account switcher in UI.
        accounts = identity.list_accounts_for_identity(dn, 'x509')
        cookie_accounts = accounts
        try:
            try:
                # try to get the default account for the identity.
                def_account = identity.get_default_account(dn, 'x509')
            except IdentityError:
                # if there is no default account used the first from the list off accounts.
                def_account = accounts[0]

            token = authentication.get_auth_token_x509(def_account,
                                                       dn,
                                                       'webui',
                                                       ctx.env.get('REMOTE_ADDR'))
        except:
            return render.problem(ctx.env)

        # write the token and account to javascript variables, that will be used in the HTML templates.
        js_token = __to_js('token', token)
        js_account = __to_js('account', def_account)

    # if there was no valid session token write the new token to a cookie.
    if token:
        setcookie('x-rucio-auth-token', value=token, expires=3600, path='/')

    if cookie_accounts:
        values = ""
        for acc in cookie_accounts:
            values += acc + " "
        setcookie('rucio-available-accounts', value=values[:-1], path='/')

    return render.base(js_token, js_account, rucio_ui_version, rendered_tpl)
