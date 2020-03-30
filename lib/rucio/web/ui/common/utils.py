#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2019
# - Ruturaj Gujar, <ruturaj.gujar23@gmail.com>, 2019
# - Jaroslav Guenther, <jaroslav.guenther@cern.ch>, 2019

from json import dumps
from os.path import dirname, join
from time import time
from web import cookies, ctx, input, setcookie, template, seeother

from rucio import version
from rucio.api import authentication, identity
from rucio.api.account import get_account_info, list_account_attributes
from rucio.common.config import config_get
from rucio.db.sqla.constants import AccountType

try:
    AUTH_TYPE = config_get('webui', 'auth_type')
    if AUTH_TYPE == 'saml':
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
except:
    AUTH_TYPE = 'x509'

try:
    AUTH_ISSUER = config_get('webui', 'auth_issuer')
except:
    if AUTH_TYPE == 'oidc':
        render = template.render(join(dirname(__file__), '../templates'))
        render.problem("Please specify auth_issuer in the [webui] section of the Rucio configuration.")
    AUTH_ISSUER = None


def prepare_webpy_request(request, data):
    """
    Prepare a webpy request for SAML
    :param request: webpy request object
    :param data: GET or POST data
    """
    if request['wsgi.url_scheme'] == 'https':
        return {
            'https': 'on' if request['wsgi.url_scheme'] == 'https' else 'off',
            'http_host': request['HTTP_HOST'],
            'server_port': request['SERVER_PORT'],
            'script_name': request['SCRIPT_NAME'],
            'get_data': data,
            # Uncomment if using ADFS as IdP
            # 'lowercase_urlencoding': True,
            'post_data': data
        }

    return None


def set_cookies(token, cookie_accounts, attribs, ui_account=None):
    # if there was no valid session token write the new token to a cookie.
    if token:
        setcookie('x-rucio-auth-token', value=token, path='/')
        setcookie('rucio-auth-token-created-at', value=long(time()), path='/')

    if cookie_accounts:
        values = ""
        for acc in cookie_accounts:
            values += acc + " "
        setcookie('rucio-available-accounts', value=values[:-1], path='/')

    if attribs:
        setcookie('rucio-account-attr', value=dumps(attribs), path='/')

    if ui_account:
        setcookie('rucio-selected-account', value=ui_account, path='/')


def __to_js(var, value):
    """
    Encapsulates python variable into a javascript var.
    :param var: The name of the javascript var.
    :param value: The value to set.
    """

    return '<script type="text/javascript">var %s = "%s";</script>' % (var, value)

    return join(dirname(file), 'templates/')


def get_token():
    account = ctx.env.get('HTTP_X_RUCIO_ACCOUNT')
    dn = ctx.env.get('SSL_CLIENT_S_DN')
    try:
        token = authentication.get_auth_token_x509(account,
                                                   dn,
                                                   'webui',
                                                   ctx.env.get('REMOTE_ADDR')).token
        return token
    except:
        return False


def check_token(rendered_tpl):
    attribs = None
    token = None
    js_token = ""
    js_account = ""
    def_account = None
    accounts = None
    cookie_accounts = None
    rucio_ui_version = version.version_string()
    policy = config_get('policy', 'permission')

    ui_account = None
    if 'ui_account' in input():
        ui_account = input()['ui_account']

    render = template.render(join(dirname(__file__), '../templates'))
    if ctx.env.get('SSL_CLIENT_VERIFY') != 'SUCCESS':
        return render.problem("No certificate provided. Please authenticate with a certificate registered in Rucio.")

    dn = ctx.env.get('SSL_CLIENT_S_DN')

    if not dn.startswith('/'):
        dn = '/%s' % '/'.join(dn.split(',')[::-1])

    msg = "Your certificate (%s) is not mapped to any rucio account." % dn
    msg += "<br><br><font color=\"red\">First, please make sure it is correctly registered in <a href=\"https://voms2.cern.ch:8443/voms/atlas\">VOMS</a> and be patient until it has been fully propagated through the system.</font>"
    msg += "<br><br>Then, if it is still not working please contact <a href=\"mailto:atlas-adc-ddm-support@cern.ch\">DDM Support</a>."

    # try to get and check the rucio session token from cookie
    session_token = cookies().get('x-rucio-auth-token')
    validate_token = authentication.validate_auth_token(session_token)

    # check if ui_account param is set and if yes, force new token
    if ui_account:
        accounts = identity.list_accounts_for_identity(dn, 'x509')

        if len(accounts) == 0:
            return render.problem(msg)

        if ui_account not in accounts:
            return render.problem("The rucio account (%s) you selected is not mapped to your certificate (%s). Please select another account or none at all to automatically use your default account." % (ui_account, dn))

        cookie_accounts = accounts
        if (validate_token is None) or (validate_token['account'] != ui_account):
            try:
                token = authentication.get_auth_token_x509(ui_account,
                                                           dn,
                                                           'webui',
                                                           ctx.env.get('REMOTE_ADDR')).token
            except:
                return render.problem(msg)

        attribs = list_account_attributes(ui_account)
        js_token = __to_js('token', token)
        js_account = __to_js('account', def_account)
    else:
        # if there is no session token or if invalid: get a new one.
        if validate_token is None:
            # get all accounts for an identity. Needed for account switcher in UI.
            accounts = identity.list_accounts_for_identity(dn, 'x509')
            if len(accounts) == 0:
                return render.problem(msg)

            cookie_accounts = accounts

            # try to set the default account to the user account, if not available take the first account.
            def_account = accounts[0]
            for account in accounts:
                account_info = get_account_info(account)
                if account_info.account_type == AccountType.USER:
                    def_account = account
                    break

            selected_account = cookies().get('rucio-selected-account')
            if (selected_account):
                def_account = selected_account
            try:
                token = authentication.get_auth_token_x509(def_account,
                                                           dn,
                                                           'webui',
                                                           ctx.env.get('REMOTE_ADDR')).token
            except:
                return render.problem(msg)

            attribs = list_account_attributes(def_account)
            # write the token and account to javascript variables, that will be used in the HTML templates.
            js_token = __to_js('token', token)
            js_account = __to_js('account', def_account)

    set_cookies(token, cookie_accounts, attribs, ui_account)

    return render.base(js_token, js_account, rucio_ui_version, policy, rendered_tpl)


def log_in(data, rendered_tpl):
    attribs = None
    token = None
    js_token = ""
    js_account = ""
    def_account = None
    accounts = None
    cookie_accounts = None
    rucio_ui_version = version.version_string()
    policy = config_get('policy', 'permission')

    render = template.render(join(dirname(__file__), '../templates'))

    # # try to get and check the rucio session token from cookie
    session_token = cookies().get('x-rucio-auth-token')
    validate_token = authentication.validate_auth_token(session_token)

    # if token is valid, render the requested page.
    if validate_token and not data:
        token = session_token
        js_token = __to_js('token', token)
        js_account = __to_js('account', def_account)

        return render.base(js_token, js_account, rucio_ui_version, policy, rendered_tpl)

    else:
        # if there is no session token or if invalid: get a new one.
        # if user tries to access a page through URL without logging in, then redirect to login page.
        if rendered_tpl:
            return render.login()

        # get all accounts for an identity. Needed for account switcher in UI.
        accounts = identity.list_accounts_for_identity(data.username, 'userpass')
        if len(accounts) == 0:
            return render.problem('No accounts for the given identity.')

        cookie_accounts = accounts
        # try to set the default account to the user account, if not available take the first account.
        def_account = accounts[0]
        for account in accounts:
            account_info = get_account_info(account)
            if account_info.account_type == AccountType.USER:
                def_account = account
                break

        selected_account = cookies().get('rucio-selected-account')
        if (selected_account):
            def_account = selected_account

        try:
            token = authentication.get_auth_token_user_pass(def_account,
                                                            data.username,
                                                            data.password.encode("ascii"),
                                                            'webui',
                                                            ctx.env.get('REMOTE_ADDR')).token

        except:
            return render.problem('Cannot get auth token')

        attribs = list_account_attributes(def_account)
        # write the token and account to javascript variables, that will be used in the HTML templates.
        js_token = __to_js('token', token)
        js_account = __to_js('account', def_account)

    set_cookies(token, cookie_accounts, attribs)

    return seeother('/')


def saml_authentication(method, rendered_tpl):
    """
    Login with SAML
    :param method: method type, GET or POST
    :param rendered_tpl: page to be rendered
    """

    attribs = None
    token = None
    js_token = ""
    js_account = ""
    def_account = None
    accounts = None
    cookie_accounts = None
    rucio_ui_version = version.version_string()
    policy = config_get('policy', 'permission')

    # Initialize variables for sending SAML request
    SAML_PATH = join(dirname(__file__), 'saml/')
    request = ctx.env
    data = dict(input())
    req = prepare_webpy_request(request, data)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=SAML_PATH)

    saml_user_data = cookies().get('saml-user-data')

    render = template.render(join(dirname(__file__), '../templates'))

    session_token = cookies().get('x-rucio-auth-token')
    validate_token = authentication.validate_auth_token(session_token)

    if method == "GET":
        # If user data is not present, redirect to IdP for authentication
        if not saml_user_data:
            return seeother(auth.login())

        # If user data is present and token is valid, render the required page
        elif validate_token:
            js_token = __to_js('token', session_token)
            js_account = __to_js('account', def_account)

            return render.base(js_token, js_account, rucio_ui_version, policy, rendered_tpl)

        # If user data is present but token is not valid, create a new one
        saml_nameid = cookies().get('saml-nameid')
        accounts = identity.list_accounts_for_identity(saml_nameid, 'saml')

        cookie_accounts = accounts
        try:
            token = authentication.get_auth_token_saml(def_account,
                                                       saml_nameid,
                                                       'webui',
                                                       ctx.env.get('REMOTE_ADDR')).token

        except:
            return render.problem('Cannot get auth token')

        attribs = list_account_attributes(def_account)
        # write the token and account to javascript variables, that will be used in the HTML templates.
        js_token = __to_js('token', token)
        js_account = __to_js('account', def_account)

        set_cookies(token, cookie_accounts, attribs)

        return render.base(js_token, js_account, rucio_ui_version, policy, rendered_tpl)

    # If method is POST, check the received SAML response and redirect to home if valid
    auth.process_response()
    errors = auth.get_errors()
    if not errors:
        if auth.is_authenticated():
            setcookie('saml-user-data', value=auth.get_attributes(), path='/')
            setcookie('saml-session-index', value=auth.get_session_index(), path='/')
            setcookie('saml-nameid', value=auth.get_nameid(), path='/')
            saml_nameid = auth.get_nameid()

            accounts = identity.list_accounts_for_identity(saml_nameid, 'saml')
            cookie_accounts = accounts
            # try to set the default account to the user account, if not available take the first account.
            def_account = accounts[0]
            for account in accounts:
                account_info = get_account_info(account)
                if account_info.account_type == AccountType.USER:
                    def_account = account
                    break

            selected_account = cookies().get('rucio-selected-account')
            if (selected_account):
                def_account = selected_account

            try:
                token = authentication.get_auth_token_saml(def_account,
                                                           saml_nameid,
                                                           'webui',
                                                           ctx.env.get('REMOTE_ADDR')).token

            except:
                return render.problem('Cannot get auth token')

            attribs = list_account_attributes(def_account)
            # write the token and account to javascript variables, that will be used in the HTML templates.
            js_token = __to_js('token', token)
            js_account = __to_js('account', def_account)

            set_cookies(token, cookie_accounts, attribs)

            return seeother("/")

        return render.problem("Not authenticated")

    return render.problem("Error while processing SAML")


def oidc(validate_token, session_token, render, rendered_tpl):
    """
    Used to finalise login once a token was put in a session cookie
    via web/rest/oidc_token endpoint.
    :param validate_token: dictionary as returned from the
                           authentication.validate_auth_token after token validation
    :param session_token: token string from the current cookie session
    :param render: template renderer object
    :param rendered_tpl: page to be rendered

    :returns: rendered web page

    """
    if not validate_token or not session_token:
        return render.problem('No valid token found.')
    try:
        js_token = __to_js('token', session_token)
        js_account = __to_js('account', validate_token['account'])
        attribs = cookies().get('rucio-account-attr')
        if not attribs:
            attribs = list_account_attributes(validate_token['account'])
        accounts = identity.list_accounts_for_identity(validate_token['identity'], 'OIDC')
        if len(accounts) == 0:
            return render.problem('No accounts for the given identity.')

        set_cookies(session_token, accounts, attribs, ui_account=validate_token['account'])
        rucio_ui_version = version.version_string()
        policy = config_get('policy', 'permission')
        return render.base(js_token, js_account, rucio_ui_version, policy, rendered_tpl)
    except:
        return render.problem('Could not finalise login with your token.')


def authenticate(rendered_tpl):
    """ Select the auth type defined in config """

    session_token = cookies().get('x-rucio-auth-token')
    validate_token = authentication.validate_auth_token(session_token)

    render = template.render(join(dirname(__file__), '../templates'))

    if AUTH_TYPE == 'x509':
        return check_token(rendered_tpl)

    elif AUTH_TYPE == 'userpass':
        if validate_token:
            return log_in(None, rendered_tpl)

        return seeother('/login')

    elif AUTH_TYPE == 'oidc':
        if not validate_token:
            kwargs = {'audience': 'rucio',
                      'auth_scope': 'openid profile',
                      'issuer': AUTH_ISSUER,
                      'auto': True,
                      'polling': False,
                      'refresh_lifetime': None,
                      'ip': None,
                      'webhome': ctx.realhome + ctx.fullpath}

            # account should be an input from the user !!! - TO-DO
            auth_url = authentication.get_auth_oidc('webui', **kwargs)
            return seeother(auth_url)

        else:
            return oidc(validate_token, session_token, render, rendered_tpl)

    elif AUTH_TYPE == 'x509_userpass':
        if ctx.env.get('SSL_CLIENT_VERIFY') == 'SUCCESS':
            return check_token(rendered_tpl)

        elif validate_token:
            return log_in(None, rendered_tpl)

        return render.no_certificate()

    elif AUTH_TYPE == 'saml':
        return saml_authentication("GET", rendered_tpl)

    return render.problem('Invalid auth type')
