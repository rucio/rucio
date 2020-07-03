#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2020
# - Ruturaj Gujar, <ruturaj.gujar23@gmail.com>, 2019
# - Jaroslav Guenther, <jaroslav.guenther@cern.ch>, 2019-2020
# - Eli Chadwick, <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
#
# PY3K COMPATIBLE
#
# TO-DO !!! Remove passing data with account and other params to the functions
# catch these from the webpy input() storage object
# will allow to remove also lines around each use of select_account_name

import re
import sys
from json import dumps, load
from os.path import dirname, join
from time import time
from web import cookies, ctx, input, setcookie, template, seeother

from rucio import version
from rucio.api import authentication as auth, identity
from rucio.api.account import get_account_info, list_account_attributes
from rucio.common.config import config_get
from rucio.db.sqla.constants import AccountType


if sys.version_info > (3, 0):
    long = int
    unicode = str

escapefunc = None
try:
    import html
    escapefunc = html.escape
except ImportError:
    import cgi
    escapefunc = cgi.escape


try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    SAML_SUPPORT = True
except:
    SAML_SUPPORT = False

RENDERER = template.render(join(dirname(__file__), '../templates'))
# check if there is preferred server side config for webui authentication
AUTH_TYPE = config_get('webui', 'auth_type', False, None)
if AUTH_TYPE == 'oidc':
    try:
        AUTH_ISSUER_WEBUI = config_get('webui', 'auth_issuer')
    except:
        RENDERER.problem("Please specify auth_issuer in the [webui] section of the Rucio configuration.")

# if no specific config on the server side - we collect information
# about all authentication options, in particular OIDC
AUTH_ISSUERS = []
if not AUTH_TYPE:
    IDPSECRETS = config_get('oidc', 'idpsecrets', False, None)
    try:
        with open(IDPSECRETS) as client_secret_file:
            client_secrets = load(client_secret_file)
            for iss in client_secrets:
                AUTH_ISSUERS.append(iss.upper())
    except:
        AUTH_ISSUERS = []


# excluded characters for injected JavaScript variables
VARIABLE_VALUE_REGEX = re.compile(r"^[\w\- /=,.+*#()\[\]]*$", re.UNICODE)


def html_escape(s, quote=True):
    return escapefunc(s, quote)


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


def set_cookies(cookie_dict):
    """
    Sets multiple cookies at once.
    :param cookie_dict: dictionary {'coookie_1_name': value, ... }
    :returns: None
    """
    for cookie_key in cookie_dict:
        if cookie_dict[cookie_key]:
            setcookie(cookie_key, value=cookie_dict[cookie_key], path='/')
    return None


def redirect_to_last_known_url():
    """
    Checks if there is preferred path in cookie and redirects to it.
    :returns: redirect to last known path
    """
    path = cookies().get('rucio-requested-path')
    if not path:
        path = '/'
    return seeother(path)


def __to_js(var, value):
    """
    Encapsulates python variable into a javascript var.
    :param var: The name of the javascript var.
    :param value: The value to set.
    """
    value = value.replace('\n', ' ')  # replace newlines for pattern matching on the whole string
    if not VARIABLE_VALUE_REGEX.match(value):
        # ensure nothing is injected
        value = ''
    return '<script type="text/javascript">var %s = "%s";</script>' % (var, value)


def select_account_name(identitystr, identity_type):
    """
    Looks for account corresponding to the provided identity.
    :param identitystr: identity string
    :param identity_type: identity_type e.g. x509, saml, oidc, userpass
    :returns: None or account string
    """
    accounts = identity.list_accounts_for_identity(identitystr, identity_type)
    ui_account = None
    if len(accounts) == 0:
        return None
    # check if ui_account param is set
    if 'ui_account' in input():
        ui_account = input()['ui_account']
    # if yes check if the accounts provided for users identity include this account
    if not ui_account and 'account' in input():
        ui_account = input()['account']
    if ui_account:
        if ui_account not in accounts:
            return None
        else:
            return ui_account
    else:
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
        ui_account = def_account
    return ui_account


def get_token(token_method, acc=None, vo=None, idt=None, pwd=None):
    """
    Gets a token with the token_method provided.
    :param token_method: the method to get the token
    :param acc: Rucio account string
    :param idt: Rucio identity string
    :param pwd: Rucio password string (in case of userpass auth_type)
    :returns: None or token string
    """
    if not acc:
        acc = ctx.env.get('HTTP_X_RUCIO_ACCOUNT')
    if not vo:
        vo = ctx.env.get('HTTP_X_RUCIO_VO', 'def')
    if not idt:
        idt = ctx.env.get('SSL_CLIENT_S_DN')
        if not idt.startswith('/'):
            idt = '/%s' % '/'.join(idt.split(',')[::-1])
    if not (acc and vo and idt):
        return None
    try:
        if pwd:
            token = token_method(acc, idt, pwd, 'webui', ctx.env.get('REMOTE_ADDR'), vo=vo).token
        else:
            token = token_method(acc, idt, 'webui', ctx.env.get('REMOTE_ADDR'), vo=vo).token
        return token
    except:
        return None


def validate_webui_token(from_cookie=True, session_token=None):
    """
    Validates token and returns token validation dictionary.
    :param from_cookie: Token is looked up in cookies if True, otherwise session_token must be provided
    :param session_token:  token string
    :returns: None or token validation dictionary
    """
    if from_cookie:
        session_token = cookies().get('x-rucio-auth-token')
    valid_token_dict = auth.validate_auth_token(session_token)
    if not valid_token_dict or not session_token:
        return None
    else:
        valid_token_dict['token'] = session_token
        return valid_token_dict


def access_granted(valid_token_dict, rendered_tpl=None):
    """
    Assuming validated token dictionary is provided, renders required template page.
    :param valid_token_dict: token validation dictionary
    :param rendered_tpl:  rendered template
    :returns: rendered base temmplate with rendered_tpl content
    """
    js_account = __to_js('account', valid_token_dict['account'])
    js_token = __to_js('token', valid_token_dict['token'])
    rucio_ui_version = version.version_string()
    policy = config_get('policy', 'permission')
    return RENDERER.base(js_token, js_account, rucio_ui_version, policy, rendered_tpl)


def finalize_auth(token, identity_type, cookie_dict_extra=None):
    """
    Finalises login. Validates provided token, sets cookies
    and redirects to the final page.
    :param token: token string
    :param identity_type:  identity_type e.g. x509, userpass, oidc, saml
    :param cookie_dict_extra: extra cookies to set, dictionary expected
    :returns: redirects to the final page or renders a page with an error message.
    """
    valid_token_dict = validate_webui_token(from_cookie=False, session_token=token)
    if not valid_token_dict:
        return RENDERER.problem("It was not possible to validate and finalize your login with the provided token.")
    try:
        attribs = list_account_attributes(valid_token_dict['account'])
        accounts = identity.list_accounts_for_identity(valid_token_dict['identity'], identity_type)
        accvalues = ""
        for acc in accounts:
            accvalues += acc + " "
        accounts = accvalues[:-1]

        cookie_dict = {'x-rucio-auth-token': token,
                       'x-rucio-auth-type': identity_type,
                       'rucio-auth-token-created-at': long(time()),
                       'rucio-available-accounts': accounts,
                       'rucio-account-attr': dumps(attribs),
                       'rucio-selected-account': valid_token_dict['account']}
        if cookie_dict_extra and isinstance(cookie_dict_extra, dict):
            cookie_dict.update(cookie_dict_extra)
        set_cookies(cookie_dict)
        return redirect_to_last_known_url()
    except:
        return RENDERER.problem("It was not possible to validate and finalize your login with the provided token.")


# AUTH_TYPE SPECIFIC METHODS FOLLOW:


def x509token_auth(data=None):
    """
    Manages login via X509 certificate.
    :param data: data object containing account string can be provided
    :returns: final page or a page with an error message
    """
    # checking if Rucio auth server succeeded to verify the certificate
    if ctx.env.get('SSL_CLIENT_VERIFY') != 'SUCCESS':
        return RENDERER.problem("No certificate provided. Please authenticate with a certificate registered in Rucio.")
    dn = ctx.env.get('SSL_CLIENT_S_DN')
    if not dn.startswith('/'):
        dn = '/%s' % '/'.join(dn.split(',')[::-1])
    if hasattr(data, 'account') and data.account:
        ui_account = data.account
    else:
        ui_account = select_account_name(dn, 'x509')
    msg = "<br><br>Your certificate (%s) is not mapped to (possibly any) rucio account: %s." % (html_escape(dn), html_escape(ui_account))
    msg += "<br><br><font color=\"red\">First, please make sure it is correctly registered in <a href=\"https://voms2.cern.ch:8443/voms/atlas\">VOMS</a> and be patient until it has been fully propagated through the system.</font>"
    msg += "<br><br>Then, if it is still not working please contact <a href=\"mailto:atlas-adc-ddm-support@cern.ch\">DDM Support</a>."
    if not ui_account:
        return RENDERER.problem(msg)
    token = get_token(auth.get_auth_token_x509, acc=ui_account, idt=dn)
    if not token:
        return RENDERER.problem(msg)
    return finalize_auth(token, 'x509')


def userpass_auth(data, rendered_tpl):
    """
    Manages login via Rucio USERPASS method.
    :param data: data object containing account, username and password string
    :param rendered_tpl: rendered page template
    :returns: final page or a page with an error message
    """
    if not data:
        return RENDERER.problem("No input credentials were provided.")
    else:
        # if user tries to access a page through URL without logging in, then redirect to login page.
        if rendered_tpl:
            return RENDERER.login(None)
        if hasattr(data, 'account') and data.account:
            ui_account = data.account
        else:
            ui_account = select_account_name(data.username, 'userpass')
        if not ui_account:
            return RENDERER.problem(('Cannot get find any account associated with %s identity.' % (html_escape(data.username))))
        token = get_token(auth.get_auth_token_user_pass, acc=ui_account, idt=data.username, pwd=data.password.encode("ascii"))
        if not token:
            return RENDERER.problem(('Cannot get auth token. It is possible that the presented identity %s is not mapped to any Rucio account %s.') % (html_escape(data.username), html_escape(ui_account)))
    return finalize_auth(token, 'userpass')


def saml_auth(method, data=None):
    """
    Login with SAML
    :param method: method type, GET or POST
    :param data: data object containing account string can be provided
    :param rendered_tpl: page to be rendered
    :returns: rendered final page or a page with error message
    """
    SAML_PATH = join(dirname(__file__), 'saml/')
    req = prepare_webpy_request(ctx.env, dict(input()))
    samlauth = OneLogin_Saml2_Auth(req, custom_base_path=SAML_PATH)
    saml_user_data = cookies().get('saml-user-data')
    ui_account = None
    if hasattr(data, 'account') and data.account:
        ui_account = data.account
    if method == "GET":
        # If user data is not present, redirect to IdP for authentication
        if not saml_user_data:
            return seeother(samlauth.login())
        # If user data is present but token is not valid, create a new one
        saml_nameid = cookies().get('saml-nameid')
        if not ui_account:
            ui_account = select_account_name(saml_nameid, 'saml')
        if not ui_account:
            return RENDERER.problem('Cannot get find any account associated with %s identity.' % (html_escape(saml_nameid)))
        token = get_token(auth.get_auth_token_saml, acc=ui_account, idt=saml_nameid)
        if not token:
            return RENDERER.problem(('Cannot get auth token. It is possible that the presented identity %s is not mapped to any Rucio account %s.') % (html_escape(saml_nameid), html_escape(ui_account)))
        return finalize_auth(token, 'saml')

    # If method is POST, check the received SAML response and redirect to home if valid
    samlauth.process_response()
    errors = samlauth.get_errors()
    if not errors:
        if samlauth.is_authenticated():
            saml_nameid = samlauth.get_nameid()
            cookie_extra = {'saml-nameid': saml_nameid}
            cookie_extra['saml-user-data'] = samlauth.get_attributes()
            cookie_extra['saml-session-index'] = samlauth.get_session_index()
            # WHY THIS ATTEMPTS TO GET A NEW TOKEN ?
            # WE SHOULD HAVE IT/GET IT FROM COOKIE OR DB AND JUST REDIRECT, NO ?
            if not ui_account:
                ui_account = select_account_name(saml_nameid, 'saml')
            if not ui_account:
                return RENDERER.problem('Cannot get find any account associated with %s identity.' % (html_escape(saml_nameid)))
            token = get_token(auth.get_auth_token_saml, acc=ui_account, idt=saml_nameid)
            if not token:
                return RENDERER.problem(('Cannot get auth token. It is possible that the presented identity %s is not mapped to any Rucio account %s.') % (html_escape(saml_nameid), html_escape(ui_account)))
            return finalize_auth(token, 'saml', cookie_extra)

        return RENDERER.problem("Not authenticated")

    return RENDERER.problem("Error while processing SAML")


def oidc_auth(account, issuer):
    """
    Open ID Connect Login
    :param account: Rucio account string
    :param issuer: issuer key (e.g. xdc, wlcg) as in the idpsecrets.json file
    :returns: rendered final page or a page with error message
    """

    if not account:
        account = 'webui'
    if not issuer:
        return RENDERER.problem("Please provide IdP issuer.")
    kwargs = {'audience': None,
              'auth_scope': None,
              'issuer': issuer.lower(),
              'auto': True,
              'polling': False,
              'refresh_lifetime': None,
              'ip': None,
              'webhome': ctx.realhome + '/oidc_final'}
    auth_url = auth.get_auth_oidc(account, **kwargs)
    if not auth_url:
        return RENDERER.problem("It was not possible to get the OIDC authentication url from the Rucio auth server. "
                                + "In case you provided your account name, make sure it is known to Rucio.")   # NOQA: W503
    return seeother(auth_url)


def authenticate(rendered_tpl):
    """
    Authentication management method.
    :param rendered_tpl: rendered page template
    :returns: rendered final page or a page with error message
    """
    global AUTH_ISSUERS, SAML_SUPPORT, AUTH_TYPE, RENDERER
    valid_token_dict = validate_webui_token()
    if not valid_token_dict:
        # remember fullpath in cookie to return to after login
        setcookie('rucio-requested-path', value=unicode(ctx.fullpath), expires=120, path='/')
    else:
        return access_granted(valid_token_dict, rendered_tpl)

    # login without any known server config
    if not AUTH_TYPE:
        return RENDERER.select_login_method(AUTH_ISSUERS, SAML_SUPPORT)
    # for AUTH_TYPE predefined by the server continue
    else:
        if AUTH_TYPE == 'userpass':
            return seeother('/login')
        elif AUTH_TYPE == 'x509':
            return x509token_auth(None)
        elif AUTH_TYPE == 'x509_userpass':
            if ctx.env.get('SSL_CLIENT_VERIFY') == 'SUCCESS':
                return x509token_auth(None)
            return RENDERER.no_certificate()
        elif AUTH_TYPE == 'oidc':
            return oidc_auth(None, AUTH_ISSUER_WEBUI)
        elif AUTH_TYPE == 'saml':
            return saml_auth("GET", rendered_tpl)
        return RENDERER.problem('Invalid auth type')
