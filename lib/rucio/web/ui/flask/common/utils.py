#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

import html
import re
from json import dumps, load
from os.path import dirname, join
from time import time
from urllib.parse import quote, unquote

from flask import request, render_template, redirect, make_response

from rucio.api import authentication as auth, identity
from rucio.api.account import account_exists, get_account_info, list_account_attributes
from rucio.common.config import config_get, config_get_bool
from rucio.common.exception import CannotAuthenticate
from rucio.common.extra import import_extras
from rucio.core import identity as identity_core, vo as vo_core
from rucio.db.sqla.constants import AccountType, IdentityType

EXTRA_MODULES = import_extras(['onelogin'])

if EXTRA_MODULES['onelogin']:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth  # pylint: disable=import-error

    SAML_SUPPORT = True
else:
    SAML_SUPPORT = False

# check if there is preferred server side config for webui authentication
AUTH_TYPE = config_get('webui', 'auth_type', False, None)
if AUTH_TYPE == 'oidc':
    try:
        AUTH_ISSUER_WEBUI = config_get('webui', 'auth_issuer')
    except:
        render_template("problem.html", msg="Please specify auth_issuer in the [webui] section of the Rucio configuration.")

# if no specific config on the server side - we collect information
# about all authentication options, in particular OIDC
AUTH_ISSUERS = []
if not AUTH_TYPE:
    IDPSECRETS = config_get('oidc', 'idpsecrets', False, None)
    try:
        if IDPSECRETS:
            with open(IDPSECRETS) as client_secret_file:
                client_secrets = load(client_secret_file)
                for iss in client_secrets:
                    AUTH_ISSUERS.append(iss.upper())
    except:
        AUTH_ISSUERS = []

MULTI_VO = config_get_bool('common', 'multi_vo', raise_exception=False, default=False)

# Additional error message that can have VO specific information for the user, e.g., support mailing list.
ADDITIONAL_ERROR_MSG = config_get("webui", "additional_error_msg", raise_exception=False, default="")

# excluded characters for injected JavaScript variables
VARIABLE_VALUE_REGEX = re.compile(r"^[\w\- /=,.+*#()\[\]]*$", re.UNICODE)

# TO-DO !!! Remove passing data with account and other params to the functions
# catch these from the webpy input() storage object
# will allow to remove also lines around each use of select_account_name


def prepare_saml_request(environ, data):
    """
    TODO: Validate for Flask
    Prepare a webpy request for SAML
    :param environ: Flask request.environ object
    :param data: GET or POST data
    """
    if environ.get('mod_wsgi.url_scheme') == 'https':
        ret = {
            'https': 'on' if environ.get('modwsgi.url_scheme') == 'https' else 'off',
            'http_host': environ.get('HTTP_HOST'),
            'server_port': environ.get('SERVER_PORT'),
            'script_name': environ.get('SCRIPT_NAME'),
            # Uncomment if using ADFS as IdP
            # 'lowercase_urlencoding': True,
        }
        if data:
            ret['get_data'] = data
            ret['post_data'] = data
        return ret

    return None


def add_cookies(response, cookie={}):
    for int_cookie in cookie:
        response.set_cookie(**int_cookie)

    return response


def redirect_to_last_known_url(cookie):
    """
    Checks if there is preferred path in cookie and redirects to it.
    :returns: redirect to last known path
    """
    requested_path = request.cookies.get('rucio-requested-path')
    if not requested_path:
        requested_path = request.environ.get('REQUEST_URI')
    resp = add_cookies(make_response(redirect(requested_path, code=303)), cookie)

    return resp


def select_account_name(identitystr, identity_type, vo=None):
    """
    Looks for account (and VO if not known) corresponding to the provided identity.
    :param identitystr: identity string
    :param identity_type: identity_type e.g. x509, saml, oidc, userpass
    :returns: Tuple of None or account string, None or VO string or list of VO strings
    """
    ui_account = None
    if not MULTI_VO:
        vo = 'def'
    if vo is not None:
        accounts = identity.list_accounts_for_identity(identitystr, identity_type)
    else:
        internal_accounts = identity_core.list_accounts_for_identity(identitystr, IdentityType[identity_type])
        accounts = [account.external for account in internal_accounts]
        vos = [account.vo for account in internal_accounts]
        if vos:
            vos = list(set(vos))
            # If we only have 1 VO that matches the identity use that, otherwise return all possible VOs so the user can choose
            if len(vos) == 1:
                vo = vos[0]
            else:
                return None, vos

    if len(accounts) == 0:
        return None, vo
    # check if ui_account param is set
    ui_account = request.args.get('ui_account', default=None)
    # if yes check if the accounts provided for users identity include this account
    if not ui_account:
        ui_account = request.args.get('account', default=None)
    if ui_account:
        if ui_account not in accounts:
            return None, vo
        else:
            return ui_account, vo
    else:
        # try to set the default account to the user account, if not available take the first account.
        def_account = accounts[0]
        for account in accounts:
            account_info = get_account_info(account, vo=vo)
            if account_info.account_type == AccountType.USER:
                def_account = account
                break
        selected_account = request.cookies.get('rucio-selected-account')
        if (selected_account):
            def_account = selected_account
        ui_account = def_account
    return ui_account, vo


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
        acc = request.environ.get('HTTP_X_RUCIO_ACCOUNT')
    if not vo:
        vo = request.environ.get('HTTP_X_RUCIO_VO')
    if not idt:
        idt = request.environ.get('SSL_CLIENT_S_DN')
    if not (acc and vo and idt):
        return None
    try:
        if pwd:
            token = token_method(acc, idt, pwd, 'webui', request.environ.get('REMOTE_ADDR'), vo=vo).get('token')
        else:
            token = token_method(acc, idt, 'webui', request.environ.get('REMOTE_ADDR'), vo=vo).get('token')
        return token
    except:
        return None


def validate_webui_token(from_cookie=True, session_token=None):
    """
    Validates token and returns token validation dictionary.
    :param from_cookie: Token is looked up in cookies if True, otherwise session_token must be provided
    :param session_token:  token string
    :returns: token validation dictionary
    :raises: CannotAuthenticate
    """
    if from_cookie:
        session_token = request.cookies.get('x-rucio-auth-token')
    if session_token:
        session_token = unquote(session_token)
    valid_token_dict = auth.validate_auth_token(session_token)
    valid_token_dict['token'] = session_token  # pylint: disable=E1137
    return valid_token_dict


def access_granted(valid_token_dict, template, title):
    """
    Assuming validated token dictionary is provided, renders required template page.
    :param valid_token_dict: token validation dictionary
    :param template: the template name that should be rendered
    :returns: rendered base temmplate with template content
    """
    policy = config_get('policy', 'permission')
    return render_template(template, token=valid_token_dict['token'], account=valid_token_dict['account'], vo=valid_token_dict['vo'], policy=policy, title=title)


def finalize_auth(token, identity_type, cookie_dict_extra=None):
    """
    Finalises login. Validates provided token, sets cookies
    and redirects to the final page.
    :param token: token string
    :param identity_type:  identity_type e.g. x509, userpass, oidc, saml
    :param cookie_dict_extra: extra cookies to set, dictionary expected
    :returns: redirects to the final page or renders a page with an error message.
    """
    cookie = []
    try:
        valid_token_dict = validate_webui_token(from_cookie=False, session_token=token)
    except CannotAuthenticate:
        return render_template("problem.html", msg="It was not possible to validate and finalize your login with the provided token: " + token)
    try:
        attribs = list_account_attributes(valid_token_dict['account'], valid_token_dict['vo'])
        accounts = identity.list_accounts_for_identity(valid_token_dict['identity'], identity_type)
        accvalues = ""
        for acc in accounts:
            accvalues += acc + " "
        accounts = accvalues[:-1]

        cookie.extend([{'key': 'x-rucio-auth-token', 'value': quote(token)},
                       {'key': 'x-rucio-auth-type', 'value': quote(identity_type)},
                       {'key': 'rucio-auth-token-created-at', 'value': str(int(time()))},
                       {'key': 'rucio-available-accounts', 'value': quote(accounts)},
                       {'key': 'rucio-account-attr', 'value': quote(dumps(attribs))},
                       {'key': 'rucio-selected-account', 'value': quote(valid_token_dict['account'])},
                       {'key': 'rucio-selected-vo', 'value': quote(valid_token_dict['vo'])}])

        if cookie_dict_extra:
            for key, value in cookie_dict_extra.items():
                cookie.append({'key': key, 'value': value})
        return redirect_to_last_known_url(cookie)
    except Exception:
        return render_template("problem.html", msg="It was not possible to validate and finalize your login with the provided token.")


def get_vo_descriptions(vos):
    """
    Gets the description for each VO in the list.
    :param vos: List of 3 character VO strings
    :returns: List of tuples containing VO string, VO description
    """
    all_vos = vo_core.list_vos()
    vos_with_desc = []
    for vo in all_vos:
        if vo['vo'] in vos:
            vos_with_desc.append((vo['vo'], vo['description']))
    return vos_with_desc


# AUTH_TYPE SPECIFIC METHODS FOLLOW:


def x509token_auth(data=None):
    """
    Manages login via X509 certificate.
    :param data: data object containing account string can be provided
    :returns: final page or a page with an error message
    """
    # checking if Rucio auth server succeeded to verify the certificate
    if request.environ.get('SSL_CLIENT_VERIFY') != 'SUCCESS':
        return render_template("problem.html", msg="No certificate provided. Please authenticate with a certificate registered in Rucio.")
    dn = request.environ.get('SSL_CLIENT_S_DN')
    if not MULTI_VO:
        ui_vo = 'def'
    elif hasattr(data, 'vo') and data.vo:
        ui_vo = data.vo
    else:
        ui_vo = None
    if hasattr(data, 'account') and data.account:
        ui_account = data.account
    else:
        ui_account = None

    if ui_account is None and ui_vo is None:
        ui_account, ui_vo = select_account_name(dn, 'x509', ui_vo)
    elif ui_account is None:
        ui_account, _ = select_account_name(dn, 'x509', ui_vo)
    elif ui_vo is None:
        _, ui_vo = select_account_name(dn, 'x509', ui_vo)

    # Try to eliminate VOs based on the account name (if we have one), if we still have multiple options let the user select one
    if type(ui_vo) is list:
        if ui_account:
            valid_vos = []
            for vo in ui_vo:
                if account_exists(ui_account, vo):
                    valid_vos.append(vo)
            if len(valid_vos) == 0:
                return render_template('problem.html', msg=('<br><br>Your certificate (%s) is not mapped to (possibly any) rucio account: %s at any VO.' % (html.escape(dn), html.escape(ui_account))))
            elif len(valid_vos) == 1:
                ui_vo = valid_vos[0]
            else:
                vos_with_desc = get_vo_descriptions(valid_vos)
                return add_cookies(make_response(render_template("select_login_method.html", oidc_issuers=AUTH_ISSUERS, saml_support=SAML_SUPPORT, possible_vos=vos_with_desc)))
        else:
            vos_with_desc = get_vo_descriptions(ui_vo)
            return add_cookies(make_response(render_template("select_login_method.html", oidc_issuers=AUTH_ISSUERS, saml_support=SAML_SUPPORT, possible_vos=vos_with_desc)))

    if not ui_account:
        if MULTI_VO:
            msg = "<br><br>Your certificate (%s) is not mapped to (possibly any) rucio account at VO: %s." % (html.escape(dn), html.escape(ui_vo))
        else:
            msg = "<br><br>Your certificate (%s) is not mapped to (possibly any) rucio account." % (html.escape(dn))
    else:
        if MULTI_VO:
            msg = "<br><br>Your certificate (%s) is not mapped to (possibly any) rucio account: %s at VO: %s." % (html.escape(dn), html.escape(ui_account), html.escape(ui_vo))
        else:
            msg = "<br><br>Your certificate (%s) is not mapped to (possibly any) rucio account: %s." % (html.escape(dn), html.escape(ui_account))

    if ADDITIONAL_ERROR_MSG:
        msg += ADDITIONAL_ERROR_MSG
    if not ui_account:
        return render_template("problem.html", msg=msg)
    token = get_token(auth.get_auth_token_x509, acc=ui_account, vo=ui_vo, idt=dn)
    if not token:
        return render_template("problem.html", msg=msg)
    return finalize_auth(token, 'x509')


def userpass_auth():
    """
    Manages login via Rucio USERPASS method.
    :returns: final page or a page with an error message
    """

    ui_account = request.args.get('account')
    ui_vo = request.args.get('vo')
    username = request.form.get('username')
    password = request.form.get('password')

    if not username and not password:
        return render_template('problem.html', msg="No input credentials were provided.")

    if not MULTI_VO:
        ui_vo = 'def'
    if ui_account is None and ui_vo is None:
        ui_account, ui_vo = select_account_name(username, 'userpass', ui_vo)
    elif ui_account is None:
        ui_account, _ = select_account_name(username, 'userpass', ui_vo)
    elif ui_vo is None:
        _, ui_vo = select_account_name(username, 'userpass', ui_vo)

    if type(ui_vo) is list:
        if ui_account:
            valid_vos = []
            for vo in ui_vo:
                if account_exists(ui_account, vo):
                    valid_vos.append(vo)

            if len(valid_vos) == 0:
                return render_template('problem.html', msg='Cannot find any Rucio account %s associated with identity %s at any VO.' % (html.escape(ui_account), html.escape(username)))
            elif len(valid_vos) == 1:
                ui_vo = valid_vos[0]
            else:
                vos_with_desc = get_vo_descriptions(valid_vos)
                return render_template('login.html', account=ui_account, vo=None, possible_vos=vos_with_desc)
        else:
            vos_with_desc = get_vo_descriptions(ui_vo)
            return render_template('login.html', account=None, vo=None, possible_vos=vos_with_desc)

    if not ui_account:
        if MULTI_VO:
            return render_template('problem.html', msg='Cannot get find any account associated with %s identity at VO %s.' % (html.escape(username), html.escape(ui_vo)))
        else:
            return render_template('problem.html', msg='Cannot get find any account associated with %s identity.' % (html.escape(username)))
    token = get_token(auth.get_auth_token_user_pass, acc=ui_account, vo=ui_vo, idt=username, pwd=password)
    if not token:
        if MULTI_VO:
            return render_template('problem.html', msg='Cannot get auth token. It is possible that the presented identity %s is not mapped to any Rucio account %s at VO %s.') % (html.escape(username), html.escape(ui_account), html.escape(ui_vo))
        else:
            return render_template('problem.html', msg='Cannot get auth token. It is possible that the presented identity %s is not mapped to any Rucio account %s.') % (html.escape(username), html.escape(ui_account))

    return finalize_auth(token, 'userpass')


def saml_auth(method, data=None):
    """
    # TODO: Validate for Flask
    Login with SAML
    :param method: method type, GET or POST
    :param data: data object containing account string can be provided
    :param rendered_tpl: page to be rendered
    :returns: rendered final page or a page with error message
    """
    SAML_PATH = join(dirname(__file__), 'saml/')
    req = prepare_saml_request(request.environ, data)
    samlauth = OneLogin_Saml2_Auth(req, custom_base_path=SAML_PATH)
    saml_user_data = request.cookies.get('saml-user-data')
    if not MULTI_VO:
        ui_vo = 'def'
    elif hasattr(data, 'vo') and data.vo:
        ui_vo = data.vo
    else:
        ui_vo = None
    if hasattr(data, 'account') and data.account:
        ui_account = data.account
    else:
        ui_account = None

    if method == "GET":
        # If user data is not present, redirect to IdP for authentication
        if not saml_user_data:
            return redirect(samlauth.login(), code=303)
        # If user data is present but token is not valid, create a new one
        saml_nameid = request.cookies.get('saml-nameid')
        if ui_account is None and ui_vo is None:
            ui_account, ui_vo = select_account_name(saml_nameid, 'saml', ui_vo)
        elif ui_account is None:
            ui_account, _ = select_account_name(saml_nameid, 'saml', ui_vo)
        elif ui_vo is None:
            _, ui_vo = select_account_name(saml_nameid, 'saml', ui_vo)

        # Try to eliminate VOs based on the account name (if we have one), if we still have multiple options let the user select one
        if type(ui_vo) is list:
            if ui_account:
                valid_vos = []
                for vo in ui_vo:
                    if account_exists(ui_account, vo):
                        valid_vos.append(vo)
                if len(valid_vos) == 0:
                    return render_template("problem.html", msg=('Cannot find any Rucio account %s associated with identity %s at any VO.' % (html.escape(ui_account), html.escape(saml_nameid))))
                elif len(valid_vos) == 1:
                    ui_vo = valid_vos[0]
                else:
                    vos_with_desc = get_vo_descriptions(valid_vos)
                    return add_cookies(make_response(render_template("select_login_method.html", oidc_issuers=AUTH_ISSUERS, saml_support=SAML_SUPPORT, possible_vos=vos_with_desc)))
            else:
                vos_with_desc = get_vo_descriptions(ui_vo)
                return add_cookies(make_response(render_template("select_login_method.html", oidc_issuers=AUTH_ISSUERS, saml_support=SAML_SUPPORT, possible_vos=vos_with_desc)))

        if not ui_account:
            if MULTI_VO:
                return render_template("problem.html", msg='Cannot get find any account associated with %s identity at VO %s.' % (html.escape(saml_nameid), html.escape(ui_vo)))
            else:
                return render_template("problem.html", msg='Cannot get find any account associated with %s identity.' % (html.escape(saml_nameid)))
        token = get_token(auth.get_auth_token_saml, acc=ui_account, vo=ui_vo, idt=saml_nameid)
        if not token:
            if MULTI_VO:
                return render_template("problem.html", msg=('Cannot get auth token. It is possible that the presented identity %s is not mapped to any Rucio account %s at VO %s.') % (html.escape(saml_nameid), html.escape(ui_account), html.escape(ui_vo)))
            else:
                return render_template("problem.html", msg=('Cannot get auth token. It is possible that the presented identity %s is not mapped to any Rucio account %s.') % (html.escape(saml_nameid), html.escape(ui_account)))
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
            if ui_account is None and ui_vo is None:
                ui_account, ui_vo = select_account_name(saml_nameid, 'saml', ui_vo)
            elif ui_account is None:
                ui_account, _ = select_account_name(saml_nameid, 'saml', ui_vo)
            elif ui_vo is None:
                _, ui_vo = select_account_name(saml_nameid, 'saml', ui_vo)

            # Try to eliminate VOs based on the account name (if we have one), if we still have multiple options let the user select one
            if type(ui_vo) is list:
                if ui_account:
                    valid_vos = []
                    for vo in ui_vo:
                        if account_exists(ui_account, vo):
                            valid_vos.append(vo)
                    if len(valid_vos) == 0:
                        return render_template("problem.html", msg=('Cannot find any Rucio account %s associated with identity %s at any VO.' % (html.escape(ui_account), html.escape(saml_nameid))))
                    elif len(valid_vos) == 1:
                        ui_vo = valid_vos[0]
                    else:
                        vos_with_desc = get_vo_descriptions(valid_vos)
                        return add_cookies(make_response(render_template("select_login_method.html", oidc_issuers=AUTH_ISSUERS, saml_support=SAML_SUPPORT, possible_vos=vos_with_desc)))
                else:
                    vos_with_desc = get_vo_descriptions(ui_vo)
                    return add_cookies(make_response(render_template("select_login_method.html", oidc_issuers=AUTH_ISSUERS, saml_support=SAML_SUPPORT, possible_vos=vos_with_desc)))

            if not ui_account:
                if MULTI_VO:
                    return render_template("problem.html", msg='Cannot get find any account associated with %s identity at VO %s.' % (html.escape(saml_nameid), html.escape(ui_vo)))
                else:
                    return render_template("problem.html", msg='Cannot get find any account associated with %s identity.' % (html.escape(saml_nameid)))
            token = get_token(auth.get_auth_token_saml, acc=ui_account, vo=ui_vo, idt=saml_nameid)
            if not token:
                if MULTI_VO:
                    return render_template("problem.html",
                                           msg=('Cannot get auth token. It is possible that the presented identity %s is not mapped to any Rucio account %s at VO %s.') % (html.escape(saml_nameid), html.escape(ui_account), html.escape(ui_vo)))
                else:
                    return render_template("problem.html", msg=('Cannot get auth token. It is possible that the presented identity %s is not mapped to any Rucio account %s.') % (html.escape(saml_nameid), html.escape(ui_account)))
            return finalize_auth(token, 'saml', cookie_extra)

        return render_template("problem.html", msg="Not authenticated")

    return render_template("problem.html", msg="Error while processing SAML")


def oidc_auth(account, issuer, ui_vo=None):
    """
    # TODO: Validate for Flask
    Open ID Connect Login
    :param account: Rucio account string
    :param issuer: issuer key (e.g. xdc, wlcg) as in the idpsecrets.json file
    :param ui_vo: 3 character string to identify the VO, if None will attempt to deduce it from `account`
    :returns: rendered final page or a page with error message
    """
    if not account:
        account = 'webui'
    if ui_vo is None:
        all_vos = [vo['vo'] for vo in vo_core.list_vos()]
        valid_vos = []
        for vo in all_vos:
            if account_exists(account, vo):
                valid_vos.append(vo)
        if len(valid_vos) == 0:
            return render_template("problem.html", msg=('Cannot find any Rucio account %s at any VO.' % html.escape(account)))
        elif len(valid_vos) == 1:
            ui_vo = valid_vos[0]
        else:
            vos_with_desc = get_vo_descriptions(valid_vos)
            return add_cookies(make_response(render_template("select_login_method.html", oidc_issuers=AUTH_ISSUERS, saml_support=SAML_SUPPORT, possible_vos=vos_with_desc)))

    if not issuer:
        return render_template("problem.html", msg="Please provide IdP issuer.")
    realhome = request.environ.get('REQUEST_SCHEME') + '://' + request.environ.get('HTTP_HOST') + request.environ.get('SCRIPT_NAME')
    kwargs = {'audience': None,
              'auth_scope': None,
              'issuer': issuer.lower(),
              'auto': True,
              'polling': False,
              'refresh_lifetime': None,
              'ip': None,
              'webhome': realhome + '/oidc_final'}
    auth_url = auth.get_auth_oidc(account, vo=ui_vo, **kwargs)
    if not auth_url:
        return render_template("problem.html", msg=("It was not possible to get the OIDC authentication url "
                                                    "from the Rucio auth server. "
                                                    "In case you provided your account name, make sure it is "
                                                    "known to Rucio."))
    return redirect(auth_url, code=303)


def authenticate(template, title):
    """
    Authentication management method.
    :param template: the template name that should be rendered
    :returns: rendered final page or a page with error message
    """
    global AUTH_ISSUERS, SAML_SUPPORT, AUTH_TYPE
    cookie = []
    try:
        valid_token_dict = validate_webui_token()
    except CannotAuthenticate:
        cookie.append({'key': 'rucio-requested-path', 'value': request.environ.get('REQUEST_URI')})
    else:
        return access_granted(valid_token_dict, template, title)

    # login without any known server config
    if not AUTH_TYPE:
        return add_cookies(make_response(render_template("select_login_method.html", oidc_issuers=AUTH_ISSUERS, saml_support=SAML_SUPPORT)), cookie)
    # for AUTH_TYPE predefined by the server continue
    else:
        if AUTH_TYPE == 'userpass':
            return redirect('/login', code=303)
        elif AUTH_TYPE == 'x509':
            return x509token_auth(None)
        elif AUTH_TYPE == 'x509_userpass':
            if request.environ.get('SSL_CLIENT_VERIFY') == 'SUCCESS':
                return x509token_auth(None)
            return render_template("no_certificate.html")
        elif AUTH_TYPE == 'oidc':
            return oidc_auth(None, AUTH_ISSUER_WEBUI)
        elif AUTH_TYPE == 'saml':
            return saml_auth("GET")
        return render_template('problem.html', msg='Invalid auth type')
