#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Vincent Garonne,  <vincent.garonne@cern.ch> , 2011

from datetime import datetime
from json import dumps, loads
from logging import getLogger, StreamHandler, DEBUG
from web import application, ctx, data, header, seeother, BadRequest, Created, InternalError, OK

from rucio.api.account import add_account, del_account, get_account_info, list_accounts
from rucio.api.identity import add_account_identity
from rucio.api.permission import has_permission
from rucio.api.scope import add_scope, get_scopes
from rucio.common.exception import AccountNotFound, Duplicate, AccessDenied
from rucio.common.utils import generate_http_error
from rucio.core.authentication import validate_auth_token

import web
web.config.debug = True

logger = getLogger("rucio.account")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = (
    '/(.+)/scopes/', 'Scopes',
    '/(.+)/scopes/(.+)', 'Scopes',
    '/(.+)/identities', 'Identities',
    '/(.+)/limits', 'AccountLimits',
    '/(.+)', 'AccountParameter',
    '/', 'Account'
)


class Scopes:
    def GET(self, accountName):
        """ list all scopes for an account.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            500 InternalError

        :param Rucio-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        :returns: A list containing all scope names for an account.
        """
        header('Content-Type', 'application/json')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        try:
            scopes = get_scopes(accountName)
        except AccountNotFound, e:
            raise generate_http_error(404, 'AccountNotFound', e.args[0][0])
        except Exception, e:
            raise InternalError(e)

        if not len(scopes):
            raise generate_http_error(404, 'ScopeNotFound', 'no scopes found for account ID \'%s\'' % accountName)

        return dumps(scopes)

    def POST(self, accountName, scopeName):
        """ create scope with given scope name.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            404 Not Found
            409 Conflict
            500 Internal Error

        :param Rucio-Auth-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        :params Rucio-Account: account belonging to the new scope.
        """

        header('Content-Type', 'application/octet-stream')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if not auth:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        try:
            if not has_permission(issuer=auth.get('account'), action='add_scope', kwargs={'accountName': accountName, 'scopeName': scopeName}):
                raise AccessDenied('Account %s can not add scope to account %s' (auth.get('account'), accountName))
            add_scope(scopeName, accountName)
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except Duplicate, e:
            raise generate_http_error(409, 'Duplicate', e.args[0][0])
        except AccountNotFound, e:
            raise generate_http_error(404, 'AccountNotFound', e.args[0][0])
        except Exception, e:
            raise InternalError(e)

        raise Created()


class AccountParameter:
    """ create, update, get and disable rucio accounts. """

    def GET(self, accountName):
        """ get account information for given account name.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            500 InternalError

        :param Rucio-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.

        :returns: JSON dict containing informations about the requested user.
        """

        header('Content-Type', 'application/json')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        if accountName == 'whoami':
            # Redirect to the account uri
            raise seeother(auth['account'])

        acc = None
        try:
            acc = get_account_info(accountName)
        except AccountNotFound, e:
            raise generate_http_error(404, 'AccountNotFound', e.args[0][0])

        dict = acc.to_dict()

        for key, value in dict.items():
            if isinstance(value, datetime):
                dict[key] = value.strftime('%Y-%m-%dT%H:%M:%S')

        del dict['_sa_instance_state']

        return dumps(dict)

    def PUT(self, accountName):
        """ update account informations for given account name """
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def POST(self, accountName):
        """ create account with given account name.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Reqeust
            401 Unauthorized
            409 Conflict
            500 Internal Error

        :param Rucio-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        :params Rucio-Type: the type of the new account.
        """
        header('Content-Type', 'application/octet-stream')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        json_data = data()

        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'cannot decode json parameter dictionary')

        accountType = None

        try:
            accountType = parameter['accountType']
        except KeyError, e:
            if e.args[0] == 'accountType':
                raise generate_http_error(400, 'KeyError', '%s not defined' % str(e))
        except TypeError:
                raise generate_http_error(400, 'TypeError', 'body must be a json dictionary')

        try:
            add_account(accountName, accountType)
        except Duplicate as e:
            raise generate_http_error(409, 'Duplicate', e.args[0][0])
        except Exception, e:
            raise InternalError(e)

        raise Created()

    def DELETE(self, accountName):
        """ disable account with given account name.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            500 InternalError

        :param Rucio-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        """

        header('Content-Type', 'application/octet-stream')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        try:
            del_account(accountName)
        except AccountNotFound, e:
            raise generate_http_error(404, 'AccountNotFound', e.args[0][0])

        raise OK()


class Account:
    def GET(self):
        """ list all rucio accounts.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            500 InternalError

        :param Rucio-Account: Account identifier.
        :param Rucio-Auth-Token: as an 32 character hex string.
        :returns: A list containing all account names.
        """

        header('Content-Type', 'application/json')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')
        return dumps(list_accounts())

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def POST(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()


class AccountLimits:
    def GET(self, accountName):
        """ get the current limits for an account """
        raise BadRequest()

    def PUT(self):
        """ update the limits for an account """
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def POST(self):
        """ set the limits for an account """
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()


class Identities:
    def POST(self, accountName):
        """ Grant an identity access to an account.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Reqeust
            401 Unauthorized
            409 Conflict
            500 Internal Error

        :param accountName: Account identifier.
        """

        header('Content-Type', 'application/octet-stream')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        json_data = data()

        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'cannot decode json parameter dictionary')

        try:
            identity = parameter['identity']
            authtype = parameter['authtype']
        except KeyError, e:
            if e.args[0] == 'authtype' or e.args[0] == 'identity':
                raise generate_http_error(400, 'KeyError', '%s not defined' % str(e))
        except TypeError:
                raise generate_http_error(400, 'TypeError', 'body must be a json dictionary')

        try:
            add_account_identity(identity=identity, type=authtype, account=accountName, issuer=auth.get('account'))
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except Duplicate as e:
            raise generate_http_error(409, 'Duplicate', e.args[0][0])
        except AccountNotFound, e:
            raise generate_http_error(404, 'AccountNotFound', e.args[0][0])
        except Exception, e:
            raise InternalError(e)

        raise Created()

    def GET(self, accountName):
        raise BadRequest()

    def PUT(self):
        """ update the limits for an account """
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
