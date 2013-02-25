#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012-2013
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013

from datetime import datetime
from json import dumps, loads
from logging import getLogger, StreamHandler, DEBUG
from traceback import format_exc
from web import application, ctx, data, header, seeother, BadRequest, Created, InternalError, OK


from rucio.api.account import add_account, del_account, get_account_info, list_accounts, list_identities
from rucio.api.authentication import validate_auth_token
from rucio.api.identity import add_account_identity
from rucio.api.scope import add_scope, get_scopes
from rucio.common.exception import AccountNotFound, Duplicate, AccessDenied, RucioException
from rucio.common.utils import generate_http_error

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
    def GET(self, account_name):
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
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        try:
            scopes = get_scopes(account_name)
        except AccountNotFound, e:
            raise generate_http_error(404, 'AccountNotFound', e.args[0][0])
        except Exception, e:
            raise InternalError(e)

        if not len(scopes):
            raise generate_http_error(404, 'ScopeNotFound', 'no scopes found for account ID \'%s\'' % account_name)

        return dumps(scopes)

    def POST(self, account_name, scope_name):
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
            add_scope(scope_name, account_name, issuer=auth.get('account'))
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except Duplicate, e:
            raise generate_http_error(409, 'Duplicate', e.args[0][0])
        except AccountNotFound, e:
            raise generate_http_error(404, 'AccountNotFound', e.args[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)

        raise Created()


class AccountParameter:
    """ create, update, get and disable rucio accounts. """

    def GET(self, account_name):
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
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        if account_name == 'whoami':
            # Redirect to the account uri
            raise seeother(auth['account'])

        acc = None
        try:
            acc = get_account_info(account_name)
        except AccountNotFound, e:
            raise generate_http_error(404, 'AccountNotFound', e.args[0][0])

        dict = acc.to_dict()

        for key, value in dict.items():
            if isinstance(value, datetime):
                dict[key] = value.strftime('%Y-%m-%dT%H:%M:%S')

        del dict['_sa_instance_state']

        return dumps(dict)

    def PUT(self, account_name):
        """ update account informations for given account name """
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def POST(self, account_name):
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

        account_type = None

        try:
            account_type = parameter['account_type']
        except KeyError, e:
            if e.args[0] == 'account_type':
                raise generate_http_error(400, 'KeyError', '%s not defined' % str(e))
        except TypeError:
                raise generate_http_error(400, 'TypeError', 'body must be a json dictionary')

        try:
            add_account(account_name, account_type, issuer=auth.get('account'))
        except Duplicate as e:
            raise generate_http_error(409, 'Duplicate', e.args[0][0])
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)

        raise Created()

    def DELETE(self, account_name):
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
            del_account(account_name, issuer=auth.get('account'))
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except AccountNotFound, e:
            raise generate_http_error(404, 'AccountNotFound', e.args[0][0])
        except Exception, e:
            raise InternalError(e)

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
        :returns: A list containing all account names as dict.
        """

        header('Content-Type', 'application/x-json-stream')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        for account in list_accounts():
            yield dumps(account) + "\n"

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
    def GET(self, account_name):
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
    def POST(self, account_name):
        """ Grant an identity access to an account.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Reqeust
            401 Unauthorized
            409 Conflict
            500 Internal Error

        :param account_name: Account identifier.
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
            add_account_identity(identity_key=identity, type=authtype, account=account_name, issuer=auth.get('account'))
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except Duplicate as e:
            raise generate_http_error(409, 'Duplicate', e.args[0][0])
        except AccountNotFound, e:
            raise generate_http_error(404, 'AccountNotFound', e.args[0][0])
        except Exception, e:
            raise InternalError(e)

        raise Created()

    def GET(self, account_name):
        header('Content-Type', 'application/x-json-stream')
        header('Cache-Control', 'no-cache, no-store, max-age=0, must-revalidate')
        header('Cache-Control', 'post-check=0, pre-check=0', False)
        header('Pragma', 'no-cache')

        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise generate_http_error(401, 'CannotAuthenticate', 'Cannot authenticate with given credentials')

        try:
            for identity in list_identities(account_name):
                yield dumps(identity) + "\n"
        except AccountNotFound, e:
            raise generate_http_error(404, 'AccountNotFound', e.args[0][0])
        except Exception, e:
            print e
            raise InternalError(e)

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
