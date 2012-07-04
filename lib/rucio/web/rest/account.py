#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012

from datetime import datetime
from json import dumps
from logging import getLogger, StreamHandler, DEBUG
from web import application, ctx, header, BadRequest, Created, InternalError, HTTPError, OK, Unauthorized

from rucio.api.account import add_account, del_account, get_account_info, list_accounts
from rucio.common.exception import AccountNotFound, Duplicate
from rucio.core.authentication import validate_auth_token

logger = getLogger("rucio.account")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = (
    '/(.+)/limits', 'AccountLimits',
    '/(.+)', 'Account',
    '/', 'AccountList'
)


class Account:
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
            raise Unauthorized()

        if accountName == 'whoami':
            # Redirect to the account uri
            raise web.seeother(auth[0])

        acc = None
        try:
            acc = get_account_info(accountName)
        except AccountNotFound, e:
            status = '404 Not Found'
            headers = {'ExceptionClass': 'AccountNotFound', 'ExceptionMessage': e[0][0]}
            data = ' '.join(['AccountNotFound:', str(e)])
            raise HTTPError(status, headers=headers, data=data)

        dict = acc.to_dict()

        for key, value in dict.items():
            if isinstance(value, datetime):
                dict[key] = value.strftime('%Y-%m-%dT%H:%M:%S')

        del dict['_sa_instance_state']

        return dumps(dict)

    def POST(self, accountName):
        """ update account informations for given account name """
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def PUT(self, accountName):
        """ create account with given account name.

        HTTP Success:
            201 Created

        HTTP Error:
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
            raise Unauthorized()

        type = ctx.env.get('HTTP_RUCIO_TYPE')

        if type is None:
            raise InternalError('Rucio-Type has to be set')

        try:
            add_account(accountName, type)
        except Duplicate as e:
            status = '409 Conflict'
            headers = {'ExceptionClass': 'Duplicate', 'ExceptionMessage': e[0][0]}
            data = ' '.join(['Duplicate:', str(e)])
            raise HTTPError(status, headers=headers, data=data)
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
            raise Unauthorized()

        try:
            del_account(accountName)
        except AccountNotFound, e:
            status = '404 Not Found'
            headers = {'ExceptionClass': 'AccountNotFound', 'ExceptionMessage': e[0][0]}
            data = ' '.join(['AccountNotFound:', str(e)])
            raise HTTPError(status, headers=headers, data=data)

        raise OK()


class AccountList:
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
            raise Unauthorized()

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

"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
