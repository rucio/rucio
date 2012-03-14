#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012

import logging
import json
import web
import datetime

from rucio.api import account
from rucio.common import exception as r_exception

logger = logging.getLogger("rucio.account")
sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
logger.addHandler(sh)

urls = (
    '/account/(.+)/limits', 'AccountLimits',
    '/account/(.+)', 'Account',
    '/accounts', 'AccountList'
)


class Account:

    def GET(self, accountName):
        """ get account information for given account name

        HTTP Body: json containing the account information

        HTTP Error Headers:
            500 InternalError

        """
        web.header('Content-Type', 'application/json')
        acc = None
        try:
            acc = account.get_account_info(accountName)
        except r_exception.NotFound, e:
            raise web.InternalError(e)

        dict = acc.to_dict()

        for key, value in dict.items():
            if isinstance(value, datetime.datetime):
                dict[key] = value.strftime('%Y-%m-%dT%H:%M:%S')

        del dict['_sa_instance_state']

        ret = json.dumps(dict)

        return ret

    def PUT(self, accountName):
        """ update account informations for given account name """
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def POST(self, accountName):
        """ create account with given account name

        HTTP Request Header:
            Rucio-Type: the type of the new account

        HTTP Success Header:
            201 Created

        HTTP Error Headers:
            500 Internal Error
        """

        web.header('Content-Type', 'application/octet-stream')
        type = web.ctx.env.get('HTTP_RUCIO_TYPE')

        if type is None:
            raise web.InternalError('Rucio-Type has to be set')

        try:
            account.add_account(accountName, type)
        except r_exception.Duplicate, e:
            raise web.InternalError(e)
        except Exception, e:
            raise web.InternalError(e)

        raise web.Created()

    def DELETE(self, accountName):
        """ disable account with given account name

        HTTP Success Header:
            200 OK

        HTTP Error Header:
            500 InternalError
        """
        web.header('Content-Type', 'application/octet-stream')
        try:
            account.del_account(accountName)
        except r_exception.NotFound, e:
            raise web.InternalError(e)

        raise web.OK()


class AccountList:
    def GET(self):
        """ list all rucio accounts """
        web.header('Content-Type', 'application/octet-stream')
        return account.list_accounts()

    def PUT(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def POST(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def DELETE(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()


class AccountLimits:
    def GET(self, accountName):
        """ get the current limits for an account """
        raise web.BadRequest()

    def PUT(self):
        """ update the limits for an account """
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def POST(self):
        """ set the limits for an account """
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def DELETE(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()


app = web.application(urls, globals())

if __name__ == "__main__":
    app.run()
