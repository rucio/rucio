#!/usr/bin/env python
'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Martin Barisits, <martin.barisits@cern.ch>, 2014
'''

from json import loads
from logging import getLogger, StreamHandler, DEBUG
from traceback import format_exc
from web import application, loadhook, ctx, data, BadRequest, Created, InternalError, OK

from rucio.api.account_limit import set_account_limit, delete_account_limit
from rucio.common.exception import RSENotFound, AccessDenied, AccountNotFound
from rucio.common.utils import generate_http_error
from rucio.web.rest.common import rucio_loadhook, RucioController


logger = getLogger("rucio.account_limit")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = (
    '/(.+)/(.+)', 'AccountLimit',
)


class AccountLimit(RucioController):
    def GET(self, account, rse):
        raise BadRequest()

    def PUT(self, account, rse):
        raise BadRequest()

    def POST(self, account, rse):
        """ Create or update an account limit.
        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            404 Not Found
            500 Internal Error

        :param X-Rucio-Auth-Account: Account identifier.
        :param X-Rucio-Auth-Token:   As an 32 character hex string.
        :param account:              Account name.
        :param rse:                  RSE name.
        """
        json_data = data()
        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'cannot decode json parameter dictionary')
        try:
            bytes = parameter['bytes']
        except KeyError, e:
            if e.args[0] == 'type':
                raise generate_http_error(400, 'KeyError', '%s not defined' % str(e))
        except TypeError:
            raise generate_http_error(400, 'TypeError', 'body must be a json dictionary')

        try:
            set_account_limit(account=account, rse=rse, bytes=bytes, issuer=ctx.env.get('issuer'))
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e.args[0][0])
        except AccountNotFound, e:
            raise generate_http_error(404, 'AccountNotFound', e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)

        raise Created()

    def DELETE(self, account, rse):
        """ Delete an account limit.
        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            500 Internal Error

        :param X-Rucio-Auth-Account: Account identifier.
        :param X-Rucio-Auth-Token:   As an 32 character hex string.
        :param account:              Account name.
        :param rse:                  RSE name.
        """
        try:
            delete_account_limit(account=account, rse=rse, issuer=ctx.env.get('issuer'))
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except AccountNotFound, e:
            raise generate_http_error(404, 'AccountNotFound', e.args[0][0])
        except RSENotFound, e:
            raise generate_http_error(404, 'RSENotFound', e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)

        raise OK()

"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
app.add_processor(loadhook(rucio_loadhook))
application = app.wsgifunc()
