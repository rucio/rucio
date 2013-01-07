#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from json import dumps, loads
from logging import getLogger, StreamHandler, DEBUG
from web import application, ctx, data, header, BadRequest, Created, InternalError, Unauthorized

from rucio.api.authentication import validate_auth_token
from rucio.api.rule import add_replication_rule

from rucio.common.utils import generate_http_error

logger = getLogger("rucio.rule")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = ('/', 'Rule')


class Rule:
    """ REST APIs for replication rules. """

    def GET(self):
        raise BadRequest()

    def PUT(self):
        raise BadRequest()

    def POST(self):
        """
        Create a new replication rule.

        HTTP Success:
            201 Created

        HTTP Error:
            401 Unauthorized
            404 Not Found
            409 Conflict
            500 Internal Error
        """

        header('Content-Type', 'application/octet-stream')
        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        auth = validate_auth_token(auth_token)

        if auth is None:
            raise Unauthorized()

        json_data = data()
        try:
            params = loads(json_data)
            dids = params['dids']
            copies = params['copies']
            rse_expression = params['rse_expression']
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            rule_id = add_replication_rule(dids=dids, copies=copies, rse_expression=rse_expression, parameters=params, issuer=auth['account'])
        except Exception, e:
            print e
            raise InternalError(e)

        raise Created(dumps({'rule_id': rule_id}))

    def DELETE(self):
        raise BadRequest()


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
