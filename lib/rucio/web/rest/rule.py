#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Martin Barisits, <martin.barisits@cern.ch>, 2013

from logging import getLogger, StreamHandler, DEBUG
from json import dumps, loads
from traceback import format_exc

from web import application, ctx, data, BadRequest, header, Created, InternalError, OK, loadhook

from rucio.api.rule import add_replication_rule, delete_replication_rule, get_replication_rule
from rucio.common.exception import (InsufficientQuota, RuleNotFound, AccessDenied, InvalidRSEExpression,
                                    InvalidReplicationRule, RucioException)
from rucio.common.utils import generate_http_error, render_json
from rucio.web.rest.common import authenticate

logger = getLogger("rucio.rule")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = ('/', 'Rule',
        '/(.+)', 'Rule')


class Rule:
    """ REST APIs for replication rules. """

    def GET(self, rule_id):
        """ get rule information for given rule id.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            500 InternalError

        :returns: JSON dict containing informations about the requested user.
        """
        header('Content-Type', 'application/json')
        try:
            rule = get_replication_rule(rule_id)
        except RuleNotFound, e:
            raise generate_http_error(404, 'RuleNotFound', e.args[0][0])
        except Exception, e:
            raise InternalError(e)

        return render_json(**rule)

    def PUT(self):
        raise BadRequest()

    def POST(self):
        """
        Create a new replication rule.

        HTTP Success:
            201 Created

        HTTP Error:
            400 Bad Request
            401 Unauthorized
            404 Not Found
            409 Conflict
            500 Internal Error
        """
        json_data = data()
        try:
            params = loads(json_data)
            dids = params['dids']
            account = params['account']
            copies = params['copies']
            rse_expression = params['rse_expression']
            grouping = params['grouping']
            weight = params['weight']
            lifetime = params['lifetime']
            locked = params['locked']
            subscription_id = params['subscription_id']
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            rule_ids = add_replication_rule(dids=dids, copies=copies, rse_expression=rse_expression, weight=weight, lifetime=lifetime, grouping=grouping, account=account, locked=locked, subscription_id=subscription_id, issuer=ctx.env.get('issuer'))
        #TODO: Add all other error cases here
        except InsufficientQuota, e:
            raise generate_http_error(409, 'InsufficientQuota', e.args[0][0])
        except InvalidRSEExpression, e:
            raise generate_http_error(409, 'InvalidRSEExpression', e.args[0][0])
        except InvalidReplicationRule, e:
            raise generate_http_error(409, 'InvalidReplicationRule', e.args[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0][0])
        except Exception, e:
            print e
            print format_exc()
            raise InternalError(e)

        raise Created(dumps(rule_ids))

    def DELETE(self, rule_id):
        """
        Delete a new replication rule.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            500 Internal Error
        """
        try:
            delete_replication_rule(rule_id=rule_id, issuer=ctx.env.get('issuer'))
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except RuleNotFound, e:
            raise generate_http_error(404, 'RuleNotFound', e.args[0][0])
        except Exception, e:
            raise InternalError(e)
        raise OK()


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
app.add_processor(loadhook(authenticate))
application = app.wsgifunc()
