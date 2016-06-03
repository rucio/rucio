#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Martin Barisits, <martin.barisits@cern.ch>, 2013-2016
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2015

from logging import getLogger, StreamHandler, DEBUG
from json import dumps, loads
from traceback import format_exc
from urlparse import parse_qsl

from web import application, ctx, data, header, Created, InternalError, OK, loadhook

from rucio.api.lock import get_replica_locks_for_rule_id
from rucio.api.rule import (add_replication_rule, delete_replication_rule, get_replication_rule, update_replication_rule,
                            reduce_replication_rule, list_replication_rule_history, list_replication_rule_full_history,
                            list_replication_rules, examine_replication_rule)
from rucio.common.exception import (InsufficientAccountLimit, RuleNotFound, AccessDenied, InvalidRSEExpression,
                                    InvalidReplicationRule, RucioException, DataIdentifierNotFound, InsufficientTargetRSEs,
                                    ReplicationRuleCreationTemporaryFailed, InvalidRuleWeight, StagingAreaRuleRequiresLifetime,
                                    DuplicateRule, InvalidObject, AccountNotFound, RuleReplaceFailed, ScratchDiskLifetimeConflict,
                                    ManualRuleApprovalBlocked, UnsupportedOperation)
from rucio.common.utils import generate_http_error, render_json, APIEncoder
from rucio.web.rest.common import rucio_loadhook

logger = getLogger("rucio.rule")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = ('/(.+)/locks', 'ReplicaLocks',
        '/(.+)/reduce', 'ReduceRule',
        '/(.+)/(.+)/history', 'RuleHistoryFull',
        '/(.+)/history', 'RuleHistory',
        '/(.+)/analysis', 'RuleAnalysis',
        '/', 'AllRule',
        '/(.+)', 'Rule',)


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
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0])
        except Exception, e:
            raise InternalError(e)

        return render_json(**rule)

    def PUT(self, rule_id):
        """
        Update the replication rules locked flag .

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            500 InternalError
        """
        json_data = data()
        try:
            params = loads(json_data)
            options = params['options']
            update_replication_rule(rule_id=rule_id, options=options, issuer=ctx.env.get('issuer'))
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except RuleNotFound, e:
            raise generate_http_error(404, 'RuleNotFound', e.args[0][0])
        except AccountNotFound, e:
            raise generate_http_error(404, 'AccountNotFound', e.args[0][0])
        except ScratchDiskLifetimeConflict, e:
            raise generate_http_error(409, 'ScratchDiskLifetimeConflict', e.args[0])
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')
        except UnsupportedOperation:
            raise generate_http_error(409, 'UnsupportedOperation', e.args[0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0])
        raise OK()

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
        json_data = data()
        try:
            purge_replicas = None
            params = loads(json_data)
            if 'purge_replicas' in params:
                purge_replicas = params['purge_replicas']
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            delete_replication_rule(rule_id=rule_id, purge_replicas=purge_replicas, issuer=ctx.env.get('issuer'))
        except AccessDenied, e:
            raise generate_http_error(401, 'AccessDenied', e.args[0][0])
        except UnsupportedOperation, e:
            raise generate_http_error(401, 'UnsupportedOperation', e.args[0][0])
        except RuleNotFound, e:
            raise generate_http_error(404, 'RuleNotFound', e.args[0][0])
        except Exception, e:
            raise InternalError(e)
        raise OK()


class AllRule:
    """ REST APIs for all rules. """

    def GET(self):
        """
        Return all rules of a given account.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found

        :param scope: The scope name.
        """
        header('Content-Type', 'application/x-json-stream')
        filters = {}
        if ctx.query:
            params = dict(parse_qsl(ctx.query[1:]))
            filters.update(params)

        try:
            for rule in list_replication_rules(filters=filters):
                yield dumps(rule, cls=APIEncoder) + '\n'
        except RuleNotFound, e:
            raise generate_http_error(404, 'RuleNotFound', e.args[0][0])
        except Exception, e:
            print format_exc()
            raise InternalError(e)

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
            grouping, weight, lifetime, locked, subscription_id, source_replica_expression, activity, notify,\
                purge_replicas, ignore_availability, comment, ask_approval, asynchronous = 'DATASET', None, None,\
                False, None, None, None, None, False, False, None, False, False

            params = loads(json_data)
            dids = params['dids']
            account = params['account']
            copies = params['copies']
            rse_expression = params['rse_expression']
            if 'grouping' in params:
                grouping = params['grouping']
            if 'weight' in params:
                weight = params['weight']
            if 'lifetime' in params:
                lifetime = params['lifetime']
            if 'locked' in params:
                locked = params['locked']
            if 'subscription_id' in params:
                subscription_id = params['subscription_id']
            if 'source_replica_expression' in params:
                source_replica_expression = params['source_replica_expression']
            if 'activity' in params:
                activity = params['activity']
            if 'notify' in params:
                notify = params['notify']
            if 'purge_replicas' in params:
                purge_replicas = params['purge_replicas']
            if 'ignore_availability' in params:
                ignore_availability = params['ignore_availability']
            if 'comment' in params:
                comment = params['comment']
            if 'ask_approval' in params:
                ask_approval = params['ask_approval']
            if 'asynchronous' in params:
                asynchronous = params['asynchronous']

        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            rule_ids = add_replication_rule(dids=dids,
                                            copies=copies,
                                            rse_expression=rse_expression,
                                            weight=weight,
                                            lifetime=lifetime,
                                            grouping=grouping,
                                            account=account,
                                            locked=locked,
                                            subscription_id=subscription_id,
                                            source_replica_expression=source_replica_expression,
                                            activity=activity,
                                            notify=notify,
                                            purge_replicas=purge_replicas,
                                            ignore_availability=ignore_availability,
                                            comment=comment,
                                            ask_approval=ask_approval,
                                            asynchronous=asynchronous,
                                            issuer=ctx.env.get('issuer'))
        # TODO: Add all other error cases here
        except InvalidReplicationRule, e:
            raise generate_http_error(409, 'InvalidReplicationRule', e.args[0][0])
        except DuplicateRule, e:
            raise generate_http_error(409, 'DuplicateRule', e.args[0])
        except InsufficientTargetRSEs, e:
            raise generate_http_error(409, 'InsufficientTargetRSEs', e.args[0][0])
        except InsufficientAccountLimit, e:
            raise generate_http_error(409, 'InsufficientAccountLimit', e.args[0][0])
        except InvalidRSEExpression, e:
            raise generate_http_error(409, 'InvalidRSEExpression', e.args[0][0])
        except DataIdentifierNotFound, e:
            raise generate_http_error(404, 'DataIdentifierNotFound', e.args[0][0])
        except ReplicationRuleCreationTemporaryFailed, e:
            raise generate_http_error(409, 'ReplicationRuleCreationTemporaryFailed', e.args[0][0])
        except InvalidRuleWeight, e:
            raise generate_http_error(409, 'InvalidRuleWeight', e.args[0][0])
        except StagingAreaRuleRequiresLifetime, e:
            raise generate_http_error(409, 'StagingAreaRuleRequiresLifetime', e.args[0])
        except ScratchDiskLifetimeConflict, e:
            raise generate_http_error(409, 'ScratchDiskLifetimeConflict', e.args[0])
        except ManualRuleApprovalBlocked, e:
            raise generate_http_error(409, 'ManualRuleApprovalBlocked', e.args[0])
        except InvalidObject, e:
            raise generate_http_error(409, 'InvalidObject', e.args[0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0])
        except Exception, e:
            print e
            print format_exc()
            raise InternalError(e)

        raise Created(dumps(rule_ids))


class ReplicaLocks:
    """ REST APIs for replica locks. """

    def GET(self, rule_id):
        """ get locks for a given rule_id.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            500 InternalError

        :returns: JSON dict containing informations about the requested user.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            locks = get_replica_locks_for_rule_id(rule_id)
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0])
        except Exception, e:
            raise InternalError(e)

        for lock in locks:
            yield dumps(lock, cls=APIEncoder) + '\n'


class ReduceRule:
    """ REST APIs for reducing rules. """

    def POST(self, rule_id):
        """
        Reduce a replication rule.

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
            exclude_expression = None

            params = loads(json_data)
            copies = params['copies']
            if 'exclude_expression' in params:
                exclude_expression = params['exclude_expression']
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            rule_ids = reduce_replication_rule(rule_id=rule_id,
                                               copies=copies,
                                               exclude_expression=exclude_expression,
                                               issuer=ctx.env.get('issuer'))
        # TODO: Add all other error cases here
        except RuleReplaceFailed, e:
            raise generate_http_error(409, 'RuleReplaceFailed', e.args[0][0])
        except RuleNotFound, e:
            raise generate_http_error(404, 'RuleNotFound', e.args[0][0])
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0])
        except Exception, e:
            print e
            print format_exc()
            raise InternalError(e)

        raise Created(dumps(rule_ids))


class RuleHistory:
    """ REST APIs for rule history. """

    def GET(self, rule_id):
        """ get history for a given rule_id.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            500 InternalError

        :returns: JSON dict containing informations about the requested user.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            history = list_replication_rule_history(rule_id)
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0])
        except Exception, e:
            raise InternalError(e)

        for hist in history:
            yield dumps(hist, cls=APIEncoder) + '\n'


class RuleHistoryFull:
    """ REST APIs for rule history for DIDs. """

    def GET(self, scope, name):
        """ get history for a given DID.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            500 InternalError

        :returns: JSON dict containing informations about the requested user.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            history = list_replication_rule_full_history(scope, name)
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0])
        except Exception, e:
            raise InternalError(e)

        for hist in history:
            yield dumps(hist, cls=APIEncoder) + '\n'


class RuleAnalysis:
    """ REST APIs for rule analysis. """

    def GET(self, rule_id):
        """ get analysis for given rule.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            500 InternalError

        :returns: JSON dict containing informations about the requested user.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            analysis = examine_replication_rule(rule_id)
        except RucioException, e:
            raise generate_http_error(500, e.__class__.__name__, e.args[0])
        except Exception, e:
            raise InternalError(e)

        return render_json(**analysis)


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
app.add_processor(loadhook(rucio_loadhook))
application = app.wsgifunc()
