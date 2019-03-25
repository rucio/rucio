#!/usr/bin/env python
# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Vincent Garonne <vgaronne@gmail.com>, 2012-2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2018
# - Thomas Beermann <thomas.beermann@cern.ch>, 2013-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2013-2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2017
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

from __future__ import print_function
from logging import getLogger, StreamHandler, DEBUG
from json import dumps, loads
from traceback import format_exc
try:
    from urlparse import parse_qsl
except ImportError:
    from urllib.parse import parse_qsl
from web import application, ctx, data, header, Created, InternalError, OK, loadhook

from rucio.api.lock import get_replica_locks_for_rule_id
from rucio.api.rule import (add_replication_rule, delete_replication_rule, get_replication_rule, update_replication_rule,
                            reduce_replication_rule, list_replication_rule_history, list_replication_rule_full_history,
                            list_replication_rules, examine_replication_rule, move_replication_rule)
from rucio.common.exception import (InsufficientAccountLimit, RuleNotFound, AccessDenied, InvalidRSEExpression,
                                    InvalidReplicationRule, RucioException, DataIdentifierNotFound, InsufficientTargetRSEs,
                                    ReplicationRuleCreationTemporaryFailed, InvalidRuleWeight, StagingAreaRuleRequiresLifetime,
                                    DuplicateRule, InvalidObject, AccountNotFound, RuleReplaceFailed, ScratchDiskLifetimeConflict,
                                    ManualRuleApprovalBlocked, UnsupportedOperation)
from rucio.common.schema import SCOPE_NAME_REGEXP
from rucio.common.utils import generate_http_error, render_json, APIEncoder
from rucio.web.rest.common import rucio_loadhook, check_accept_header_wrapper

LOGGER = getLogger("rucio.rule")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)

URLS = ('/(.+)/locks', 'ReplicaLocks',
        '/(.+)/reduce', 'ReduceRule',
        '/(.+)/move', 'MoveRule',
        '%s/history' % SCOPE_NAME_REGEXP, 'RuleHistoryFull',
        '/(.+)/history', 'RuleHistory',
        '/(.+)/analysis', 'RuleAnalysis',
        '/', 'AllRule',
        '/(.+)', 'Rule',)


class Rule:
    """ REST APIs for replication rules. """

    @check_accept_header_wrapper(['application/json'])
    def GET(self, rule_id):
        """ get rule information for given rule id.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            406 Not Acceptable
            500 InternalError

        :returns: JSON dict containing informations about the requested user.
        """
        header('Content-Type', 'application/json')
        try:
            estimate_ttc = False
            json_data = data()
            params = loads(json_data)
            if 'estimate_ttc' in params:
                estimate_ttc = params['estimate_ttc']
        except ValueError:
            estimate_ttc = False
        try:
            rule = get_replication_rule(rule_id, estimate_ttc=estimate_ttc)
        except RuleNotFound as error:
            raise generate_http_error(404, 'RuleNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)

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
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except RuleNotFound as error:
            raise generate_http_error(404, 'RuleNotFound', error.args[0])
        except AccountNotFound as error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0])
        except ScratchDiskLifetimeConflict as error:
            raise generate_http_error(409, 'ScratchDiskLifetimeConflict', error.args[0])
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')
        except UnsupportedOperation as error:
            raise generate_http_error(409, 'UnsupportedOperation', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
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
        except AccessDenied as error:
            raise generate_http_error(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            raise generate_http_error(401, 'UnsupportedOperation', error.args[0])
        except RuleNotFound as error:
            raise generate_http_error(404, 'RuleNotFound', error.args[0])
        except Exception as error:
            raise InternalError(error)
        raise OK()


class AllRule:
    """ REST APIs for all rules. """

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self):
        """
        Return all rules of a given account.

        HTTP Success:
            200 OK

        HTTP Error:
            401 Unauthorized
            404 Not Found
            406 Not Acceptable

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
        except RuleNotFound as error:
            raise generate_http_error(404, 'RuleNotFound', error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

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
                purge_replicas, ignore_availability, comment, ask_approval, asynchronous, priority,\
                split_container, meta = 'DATASET', None, None, False, None, None, None, None, False, False, None,\
                False, False, 3, False, None

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
            if 'priority' in params:
                priority = params['priority']
            if 'split_container' in params:
                split_container = params['split_container']
            if 'meta' in params:
                meta = params['meta']

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
                                            priority=priority,
                                            split_container=split_container,
                                            meta=meta,
                                            issuer=ctx.env.get('issuer'))
        # TODO: Add all other error cases here
        except InvalidReplicationRule as error:
            raise generate_http_error(409, 'InvalidReplicationRule', error.args[0])
        except DuplicateRule as error:
            raise generate_http_error(409, 'DuplicateRule', error.args[0])
        except InsufficientTargetRSEs as error:
            raise generate_http_error(409, 'InsufficientTargetRSEs', error.args[0])
        except InsufficientAccountLimit as error:
            raise generate_http_error(409, 'InsufficientAccountLimit', error.args[0])
        except InvalidRSEExpression as error:
            raise generate_http_error(409, 'InvalidRSEExpression', error.args[0])
        except DataIdentifierNotFound as error:
            raise generate_http_error(404, 'DataIdentifierNotFound', error.args[0])
        except ReplicationRuleCreationTemporaryFailed as error:
            raise generate_http_error(409, 'ReplicationRuleCreationTemporaryFailed', error.args[0])
        except InvalidRuleWeight as error:
            raise generate_http_error(409, 'InvalidRuleWeight', error.args[0])
        except StagingAreaRuleRequiresLifetime as error:
            raise generate_http_error(409, 'StagingAreaRuleRequiresLifetime', error.args[0])
        except ScratchDiskLifetimeConflict as error:
            raise generate_http_error(409, 'ScratchDiskLifetimeConflict', error.args[0])
        except ManualRuleApprovalBlocked as error:
            raise generate_http_error(409, 'ManualRuleApprovalBlocked', error.args[0])
        except InvalidObject as error:
            raise generate_http_error(409, 'InvalidObject', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            raise InternalError(error)

        raise Created(dumps(rule_ids))


class ReplicaLocks:
    """ REST APIs for replica locks. """

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, rule_id):
        """ get locks for a given rule_id.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            406 Not Acceptable
            500 InternalError

        :returns: JSON dict containing informations about the requested user.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            locks = get_replica_locks_for_rule_id(rule_id)
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)

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
        except RuleReplaceFailed as error:
            raise generate_http_error(409, 'RuleReplaceFailed', error.args[0])
        except RuleNotFound as error:
            raise generate_http_error(404, 'RuleNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            raise InternalError(error)

        raise Created(dumps(rule_ids))


class MoveRule:
    """ REST APIs for moving rules. """

    def POST(self, rule_id):
        """
        Move a replication rule.

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
            rule_id = params['rule_id']
            rse_expression = params['rse_expression']
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            rule_ids = move_replication_rule(rule_id=rule_id,
                                             rse_expression=rse_expression,
                                             issuer=ctx.env.get('issuer'))
        except RuleReplaceFailed as error:
            raise generate_http_error(409, 'RuleReplaceFailed', error.args[0])
        except RuleNotFound as error:
            raise generate_http_error(404, 'RuleNotFound', error.args[0])
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            raise InternalError(error)

        raise Created(dumps(rule_ids))


class RuleHistory:
    """ REST APIs for rule history. """

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, rule_id):
        """ get history for a given rule_id.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            406 Not Acceptable
            500 InternalError

        :returns: JSON dict containing informations about the requested user.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            history = list_replication_rule_history(rule_id)
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)

        for hist in history:
            yield dumps(hist, cls=APIEncoder) + '\n'


class RuleHistoryFull:
    """ REST APIs for rule history for DIDs. """

    @check_accept_header_wrapper(['application/x-json-stream'])
    def GET(self, scope, name):
        """ get history for a given DID.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            406 Not Acceptable
            500 InternalError

        :returns: JSON dict containing informations about the requested user.
        """
        header('Content-Type', 'application/x-json-stream')
        try:
            history = list_replication_rule_full_history(scope, name)
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)

        for hist in history:
            yield dumps(hist, cls=APIEncoder) + '\n'


class RuleAnalysis:
    """ REST APIs for rule analysis. """

    @check_accept_header_wrapper(['application/json'])
    def GET(self, rule_id):
        """ get analysis for given rule.

        HTTP Success:
            200 OK

        HTTP Error:
            404 Not Found
            406 Not Acceptable
            500 InternalError

        :returns: JSON dict containing informations about the requested user.
        """
        header('Content-Type', 'application/json')
        try:
            analysis = examine_replication_rule(rule_id)
        except RucioException as error:
            raise generate_http_error(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            raise InternalError(error)

        return render_json(**analysis)


"""----------------------
   Web service startup
----------------------"""

APP = application(URLS, globals())
APP.add_processor(loadhook(rucio_loadhook))
application = APP.wsgifunc()
