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

from flask import Flask, Blueprint, request, Response
from flask.views import MethodView

from rucio.api.lock import get_replica_locks_for_rule_id
from rucio.api.rule import (add_replication_rule, delete_replication_rule, get_replication_rule, update_replication_rule,
                            reduce_replication_rule, list_replication_rule_history, list_replication_rule_full_history,
                            list_replication_rules, examine_replication_rule, move_replication_rule)
from rucio.common.exception import (InsufficientAccountLimit, RuleNotFound, AccessDenied, InvalidRSEExpression,
                                    InvalidReplicationRule, RucioException, DataIdentifierNotFound, InsufficientTargetRSEs,
                                    ReplicationRuleCreationTemporaryFailed, InvalidRuleWeight, StagingAreaRuleRequiresLifetime,
                                    DuplicateRule, InvalidObject, AccountNotFound, RuleReplaceFailed, ScratchDiskLifetimeConflict,
                                    ManualRuleApprovalBlocked, UnsupportedOperation)
from rucio.common.utils import generate_http_error_flask, render_json, APIEncoder
from rucio.web.rest.flaskapi.v1.common import before_request, after_request, check_accept_header_wrapper_flask

LOGGER = getLogger("rucio.rule")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)


class Rule(MethodView):
    """ REST APIs for replication rules. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, rule_id):
        """ get rule information for given rule id.

        .. :quickref: Rule; get rule info

        :returns: JSON dict containing informations about the requested user.
        :status 200: Rule found
        :status 406: Not Acceptable
        :status 410: Invalid Auth Token
        :status 404: no rule found for id
        """
        try:
            estimate_ttc = False
            json_data = request.data
            params = loads(json_data)
            if 'estimate_ttc' in params:
                estimate_ttc = params['estimate_ttc']
        except ValueError:
            estimate_ttc = False
        try:
            rule = get_replication_rule(rule_id, estimate_ttc=estimate_ttc)
        except RuleNotFound as error:
            return generate_http_error_flask(404, 'RuleNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            return error, 500

        return Response(render_json(**rule), content_type="application/json")

    def put(self, rule_id):
        """
        Update the replication rules locked flag .

        .. :quickref: Rule; update rule

        :status 200: Rule found
        :status 401: Invalid Auth Token
        :status 404: no rule found for id
        """
        json_data = request.data
        try:
            params = loads(json_data)
            options = params['options']
            update_replication_rule(rule_id=rule_id, options=options, issuer=request.environ.get('issuer'))
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except RuleNotFound as error:
            return generate_http_error_flask(404, 'RuleNotFound', error.args[0])
        except AccountNotFound as error:
            return generate_http_error_flask(404, 'AccountNotFound', error.args[0])
        except ScratchDiskLifetimeConflict as error:
            return generate_http_error_flask(409, 'ScratchDiskLifetimeConflict', error.args[0])
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')
        except UnsupportedOperation as error:
            return generate_http_error_flask(409, 'UnsupportedOperation', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        return "OK", 200

    def delete(self, rule_id):
        """
        Delete a new replication rule.

        .. :quickref: Rule; delete rule

        :status 200: DIDs found
        :status 401: Invalid Auth Token
        :status 404: no rule found for id
        """
        json_data = request.data
        try:
            purge_replicas = None
            params = loads(json_data)
            if 'purge_replicas' in params:
                purge_replicas = params['purge_replicas']
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            delete_replication_rule(rule_id=rule_id, purge_replicas=purge_replicas, issuer=request.environ.get('issuer'))
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except UnsupportedOperation as error:
            return generate_http_error_flask(401, 'UnsupportedOperation', error.args[0])
        except RuleNotFound as error:
            return generate_http_error_flask(404, 'RuleNotFound', error.args[0])
        except Exception as error:
            return error, 500
        return "OK", 200


class AllRule(MethodView):
    """ REST APIs for all rules. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """
        Return all rules of a given account.

        .. :quickref: AllRule; get all rules for account

        :resheader Content-Type: application/x-json-stream
        :status 200: Rule found
        :status 401: Invalid Auth Token
        :status 404: no rule found for id
        :status 406: Not Acceptable
        :query scope: The scope name.
        """
        filters = {}
        if request.args:
            params = dict(request.args)
            filters.update(params)

        try:
            data = ""
            for rule in list_replication_rules(filters=filters):
                data += dumps(rule, cls=APIEncoder) + '\n'
            return Response(data, content_type="application/x-json-stream")
        except RuleNotFound as error:
            return generate_http_error_flask(404, 'RuleNotFound', error.args[0])
        except Exception as error:
            print(format_exc())
            return error, 500

    def post(self):
        """
        Create a new replication rule.

        .. :quickref: AllRule; create new rule

        :<json list dids: List of data identifiers.
        :<json string account: Account issuing the rule.
        :<json int copies: The number of replicas.
        :<json string rse_expression: RSE expression which gets resolved into a list of RSEs.
        :<json string grouping: ALL -  All files will be replicated to the same RSE.
                                       DATASET - All files in the same dataset will be replicated to the same RSE.
                                       NONE - Files will be completely spread over all allowed RSEs without any grouping considerations at all
        :<json int weight: Weighting scheme to be used.
        :<json int lifetime: The lifetime of the replication rule in seconds.
        :<json string locked: If the is locked.
        :<json string subscription_id: The subscription_id, if the rule is created by a subscription.
        :<json string source_replica_expression: Only use replicas as source from these RSEs.
        :<json string activity: Activity to be passed to the conveyor.
        :<json string notify: Notification setting of the rule ('Y', 'N', 'C'; None = 'N').
        :<json bool purge_replicas: Purge setting if a replica should be directly deleted after the rule is deleted.
        :<json bool ignore_availability: Option to ignore the availability of RSEs.
        :<json string comments: Comment about the rule.
        :<json bool ask_approval: Ask for approval for this rule.
        :<json bool asynchronous: Create replication rule asynchronously by the judge-injector.
        :<json int priority: Priority of the rule and the transfers which should be submitted.
        :<json bool split_container: Should a container rule be split into individual dataset rules.
        :<json string meta: Dictionary with metadata from the WFMS.
        :status 201: rule created
        :status 401: Invalid Auth Token
        :status 404: DID not found
        :status 409: Invalid Replication Rule
        :status 409: Duplicate Replication Rule
        :status 409: Insufficient Target RSEs
        :status 409: Insufficient Account Limit
        :status 409: Invalid RSE Expression
        :status 409: Replication Rule Creation Temporary Failed
        :status 409: Invalid Rule Weight
        :status 409: Staging Area Rule Requires Lifetime
        :status 409: Scratch Disk Lifetime Conflict
        :status 409: Manual Rule Approval Blocked
        :status 409: Invalid Object
        :returns: List of ids for created rules
        """
        json_data = request.data
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
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

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
                                            issuer=request.environ.get('issuer'))
        # TODO: Add all other error cases here
        except InvalidReplicationRule as error:
            return generate_http_error_flask(409, 'InvalidReplicationRule', error.args[0])
        except DuplicateRule as error:
            return generate_http_error_flask(409, 'DuplicateRule', error.args[0])
        except InsufficientTargetRSEs as error:
            return generate_http_error_flask(409, 'InsufficientTargetRSEs', error.args[0])
        except InsufficientAccountLimit as error:
            return generate_http_error_flask(409, 'InsufficientAccountLimit', error.args[0])
        except InvalidRSEExpression as error:
            return generate_http_error_flask(409, 'InvalidRSEExpression', error.args[0])
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, 'DataIdentifierNotFound', error.args[0])
        except ReplicationRuleCreationTemporaryFailed as error:
            return generate_http_error_flask(409, 'ReplicationRuleCreationTemporaryFailed', error.args[0])
        except InvalidRuleWeight as error:
            return generate_http_error_flask(409, 'InvalidRuleWeight', error.args[0])
        except StagingAreaRuleRequiresLifetime as error:
            return generate_http_error_flask(409, 'StagingAreaRuleRequiresLifetime', error.args[0])
        except ScratchDiskLifetimeConflict as error:
            return generate_http_error_flask(409, 'ScratchDiskLifetimeConflict', error.args[0])
        except ManualRuleApprovalBlocked as error:
            return generate_http_error_flask(409, 'ManualRuleApprovalBlocked', error.args[0])
        except InvalidObject as error:
            return generate_http_error_flask(409, 'InvalidObject', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            return error, 500

        return Response(dumps(rule_ids), status=201)


class ReplicaLocks(MethodView):
    """ REST APIs for replica locks. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, rule_id):
        """ get locks for a given rule_id.

        .. :quickref: ReplicaLocks; get locks by rule id

        :status 200: Rule found
        :status 406: Not Acceptable
        :status 500: Database Exception
        :returns: JSON dict containing informations about the requested user.
        """
        try:
            locks = get_replica_locks_for_rule_id(rule_id)
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            return error, 500

        data = ""
        for lock in locks:
            data += dumps(lock, cls=APIEncoder) + '\n'

        return Response(data, content_type="application/x-json-stream")


class ReduceRule(MethodView):
    """ REST APIs for reducing rules. """

    def post(self, rule_id):
        """
        Reduce a replication rule.

        .. :quickref: ReduceRule; reduce rule

        :status 200: Rule found.
        :status 401: Invalid Auth Token.
        :status 404: no rule found for id.
        :status 409: Rule replace failed.
        :returns: List of rule ids
        """
        json_data = request.data
        try:
            exclude_expression = None

            params = loads(json_data)
            copies = params['copies']
            if 'exclude_expression' in params:
                exclude_expression = params['exclude_expression']
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            rule_ids = reduce_replication_rule(rule_id=rule_id,
                                               copies=copies,
                                               exclude_expression=exclude_expression,
                                               issuer=request.environ.get('issuer'))
        # TODO: Add all other error cases here
        except RuleReplaceFailed as error:
            return generate_http_error_flask(409, 'RuleReplaceFailed', error.args[0])
        except RuleNotFound as error:
            return generate_http_error_flask(404, 'RuleNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            return error, 500

        return Response(dumps(rule_ids), status=201)


class MoveRule(MethodView):
    """ REST APIs for moving rules. """

    def post(self, rule_id):
        """
        Move a replication rule.

        .. :quickref: MoveRule; move rule

        :status 200: Rule found
        :status 401: Invalid Auth Token
        :status 404: no rule found for id
        :status 409: Rule replace failed.
        :returns: List of rule ids.
        """
        json_data = request.data
        try:
            params = loads(json_data)
            rule_id = params['rule_id']
            rse_expression = params['rse_expression']
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            rule_ids = move_replication_rule(rule_id=rule_id,
                                             rse_expression=rse_expression,
                                             issuer=request.environ.get('issuer'))
        except RuleReplaceFailed as error:
            return generate_http_error_flask(409, 'RuleReplaceFailed', error.args[0])
        except RuleNotFound as error:
            return generate_http_error_flask(404, 'RuleNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(error)
            print(format_exc())
            return error, 500

        return Response(dumps(rule_ids), status=201)


class RuleHistory(MethodView):
    """ REST APIs for rule history. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, rule_id):
        """ get history for a given rule_id.

        .. :quickref: RuleHistory; get rule history by id

        :resheader Content-Type: application/x-json-stream
        :status 200: Rule found
        :status 406: Not Acceptable
        :status 500: Database Exception
        :returns: JSON dict containing informations about the requested user.
        """
        try:
            history = list_replication_rule_history(rule_id)
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            return error, 500

        data = ""
        for hist in history:
            data += dumps(hist, cls=APIEncoder) + '\n'
        return Response(data, content_type="application/x-json-stream")


class RuleHistoryFull(MethodView):
    """ REST APIs for rule history for DIDs. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope, name):
        """ get history for a given DID.

        .. :quickref: RuleHistoryFull; get rule history for DID

        :resheader Content-Type: application/x-json-stream
        :status 200: Rule found
        :status 406: Not Acceptable
        :status 500: Database Exception
        :returns: JSON dict containing informations about the requested user.
        """
        try:
            history = list_replication_rule_full_history(scope, name)
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            return error, 500

        data = ""
        for hist in history:
            data += dumps(hist, cls=APIEncoder) + '\n'
        return Response(data, content_type="application/x-json-stream")


class RuleAnalysis(MethodView):
    """ REST APIs for rule analysis. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, rule_id):
        """ get analysis for given rule.

        .. :quickref: RuleAnalysis; analyse rule,

        :resheader Content-Type: application/x-json-stream
        :status 200: Rule found
        :status 406: Not Acceptable
        :status 500: Database Exception
        :returns: JSON dict containing informations about the requested user.
        """
        try:
            analysis = examine_replication_rule(rule_id)
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            return error, 500

        return Response(render_json(**analysis), content_type="application/x-json-stream")


"""----------------------
   Web service startup
----------------------"""

bp = Blueprint('rule', __name__)

rule_view = Rule.as_view('rule')
bp.add_url_rule('/<rule_id>', view_func=rule_view, methods=['get', 'put', 'delete'])
all_rule_view = AllRule.as_view('all_rule')
bp.add_url_rule('/', view_func=all_rule_view, methods=['get', 'post'])
replica_locks_view = ReplicaLocks.as_view('replica_locks')
bp.add_url_rule('/<rule_id>/locks', view_func=replica_locks_view, methods=['get', ])
reduce_rule_view = ReduceRule.as_view('reduce_rule')
bp.add_url_rule('/<rule_id>/reduce', view_func=reduce_rule_view, methods=['post', ])
move_rule_view = MoveRule.as_view('move_rule')
bp.add_url_rule('/<rule_id>/mode', view_func=move_rule_view, methods=['post', ])
rule_history_view = RuleHistory.as_view('rule_history')
bp.add_url_rule('/<rule_id>/history', view_func=rule_history_view, methods=['get', ])
rule_history_full_view = RuleHistoryFull.as_view('rule_history_full')
bp.add_url_rule('/<scope>/<name>/history', view_func=rule_history_full_view, methods=['get', ])
rule_analysis_view = RuleAnalysis.as_view('rule_analysis')
bp.add_url_rule('/<rule_id>/analysis', view_func=rule_analysis_view, methods=['get', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/rule')
    return doc_app


if __name__ == "__main__":
    application.run()
