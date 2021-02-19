# -*- coding: utf-8 -*-
# Copyright 2012-2021 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2013-2021
# - Martin Barisits <martin.barisits@cern.ch>, 2013-2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2017
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Muhammad Aditya Hilmy <didithilmy@gmail.com>, 2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

from json import dumps

from flask import Flask, Blueprint, request, Response

from rucio.api.lock import get_replica_locks_for_rule_id
from rucio.api.rule import add_replication_rule, delete_replication_rule, get_replication_rule, \
    update_replication_rule, reduce_replication_rule, list_replication_rule_history, \
    list_replication_rule_full_history, list_replication_rules, examine_replication_rule, move_replication_rule
from rucio.common.exception import InsufficientAccountLimit, RuleNotFound, AccessDenied, InvalidRSEExpression, \
    InvalidReplicationRule, DataIdentifierNotFound, InsufficientTargetRSEs, ReplicationRuleCreationTemporaryFailed, \
    InvalidRuleWeight, StagingAreaRuleRequiresLifetime, DuplicateRule, InvalidObject, AccountNotFound, \
    RuleReplaceFailed, ScratchDiskLifetimeConflict, ManualRuleApprovalBlocked, UnsupportedOperation
from rucio.common.utils import render_json, APIEncoder
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, parse_scope_name, try_stream, \
    request_auth_env, response_headers, generate_http_error_flask, ErrorHandlingMethodView, json_parameters, param_get


class Rule(ErrorHandlingMethodView):
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
        parameters = json_parameters(optional=True)
        estimate_ttc = param_get(parameters, 'estimate_ttc', default=False)
        try:
            rule = get_replication_rule(rule_id, estimate_ttc=estimate_ttc, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except RuleNotFound as error:
            return generate_http_error_flask(404, error)

        return Response(render_json(**rule), content_type="application/json")

    def put(self, rule_id):
        """
        Update the replication rules locked flag .

        .. :quickref: Rule; update rule

        :status 200: Rule found
        :status 401: Invalid Auth Token
        :status 404: no rule found for id
        """
        parameters = json_parameters()
        options = param_get(parameters, 'options')
        try:
            update_replication_rule(rule_id=rule_id, options=options, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except (RuleNotFound, AccountNotFound) as error:
            return generate_http_error_flask(404, error)
        except (ScratchDiskLifetimeConflict, UnsupportedOperation) as error:
            return generate_http_error_flask(409, error)

        return '', 200

    def delete(self, rule_id):
        """
        Delete a new replication rule.

        .. :quickref: Rule; delete rule

        :status 200: DIDs found
        :status 401: Invalid Auth Token
        :status 404: no rule found for id
        """
        parameters = json_parameters()
        purge_replicas = param_get(parameters, 'purge_replicas', default=None)
        try:
            delete_replication_rule(rule_id=rule_id, purge_replicas=purge_replicas, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except (AccessDenied, UnsupportedOperation) as error:
            return generate_http_error_flask(401, error)
        except RuleNotFound as error:
            return generate_http_error_flask(404, error)

        return '', 200


class AllRule(ErrorHandlingMethodView):
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
        try:
            def generate(filters, vo):
                for rule in list_replication_rules(filters=filters, vo=vo):
                    yield dumps(rule, cls=APIEncoder) + '\n'

            return try_stream(generate(filters=dict(request.args.items(multi=False)), vo=request.environ.get('vo')))
        except RuleNotFound as error:
            return generate_http_error_flask(404, error)

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
        parameters = json_parameters()
        dids = param_get(parameters, 'dids')
        account = param_get(parameters, 'account')
        copies = param_get(parameters, 'copies')
        rse_expression = param_get(parameters, 'rse_expression')
        try:
            rule_ids = add_replication_rule(
                dids=dids,
                copies=copies,
                rse_expression=rse_expression,
                weight=param_get(parameters, 'weight', default=None),
                lifetime=param_get(parameters, 'lifetime', default=None),
                grouping=param_get(parameters, 'grouping', default='DATASET'),
                account=account,
                locked=param_get(parameters, 'locked', default=False),
                subscription_id=param_get(parameters, 'subscription_id', default=None),
                source_replica_expression=param_get(parameters, 'source_replica_expression', default=None),
                activity=param_get(parameters, 'activity', default=None),
                notify=param_get(parameters, 'notify', default=None),
                purge_replicas=param_get(parameters, 'purge_replicas', default=False),
                ignore_availability=param_get(parameters, 'ignore_availability', default=False),
                comment=param_get(parameters, 'comment', default=None),
                ask_approval=param_get(parameters, 'ask_approval', default=False),
                asynchronous=param_get(parameters, 'asynchronous', default=False),
                priority=param_get(parameters, 'priority', default=3),
                split_container=param_get(parameters, 'split_container', default=False),
                meta=param_get(parameters, 'meta', default=None),
                issuer=request.environ.get('issuer'),
                vo=request.environ.get('vo'),
            )
        except (
            InvalidReplicationRule,
            DuplicateRule,
            InsufficientTargetRSEs,
            InsufficientAccountLimit,
            InvalidRSEExpression,
            ReplicationRuleCreationTemporaryFailed,
            InvalidRuleWeight,
            StagingAreaRuleRequiresLifetime,
            ScratchDiskLifetimeConflict,
            ManualRuleApprovalBlocked,
            InvalidObject,
        ) as error:
            return generate_http_error_flask(409, error)
        except DataIdentifierNotFound as error:
            return generate_http_error_flask(404, error)

        return Response(dumps(rule_ids), status=201)


class ReplicaLocks(ErrorHandlingMethodView):
    """ REST APIs for replica locks. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, rule_id):
        """ get locks for a given rule_id.

        .. :quickref: ReplicaLocks; get locks by rule id

        :status 200: Rule found
        :status 406: Not Acceptable
        :returns: JSON dict containing informations about the requested user.
        """

        def generate(vo):
            for lock in get_replica_locks_for_rule_id(rule_id, vo=vo):
                yield render_json(**lock) + '\n'

        return try_stream(generate(vo=request.environ.get('vo')))


class ReduceRule(ErrorHandlingMethodView):
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
        parameters = json_parameters()
        copies = param_get(parameters, 'copies')
        exclude_expression = param_get(parameters, 'exclude_expression', default=None)
        try:
            rule_ids = reduce_replication_rule(rule_id=rule_id,
                                               copies=copies,
                                               exclude_expression=exclude_expression,
                                               issuer=request.environ.get('issuer'),
                                               vo=request.environ.get('vo'))
        # TODO: Add all other error cases here
        except RuleReplaceFailed as error:
            return generate_http_error_flask(409, error)
        except RuleNotFound as error:
            return generate_http_error_flask(404, error)

        return Response(dumps(rule_ids), status=201)


class MoveRule(ErrorHandlingMethodView):
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
        parameters = json_parameters()
        rse_expression = param_get(parameters, 'rse_expression')
        rule_id = param_get(parameters, 'rule_id', default=rule_id)
        try:
            rule_ids = move_replication_rule(rule_id=rule_id,
                                             rse_expression=rse_expression,
                                             issuer=request.environ.get('issuer'),
                                             vo=request.environ.get('vo'))
        except RuleReplaceFailed as error:
            return generate_http_error_flask(409, error)
        except RuleNotFound as error:
            return generate_http_error_flask(404, error)

        return Response(dumps(rule_ids), status=201)


class RuleHistory(ErrorHandlingMethodView):
    """ REST APIs for rule history. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, rule_id):
        """ get history for a given rule_id.

        .. :quickref: RuleHistory; get rule history by id

        :resheader Content-Type: application/x-json-stream
        :status 200: Rule found
        :status 406: Not Acceptable
        :returns: JSON dict containing informations about the requested user.
        """
        def generate(issuer, vo):
            for history in list_replication_rule_history(rule_id, issuer=issuer, vo=vo):
                yield render_json(**history) + '\n'

        return try_stream(generate(issuer=request.environ.get('issuer'), vo=request.environ.get('vo')))


class RuleHistoryFull(ErrorHandlingMethodView):
    """ REST APIs for rule history for DIDs. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """ get history for a given DID.

        .. :quickref: RuleHistoryFull; get rule history for DID

        :resheader Content-Type: application/x-json-stream
        :param scope_name: data identifier (scope)/(name).
        :status 200: Rule found
        :status 406: Not Acceptable
        :returns: JSON dict containing informations about the requested user.
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))

            def generate(vo):
                for history in list_replication_rule_full_history(scope, name, vo=vo):
                    yield render_json(**history) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except ValueError as error:
            return generate_http_error_flask(400, error)


class RuleAnalysis(ErrorHandlingMethodView):
    """ REST APIs for rule analysis. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, rule_id):
        """ get analysis for given rule.

        .. :quickref: RuleAnalysis; analyse rule,

        :resheader Content-Type: application/json
        :status 200: Rule found
        :status 406: Not Acceptable
        :returns: JSON dict containing informations about the requested user.
        """
        analysis = examine_replication_rule(rule_id, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        return Response(render_json(**analysis), content_type='application/json')


def blueprint():
    bp = Blueprint('rules', __name__, url_prefix='/rules')

    rule_view = Rule.as_view('rule')
    bp.add_url_rule('/<rule_id>', view_func=rule_view, methods=['get', 'put', 'delete'])
    all_rule_view = AllRule.as_view('all_rule')
    bp.add_url_rule('/', view_func=all_rule_view, methods=['get', 'post'])
    replica_locks_view = ReplicaLocks.as_view('replica_locks')
    bp.add_url_rule('/<rule_id>/locks', view_func=replica_locks_view, methods=['get', ])
    reduce_rule_view = ReduceRule.as_view('reduce_rule')
    bp.add_url_rule('/<rule_id>/reduce', view_func=reduce_rule_view, methods=['post', ])
    move_rule_view = MoveRule.as_view('move_rule')
    bp.add_url_rule('/<rule_id>/move', view_func=move_rule_view, methods=['post', ])
    rule_history_view = RuleHistory.as_view('rule_history')
    bp.add_url_rule('/<rule_id>/history', view_func=rule_history_view, methods=['get', ])
    rule_history_full_view = RuleHistoryFull.as_view('rule_history_full')
    bp.add_url_rule('/<path:scope_name>/history', view_func=rule_history_full_view, methods=['get', ])
    rule_analysis_view = RuleAnalysis.as_view('rule_analysis')
    bp.add_url_rule('/<rule_id>/analysis', view_func=rule_analysis_view, methods=['get', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
