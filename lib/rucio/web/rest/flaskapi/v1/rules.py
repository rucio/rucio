# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

from json import dumps
from typing import Any

from flask import Flask, request, Response

from rucio.api.lock import get_replica_locks_for_rule_id
from rucio.api.rule import add_replication_rule, delete_replication_rule, get_replication_rule, \
    update_replication_rule, reduce_replication_rule, list_replication_rule_history, \
    list_replication_rule_full_history, list_replication_rules, examine_replication_rule, move_replication_rule
from rucio.common.exception import InputValidationError, InsufficientAccountLimit, RuleNotFound, AccessDenied, InvalidRSEExpression, \
    InvalidReplicationRule, DataIdentifierNotFound, InsufficientTargetRSEs, ReplicationRuleCreationTemporaryFailed, \
    InvalidRuleWeight, StagingAreaRuleRequiresLifetime, DuplicateRule, InvalidObject, AccountNotFound, \
    RuleReplaceFailed, ScratchDiskLifetimeConflict, ManualRuleApprovalBlocked, UnsupportedOperation
from rucio.common.utils import render_json, APIEncoder
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, parse_scope_name, try_stream, \
    response_headers, generate_http_error_flask, ErrorHandlingMethodView, json_parameters, param_get


class Rule(ErrorHandlingMethodView):
    """ REST APIs for replication rules. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, rule_id):
        """
        ---
        summary: Return a Rule
        tags:
          - Rule
        parameters:
        - name: rule_id
          in: path
          description: The id of the replication rule.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  type: string
          406:
            description: Not Acceptable
          401:
            description: Invalid Auth Token
          404:
            description: No rule found for the given id
        """
        parameters = json_parameters(optional=True)
        estimate_ttc = param_get(parameters, 'estimate_ttc', default=False)
        if estimate_ttc:
            return generate_http_error_flask(501, "NotImplemented", exc_msg="estimate_ttc is not implemented!")

        try:
            rule = get_replication_rule(rule_id, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except RuleNotFound as error:
            return generate_http_error_flask(404, error)

        return Response(render_json(**rule), content_type="application/json")

    def put(self, rule_id):
        """
        ---
        summary: Update the replication rules parameters
        tags:
          - Rule
        parameters:
        - name: rule_id
          in: path
          description: The id of the replication rule.
          schema:
            type: string
          style: simple
        requestBody:
          description: Parameters for the new rule.
          content:
            'application/json':
              schema:
                type: object
                required:
                - options
                properties:
                  options:
                    description: The parameters to change.
                    type: object
                    properties:
                      lifetime:
                        description: The time in which the rule will expire in seconds.
                        type: integer
                      account:
                        description: The account of the replication rule.
                        type: string
                      state:
                        description: The state of the replication rule.
                        type: string
                      cancel_requests:
                        description: Cancels all requests if used together with state.
                        type: boolean
                      priority:
                        description: The priority of a rule.
                        type: integer
                      child_rule_id:
                        description: The child rule. Parent and child rule must be on the same dataset.
                        type: string
                      meta:
                        description: The meta of a rule.
                        type: object
                      boost_rule:
                        description: Boosts the processing of a rule.
                        type: object
                      locked:
                        description: The locked state of the replication rule.
                        type: boolean
                      comment:
                        description: The comment of the replication rule.
                        type: string
                      activity:
                        description: The activity of a replication rule.
                        type: string
                      source_replica_expression:
                        description: The source replica expression of a replication rule.
                        type: string
                      eol_at:
                        description: The end of life of a replication rule.
                        type: string
                      purge_replicas:
                        description: Purge replicas
                        type: boolean
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: No rule found for the given id
       """
        parameters = json_parameters()
        options: dict[str, Any] = param_get(parameters, 'options')
        try:
            update_replication_rule(rule_id=rule_id, options=options, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except (RuleNotFound, AccountNotFound) as error:
            return generate_http_error_flask(404, error)
        except (ScratchDiskLifetimeConflict,
                UnsupportedOperation, InputValidationError) as error:
            return generate_http_error_flask(409, error)

        return '', 200

    def delete(self, rule_id):
        """
        ---
        summary: Delete a replication rule
        tags:
          - Rule
        parameters:
        - name: rule_id
          in: path
          description: The id of the replication rule.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: No rule found for the given id
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
        ---
        summary: Return all rules for a given account
        tags:
          - Rule
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  type: string
          401:
            description: Invalid Auth Token
          404:
            description: No rule found for the given id
          406:
            description: Not Acceptable
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
        ---
        summary: Create a new replication rule
        tags:
          - Rule
        requestBody:
          description: Parameters for the new rule.
          content:
            'application/json':
              schema:
                type: object
                required:
                - dids
                - account
                - copies
                - rse_expression
                properties:
                  dids:
                    description: The list of data identifiers.
                    type: array
                    items:
                      type: string
                  account:
                    description: The account of the issuer.
                    type: string
                  copies:
                    description: The number of replicas.
                    type: integer
                  rse_expression:
                    description: The rse expression which gets resolved into a list of RSEs.
                    type: string
                  grouping:
                    description: The grouping of the files to take into account. (ALL, DATASET, NONE)
                    type: string
                  weight:
                     description: Weighting scheme to be used.
                     type: number
                  lifetime:
                     description: The lifetime of the replication rule in seconds.
                     type: integer
                  locked:
                     description: If the rule is locked.
                     type: boolean
                  subscription_id:
                     description: The subscription_id, if the rule is created by a subscription.
                     type: string
                  sourse_replica_expression:
                     description: Only use replicas as source from these RSEs.
                     type: string
                  activity:
                     description: Activity to be passed to the conveyor.
                     type: string
                  notify:
                     description: Notification setting of the rule ('Y', 'N', 'C'; None = 'N').
                     type: string
                  purge_replicas:
                     description: Purge setting if a replica should be directly deleted after the rule is deleted.
                     type: boolean
                  ignore_availability:
                     description: Option to ignore the availability of RSEs.
                     type: boolean
                  comments:
                     description: Comment about the rule.
                     type: string
                  ask_approval:
                     description: Ask for approval for this rule.
                     type: boolean
                  asynchronous:
                     description: Create replication rule asynchronously by the judge-injector.
                     type: boolean
                  priority:
                     description: Priority of the rule and the transfers which should be submitted.
                     type: integer
                  split_container:
                     description: Should a container rule be split into individual dataset rules.
                     type: boolean
                  meta:
                     description: Dictionary with metadata from the WFMS.
                     type: string
        responses:
          201:
            description: Rule created.
            content:
              application/json:
                schema:
                  type: array
                  items:
                    type: string
                    description: Id of each created rule.
          401:
            description: Invalid Auth Token
          404:
            description: No rule found for the given id
          409:
            description: |
              - Invalid Replication Rule
              - Duplicate Replication Rule
              - Insufficient Target RSEs
              - Insufficient Account Limit
              - Invalid RSE Expression
              - Replication Rule Creation Temporary Failed,
              - Invalid Rule Weight
              - Staging Area Rule Requires Lifetime
              - Scratch Disk Lifetime Conflict
              - Manual Rule Approval Blocked
              - Invalid Object
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
                delay_injection=param_get(parameters, 'delay_injection', default=None),
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
        """
        ---
        summary: Return all locks for a Rule
        tags:
          - Rule
        parameters:
        - name: rule_id
          in: path
          description: The id of the replication rule.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  type: array
                  items:
                    type: object
                    properties:
                      scope:
                        description: The scope of the lock.
                        type: string
                      name:
                        description: The name of the lock.
                        type: string
                      rse_id:
                        description: The rse_id of the lock.
                        type: string
                      rse:
                        description: Information about the rse of the lock.
                        type: object
                      state:
                        description: The state of the lock.
                        type: string
                      rule_id:
                        description: The rule_id of the lock.
                        type: string
          401:
            description: Invalid Auth Token
          404:
            description: No rule found for the given id
          406:
            description: Not Acceptable
        """

        def generate(vo):
            for lock in get_replica_locks_for_rule_id(rule_id, vo=vo):
                yield render_json(**lock) + '\n'

        return try_stream(generate(vo=request.environ.get('vo')))


class ReduceRule(ErrorHandlingMethodView):
    """ REST APIs for reducing rules. """

    def post(self, rule_id):
        """
        ---
        summary: Reduce a replication rule
        tags:
          - Rule
        parameters:
        - name: rule_id
          in: path
          description: The id of the replication rule.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                required:
                - copies
                properties:
                  copies:
                    description: Number of copies to keep.
                    type: integer
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  type: array
                  items:
                    type: string
                    description: Rule id.
          401:
            description: Invalid Auth Token
          404:
            description: No rule found for the given id
          409:
            description: Rule replace failed.
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
        ---
        summary: Move a replication Rule
        tags:
          - Rule
        parameters:
        - name: rule_id
          in: path
          description: The id of the replication rule.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                required:
                - rse_expression
                properties:
                  rse_expression:
                    description: The new rse expression.
                    type: string
                  rule_id:
                    description: The rule_id of the rule to moves. If specified, overrides the `rule_id` parameter.
                    type: string
                  activity:
                    description: The `activity` of the moved rule.
                    type: string
                  source_replica_expression:
                    description: The `source_replica_expression` of the moved rule.
                    type: string
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  type: array
                  items:
                    type: string
                    description: Rule id.
          401:
            description: Invalid Auth Token
          404:
            description: No rule found for the given id
          409:
            description: Rule replace failed.
        """
        parameters = json_parameters()
        rse_expression = param_get(parameters, 'rse_expression')
        rule_id = param_get(parameters, 'rule_id', default=rule_id)
        override = param_get(parameters, 'override', default={})

        # For backwards-compatibility, deprecate in the future.
        activity = param_get(parameters, 'activity', default=None)
        if activity and 'activity' not in override:
            override['activity'] = activity
        source_replica_expression = param_get(parameters, 'source_replica_expression', default=None)
        if source_replica_expression and 'source_replica_expression' not in override:
            override['source_replica_expression'] = source_replica_expression

        try:
            rule_ids = move_replication_rule(rule_id=rule_id,
                                             rse_expression=rse_expression,
                                             override=override,
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
        """
        ---
        summary: Get the history of a rule
        tags:
          - Rule
        parameters:
        - name: rule_id
          in: path
          description: The id of the replication rule.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  type: array
                  items:
                    type: object
                    description: Rule history object.
                    properties:
                      updated_at:
                        type: string
                        description: The date of the update.
                      state:
                        type: string
                        description: The state of the update.
                      locks_ok_cnt:
                        type: integer
                        description: The number of locks which are ok.
                      locks_stuck_cnt:
                        type: integer
                        description: The number of locks which are stuck.
                      locks_replicating_cnt:
                        type: integer
                        description: The number of locks which are replicating.
          401:
            description: Invalid Auth Token
          404:
            description: No rule found for the given id
          406:
            description: Not acceptable.
        """
        def generate(issuer, vo):
            for history in list_replication_rule_history(rule_id, issuer=issuer, vo=vo):
                yield render_json(**history) + '\n'

        return try_stream(generate(issuer=request.environ.get('issuer'), vo=request.environ.get('vo')))


class RuleHistoryFull(ErrorHandlingMethodView):
    """ REST APIs for rule history for DIDs. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name):
        """
        ---
        summary: Get the history of a DID
        tags:
          - Rule
        parameters:
        - name: scope_name
          in: path
          description: The data identifier of scope-name to retrieve the history from. ((scope)/(name))
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/x-json-stream:
                schema:
                  type: array
                  items:
                    type: object
                    description: Rule history object.
                    properties:
                      rule_id:
                        type: string
                        description: The id of the rule.
                      updated_at:
                        type: string
                        description: The date of the update.
                      created_at:
                        type: string
                        description: The date of the creation.
                      rse_expression:
                        type: string
                        description: The rse expression.
                      state:
                        type: string
                        description: The state of the update.
                      account:
                        type: string
                        description: The account who initiated the change.
                      locks_ok_cnt:
                        type: integer
                        description: The number of locks which are ok.
                      locks_stuck_cnt:
                        type: integer
                        description: The number of locks which are stuck.
                      locks_replicating_cnt:
                        type: integer
                        description: The number of locks which are replicating.
          401:
            description: Invalid Auth Token
          406:
            description: Not acceptable.
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
        """
        ---
        summary: Get the analysis of a rule
        tags:
          - Rule
        parameters:
        - name: rule_id
          in: path
          description: The id of the replication rule.
          schema:
            type: string
          style: simple
        responses:
          200:
            description: OK
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    rule_error:
                      type: string
                      description: The state of the rule.
                    transfers:
                      type: array
                      description: List of all transfer errors.
                      items:
                        type: object
                        properties:
                          scope:
                            type: string
                            description: The scope of the transfer.
                          name:
                            type: string
                            description: The name of the lock.
                          rse_id:
                            type: string
                            description: The rse_id of the transfered lock.
                          rse:
                            type: object
                            description: Information about the rse of the transfered lock.
                          attempts:
                            type: integer
                            description: The number of attempts.
                          last_error:
                            type: string
                            description: The last error that occured.
                          last_source:
                            type: string
                            description: The last source.
                          sources:
                            type: array
                            description: All available rse sources.
                          last_time:
                            type: string
                            description: The time of the last transfer.
          401:
            description: Invalid Auth Token
          404:
            description: No rule found for the given id
          406:
            description: Not acceptable.
        """
        analysis = examine_replication_rule(rule_id, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        return Response(render_json(**analysis), content_type='application/json')


def blueprint():
    bp = AuthenticatedBlueprint('rules', __name__, url_prefix='/rules')

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

    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
