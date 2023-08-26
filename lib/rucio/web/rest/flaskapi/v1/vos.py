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

from flask import Flask, request

from rucio.api.vo import add_vo, list_vos, recover_vo_root_identity, update_vo
from rucio.common.exception import AccessDenied, AccountNotFound, Duplicate, VONotFound, UnsupportedOperation
from rucio.common.utils import render_json
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import response_headers, check_accept_header_wrapper_flask, \
    try_stream, generate_http_error_flask, ErrorHandlingMethodView, json_parameters, param_get


class VOs(ErrorHandlingMethodView):
    """ List all the VOs in the database. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """
        ---
        summary: List VOs
        tags:
          - VO
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
                      vo:
                        description: The vo.
                        type: string
                      description:
                        description: The description of the vo.
                        type: string
                      email:
                        description: The email for the vo.
                        type: string
                      created_at:
                        description: The date the vo was created.
                        type: string
                        format: date-time
                      updated_at:
                        description: The date the vo was updated.
                        type: string
                        format: date-time

          406:
            description: Not Acceptable
          401:
            description: Invalid Auth Token
          409:
            description: Unsupported operation.
        """
        try:
            def generate(issuer, vo):
                for vo in list_vos(issuer=issuer, vo=vo):
                    yield render_json(**vo) + '\n'

            return try_stream(generate(issuer=request.environ.get('issuer'), vo=request.environ.get('vo')))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except UnsupportedOperation as error:
            return generate_http_error_flask(409, error)


class VO(ErrorHandlingMethodView):
    """ Add and update a VO. """

    def post(self, vo):
        """
        ---
        summary: Add VO
        tags:
          - VO
        parameters:
        - name: vo
          in: path
          description: The vo to add.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  description:
                    description: The description of the VO.
                    type: string
                  email:
                    description: The admin email associated with the VO.
                    type: string
        responses:
          201:
            description: OK
          401:
            description: Invalid Auth Token
          409:
            description: Unsupported operation.
        """
        parameters = json_parameters(optional=True)
        kwargs = {'description': None, 'email': None}
        for keyword in kwargs.keys():
            kwargs[keyword] = param_get(parameters, keyword, default=kwargs[keyword])
        kwargs['issuer'] = request.environ.get('issuer')
        kwargs['vo'] = request.environ.get('vo')

        try:
            add_vo(new_vo=vo, **kwargs)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except (UnsupportedOperation, Duplicate) as error:
            return generate_http_error_flask(409, error)

        return 'Created', 201

    def put(self, vo):
        """
        ---
        summary: Update VO
        tags:
          - VO
        parameters:
        - name: vo
          in: path
          description: The vo to add.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            application/json:
              schema:
                type: object
                properties:
                  description:
                    description: The description of the VO.
                    type: string
                  email:
                    description: The admin email associated with the VO.
                    type: string
        responses:
          200:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: VO not found.
          409:
            description: Unsupported operation.
        """
        parameters = json_parameters()
        try:
            update_vo(updated_vo=vo, parameters=parameters, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except VONotFound as error:
            return generate_http_error_flask(404, error)
        except UnsupportedOperation as error:
            return generate_http_error_flask(409, error)

        return '', 200


class RecoverVO(ErrorHandlingMethodView):
    """ Recover root identity for a VO. """

    def post(self, vo):
        """
        ---
        summary: Recover Root Identity
        tags:
          - VO
        parameters:
        - name: vo
          in: path
          description: The vo to add.
          schema:
            type: string
          style: simple
        requestBody:
          content:
            application/json:
              schema:
                type: object
                required:
                - identity
                - authtype
                - email
                properties:
                  identity:
                    description: Identity key to use.
                    type: string
                  authtype:
                    description: The authtype of the account.
                    type: string
                  email:
                    description: The admin email for the vo.
                    type: string
                  password:
                    description: Password for identity.
                    type: string
                  default:
                    description: Whether to use identity as account default.
                    type: boolean
        responses:
          201:
            description: OK
          401:
            description: Invalid Auth Token
          404:
            description: Account not found.
          409:
            description: Unsupported operation.
        """
        parameters = json_parameters()
        identity = param_get(parameters, 'identity')
        authtype = param_get(parameters, 'authtype')
        email = param_get(parameters, 'email')
        password = param_get(parameters, 'password', default=None)
        default = param_get(parameters, 'default', default=False)

        try:
            recover_vo_root_identity(
                root_vo=vo,
                identity_key=identity,
                id_type=authtype,
                email=email,
                password=password,
                default=default,
                issuer=request.environ.get('issuer'),
                vo=request.environ.get('vo'),
            )
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except AccountNotFound as error:
            return generate_http_error_flask(404, error)
        except Duplicate as error:
            return generate_http_error_flask(409, error)

        return 'Created', 201


def blueprint():
    bp = AuthenticatedBlueprint('vos', __name__, url_prefix='/vos')

    recover_view = RecoverVO.as_view('recover')
    bp.add_url_rule('/<vo>/recover', view_func=recover_view, methods=['post', ])
    vo_view = VO.as_view('vo')
    bp.add_url_rule('/<vo>', view_func=vo_view, methods=['put', 'post'])
    vos_view = VOs.as_view('vos')
    bp.add_url_rule('/', view_func=vos_view, methods=['get', ])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
