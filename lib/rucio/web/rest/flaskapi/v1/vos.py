# -*- coding: utf-8 -*-
# Copyright 2020-2021 CERN
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
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Thomas Beermann <thomas.beermann@cern.ch>, 2021

from flask import Flask, Blueprint, request

from rucio.api.vo import add_vo, list_vos, recover_vo_root_identity, update_vo
from rucio.common.exception import AccessDenied, AccountNotFound, Duplicate, VONotFound, UnsupportedOperation
from rucio.common.utils import render_json
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, check_accept_header_wrapper_flask, \
    try_stream, generate_http_error_flask, ErrorHandlingMethodView, json_parameters, param_get


class VOs(ErrorHandlingMethodView):
    """ List all the VOs in the database. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """ List all VOs.

        .. :quickref: VOs; List all VOs.

        :resheader Content-Type: application/x-json-stream
        :status 200: VOs found.
        :status 401: Invalid Auth Token.
        :status 409: Unsupported operation.
        :returns: A list containing all VOs.

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
        """ Add a VO with a given name.

        .. :quickref: VO; Add a VOs.

        :param vo: VO to be added.
        :<json string description: Desciption of VO.
        :<json string email: Admin email for VO.
        :status 201: VO created successfully.
        :status 401: Invalid Auth Token.
        :status 409: Unsupported operation.
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
        """ Update the details for a given VO

        .. :quickref: VO; Update a VOs.

        :param vo: VO to be updated.
        :<json string description: Desciption of VO.
        :<json string email: Admin email for VO.
        :status 200: VO updated successfully.
        :status 401: Invalid Auth Token.
        :status 404: VO not found.
        :status 409: Unsupported operation.
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
        """ Recover root identity for a given VO

        .. :quickref: RecoverVO; Recover VO root identity.

        :param vo: VO to be recovered.
        :<json string identity: Identity key to use.
        :<json string authtype: Type of identity.
        :<json string email: Admin email for VO.
        :<json string email: Password for identity.
        :<json bool default: Whether to use identity as account default.
        :status 201: VO recovered successfully.
        :status 401: Invalid Auth Token.
        :status 404: Account not found.
        :status 409: Unsupported operation.
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
    bp = Blueprint('vos', __name__, url_prefix='/vos')

    recover_view = RecoverVO.as_view('recover')
    bp.add_url_rule('/<vo>/recover', view_func=recover_view, methods=['post', ])
    vo_view = VO.as_view('vo')
    bp.add_url_rule('/<vo>', view_func=vo_view, methods=['put', 'post'])
    vos_view = VOs.as_view('vos')
    bp.add_url_rule('/', view_func=vos_view, methods=['get', ])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
