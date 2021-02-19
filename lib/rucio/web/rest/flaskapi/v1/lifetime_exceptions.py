# -*- coding: utf-8 -*-
# Copyright 2016-2021 CERN
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2016-2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018-2021
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

from json import dumps

from flask import Flask, Blueprint, Response, request

from rucio.api.lifetime_exception import list_exceptions, add_exception, update_exception
from rucio.common.exception import LifetimeExceptionNotFound, UnsupportedOperation, InvalidObject, AccessDenied, \
    LifetimeExceptionDuplicate
from rucio.common.utils import APIEncoder
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, check_accept_header_wrapper_flask, \
    try_stream, generate_http_error_flask, ErrorHandlingMethodView, json_parameters, param_get


class LifetimeException(ErrorHandlingMethodView):
    """ REST APIs for Lifetime Model exception. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self):
        """
        Retrieve all exceptions.

        .. :quickref: LifetimeException; Get all exceptions.

        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: Lifetime Exception Not Found.
        :status 406: Not Acceptable.
        """
        try:
            def generate(vo):
                for exception in list_exceptions(vo=vo):
                    yield dumps(exception, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except LifetimeExceptionNotFound as error:
            return generate_http_error_flask(404, error)

    def post(self):
        """
        Create a new Lifetime Model exception.

        .. :quickref: LifetimeException; Create new exception.

        :<json string dids: The list of dids.
        :<json string pattern: The pattern.
        :<json string comments: The comment for the exception.
        :<json string expires_at: The expiration date for the exception.
        :resheader Content-Type: application/json
        :status 201: Created.
        :status 400: Cannot decode json parameter list.
        :status 401: Invalid Auth Token.
        :status 409: Lifetime Exception already exists.
        :returns: The id for the newly created execption.
        """
        parameters = json_parameters()
        try:
            exception_id = add_exception(
                dids=param_get(parameters, 'dids', default=[]),
                account=request.environ.get('issuer'),
                vo=request.environ.get('vo'),
                pattern=param_get(parameters, 'pattern', default=None),
                comments=param_get(parameters, 'comments', default=None),
                expires_at=param_get(parameters, 'expires_at', default=None),
            )
        except InvalidObject as error:
            return generate_http_error_flask(400, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except LifetimeExceptionDuplicate as error:
            return generate_http_error_flask(409, error)

        return Response(dumps(exception_id), status=201, content_type="application/json")


class LifetimeExceptionId(ErrorHandlingMethodView):
    """ REST APIs for Lifetime Model exception. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, exception_id):
        """
        Retrieve an exception.

        .. :quickref: LifetimeExceptionId; Get an exceptions.

        :param exception_id: The exception identifier.
        :resheader Content-Type: application/x-json-stream
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: Lifetime Exception Not Found.
        :status 406: Not Acceptable.
        :returns: List of exceptions.
        """
        try:
            def generate(vo):
                for exception in list_exceptions(exception_id, vo=vo):
                    yield dumps(exception, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except LifetimeExceptionNotFound as error:
            return generate_http_error_flask(404, error)

    def put(self, exception_id):
        """
        Approve/Reject an execption.

        .. :quickref: LifetimeExceptionId; Approve/reject exception.

        :param exception_id: The exception identifier.
        :<json string state: the new state (APPROVED/REJECTED)
        :status 201: Created.
        :status 400: Cannot decode json parameter list.
        :status 401: Invalid Auth Token.
        :status 404: Lifetime Exception Not Found.
        """
        parameters = json_parameters()
        state = param_get(parameters, 'state', default=None)

        try:
            update_exception(exception_id=exception_id, state=state, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except UnsupportedOperation as error:
            return generate_http_error_flask(400, error)
        except AccessDenied as error:
            return generate_http_error_flask(401, error)
        except LifetimeExceptionNotFound as error:
            return generate_http_error_flask(404, error)

        return 'Created', 201


def blueprint():
    bp = Blueprint('lifetime_exceptions', __name__, url_prefix='/lifetime_exceptions')

    lifetime_exception_view = LifetimeException.as_view('lifetime_exception')
    bp.add_url_rule('/', view_func=lifetime_exception_view, methods=['get', 'post'])
    lifetime_exception_id_view = LifetimeExceptionId.as_view('lifetime_exception_id')
    bp.add_url_rule('/<exception_id>', view_func=lifetime_exception_id_view, methods=['get', 'put'])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
