# -*- coding: utf-8 -*-
# Copyright 2016-2020 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from json import loads, dumps
from traceback import format_exc

from flask import Flask, Blueprint, Response, request
from flask.views import MethodView

from rucio.api.lifetime_exception import list_exceptions, add_exception, update_exception
from rucio.common.exception import LifetimeExceptionNotFound, UnsupportedOperation, InvalidObject, RucioException, AccessDenied, LifetimeExceptionDuplicate
from rucio.common.utils import APIEncoder
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, check_accept_header_wrapper_flask, try_stream
from rucio.web.rest.utils import generate_http_error_flask


class LifetimeException(MethodView):
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
        :status 500: Internal Error.
        """
        try:
            def generate(vo):
                for exception in list_exceptions(vo=vo):
                    yield dumps(exception, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except LifetimeExceptionNotFound as error:
            return generate_http_error_flask(404, 'LifetimeExceptionNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500

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
        :status 500: Internal Error.
        :returns: The id for the newly created execption.
        """
        json_data = request.data
        dids, pattern, comments, expires_at = [], None, None, None
        try:
            params = loads(json_data)
            if 'dids' in params:
                dids = params['dids']
            if 'pattern' in params:
                pattern = params['pattern']
            if 'comments' in params:
                comments = params['comments']
            if 'expires_at' in params:
                expires_at = params['expires_at']
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')

        try:
            exception_id = add_exception(dids=dids, account=request.environ.get('issuer'), vo=request.environ.get('vo'),
                                         pattern=pattern, comments=comments, expires_at=expires_at)
        except InvalidObject as error:
            return generate_http_error_flask(400, 'InvalidObject', error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except LifetimeExceptionDuplicate as error:
            return generate_http_error_flask(409, 'LifetimeExceptionDuplicate', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500
        return Response(dumps(exception_id), status=201, content_type="application/json")


class LifetimeExceptionId(MethodView):
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
        :status 500: Internal Error.
        :returns: List of exceptions.
        """
        try:
            def generate(vo):
                for exception in list_exceptions(exception_id, vo=vo):
                    yield dumps(exception, cls=APIEncoder) + '\n'

            return try_stream(generate(vo=request.environ.get('vo')))
        except LifetimeExceptionNotFound as error:
            return generate_http_error_flask(404, 'LifetimeExceptionNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500

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
        :Status 500: Internal Error.
        """
        json_data = request.data
        try:
            params = loads(json_data)
        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')
        try:
            state = params['state']
        except KeyError:
            state = None
        try:
            update_exception(exception_id=exception_id, state=state, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        except UnsupportedOperation as error:
            return generate_http_error_flask(400, 'UnsupportedOperation', error.args[0])
        except AccessDenied as error:
            return generate_http_error_flask(401, 'AccessDenied', error.args[0])
        except LifetimeExceptionNotFound as error:
            return generate_http_error_flask(404, 'LifetimeExceptionNotFound', error.args[0])
        except RucioException as error:
            return generate_http_error_flask(500, error.__class__.__name__, error.args[0])
        except Exception as error:
            print(format_exc())
            return str(error), 500
        return 'Created', 201


def blueprint():
    bp = Blueprint('lifetime_exception', __name__, url_prefix='/lifetime_exceptions')

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
