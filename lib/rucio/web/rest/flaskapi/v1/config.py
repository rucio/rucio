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

from typing import TYPE_CHECKING

from flask import Flask, jsonify
from flask import request as request

from rucio.common.exception import AccessDenied, ConfigNotFound, ConfigurationError
from rucio.gateway import config
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, check_accept_header_wrapper_flask, generate_http_error_flask, json_parameters, response_headers

if TYPE_CHECKING:
    from flask.typing import ResponseReturnValue


class Config(ErrorHandlingMethodView):
    """ REST API for full configuration. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self) -> 'ResponseReturnValue':
        """
        ---
        summary: List
        description: "List the full configuration."
        tags:
          - Config
        responses:
          200:
            description: "OK"
            content:
              application/json:
                schema:
                  description: "A dict with the sections as keys and a dict with the configuration as value."
                  type: object
          401:
            description: "Invalid Auth Token"
          406:
            description: "Not acceptable"
        """
        res = {}
        for section in config.sections(issuer=request.environ['issuer'], vo=request.environ['vo']):
            res[section] = {}
            for item in config.items(section, issuer=request.environ['issuer'], vo=request.environ['vo']):
                res[section][item[0]] = item[1]

        return jsonify(res), 200

    def post(self) -> 'ResponseReturnValue':
        """
        ---
        summary: Create
        description: "Create or set the configuration option in the requested section."
        tags:
          - Config
        requestBody:
          content:
            'application/json':
              schema:
                description: "The request body is expected to contain a json {'section': {'option': 'value'}}."
                type: object
        responses:
          201:
            description: "OK"
            content:
              application/json:
                schema:
                  type: string
                  enum: ['Created']
          401:
            description: "Invalid Auth Token"
          400:
            description: "The input data was incomplete or invalid"
          500:
            description: "Configuration error"
        """
        parameters = json_parameters()
        for section, section_config in parameters.items():
            if not isinstance(section_config, dict):
                return generate_http_error_flask(400, ValueError.__name__, '')
            for option, value in section_config.items():
                try:
                    config.set(section=section, option=option, value=value, issuer=request.environ['issuer'], vo=request.environ['vo'])
                except ConfigurationError:
                    return generate_http_error_flask(400, 'ConfigurationError', f"Could not set value '{value}' for section '{section}' option '{option}'")
        return 'Created', 201


class Section(ErrorHandlingMethodView):
    """ REST API for the sections in the configuration. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, section: str) -> 'ResponseReturnValue':
        """
        ---
        summary: List Sections
        tags:
          - Config
        parameters:
        - name: section
          in: path
          description: "The section to return."
          schema:
            type: string
          style: simple
        requestBody:
          content:
            'application/json':
              schema:
                type: object
                required:
                - bytes
                properties:
                  bytes:
                    description: "The new limit in bytes."
                    type: integer
        responses:
          200:
            description: "OK"
            content:
              application/json:
                schema:
                  description: "Dictionary of section options."
                  type: object
          401:
            description: "Invalid Auth Token"
          404:
            description: "Config not found"
          406:
            description: "Not acceptable"
        """
        if config.has_section(section, issuer=request.environ['issuer'], vo=request.environ['vo']):
            res = {}
            for item in config.items(section, issuer=request.environ['issuer'], vo=request.environ['vo']):
                res[item[0]] = item[1]
            return jsonify(res), 200

        else:
            return generate_http_error_flask(
                status_code=404,
                exc=ConfigNotFound.__name__,
                exc_msg=f"No configuration found for section '{section}'"
            )

    def delete(self, section: str) -> 'ResponseReturnValue':
        """
        ---
        summary: Remove an existing section
        tags:
            - Config
        parameters:
        - name: section
            in: path
            description: "The section to remove."
            schema:
            type: string
        responses:
            200:
            description: "OK"
            401:
            description: "Invalid Auth Token"
            404:
            description: "Config not found"
            406:
            description: "Not acceptable"
        """
        if config.has_section(section, issuer=request.environ['issuer'], vo=request.environ['vo']):
            config.remove_section(section, issuer=request.environ['issuer'], vo=request.environ['vo'])
            return '', 200
        else:
            return generate_http_error_flask(
                status_code=404,
                exc=ConfigNotFound.__name__,
                exc_msg=f"No configuration found for section '{section}'"
            )


class OptionGetDel(ErrorHandlingMethodView):
    """ REST API for reading or deleting the options in the configuration. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, section: str, option: str) -> 'ResponseReturnValue':
        """
        ---
        summary: Get option
        description: "Returns the value of an option"
        tags:
          - Config
        parameters:
        - name: section
          in: path
          description: "The section."
          schema:
            type: string
          style: simple
        - name: option
          in: path
          description: "The option of the section."
          schema:
            type: string
          style: simple
        responses:
          200:
            description: "OK"
            content:
              application/json:
                schema:
                  description: "The value of the option"
                  type: string
          401:
            description: "Invalid Auth Token"
          404:
            description: "Config not found"
          406:
            description: "Not acceptable"
        """
        try:
            result = config.get(section=section, option=option, issuer=request.environ['issuer'], vo=request.environ['vo'])
            return jsonify(result), 200
        except AccessDenied as error:
            return generate_http_error_flask(401, error, f"Access to '{section}' option '{option}' denied")
        except ConfigNotFound as error:
            return generate_http_error_flask(404, error, f"No configuration found for section '{section}' option '{option}'")

    def delete(self, section: str, option: str) -> 'ResponseReturnValue':
        """
        ---
        summary: Delete option
        description: "Delete an option of a section."
        tags:
          - Config
        parameters:
        - name: section
          in: path
          description: "The section."
          schema:
            type: string
          style: simple
        - name: option
          in: path
          description: "The option of the section."
          schema:
            type: string
          style: simple
        responses:
          200:
            description: "OK"
          401:
            description: "Invalid Auth Token"
        """
        if config.has_option(section, option, issuer=request.environ['issuer'], vo=request.environ['vo']):
            config.remove_option(section=section, option=option, issuer=request.environ['issuer'], vo=request.environ['vo'])
            return '', 200
        else:
            return generate_http_error_flask(404, ConfigNotFound.__name__, f"No configuration found for section '{section}' option '{option}'")


class OptionSet(ErrorHandlingMethodView):
    """ REST API for setting the options in the configuration. """

    def put(self, section: str, option: str, value: str) -> 'ResponseReturnValue':
        """
        ---
        summary: Create value
        description: "Create or set the value of an option."
        tags:
          - Config
        parameters:
        - name: section
          in: path
          description: "The section."
          schema:
            type: string
          style: simple
        - name: option
          in: path
          description: "The option of the section."
          schema:
            type: string
          style: simple
        - name: value
          in: path
          description: "The value to set."
          schema:
            type: string
          style: simple
        responses:
          201:
            description: "OK"
            content:
              application/json:
                schema:
                  type: string
                  enum: ['Created']
          401:
            description: "Invalid Auth Token"
          500:
            description: "Value could not be set"
            content:
              application/json:
                schema:
                  type: string
                  enum: ['Could not set value {} for section {} option {}']
          """
        try:
            config.set(section=section, option=option, value=value, issuer=request.environ['issuer'], vo=request.environ['vo'])
            return 'Created', 201
        except ConfigurationError as error:
            return generate_http_error_flask(500, error, f"Could not set value '{value}' for section '{section}' option '{option}'")


def blueprint() -> AuthenticatedBlueprint:
    bp = AuthenticatedBlueprint('config', __name__, url_prefix='/config')

    option_set_view = OptionSet.as_view('option_set')
    bp.add_url_rule('/<section>/<option>/<value>', view_func=option_set_view, methods=['put', ])
    option_get_del_view = OptionGetDel.as_view('option_get_del')
    bp.add_url_rule('/<section>/<option>', view_func=option_get_del_view, methods=['get', 'delete'])
    section_view = Section.as_view('section')
    bp.add_url_rule('/<section>', view_func=section_view, methods=['get', 'delete'])
    config_view = Config.as_view('config')
    bp.add_url_rule('', view_func=config_view, methods=['get', 'post'])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
