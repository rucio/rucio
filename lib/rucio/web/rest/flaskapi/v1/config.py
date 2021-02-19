# -*- coding: utf-8 -*-
# Copyright 2014-2021 CERN
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2018
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018-2021
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Muhammad Aditya Hilmy <didithilmy@gmail.com>, 2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021

from flask import Flask, Blueprint, request as request, jsonify

from rucio.api import config
from rucio.common.exception import ConfigurationError, AccessDenied, ConfigNotFound
from rucio.web.rest.flaskapi.v1.common import request_auth_env, response_headers, check_accept_header_wrapper_flask, \
    generate_http_error_flask, ErrorHandlingMethodView, json_parameters


class Config(ErrorHandlingMethodView):
    """ REST API for full configuration. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self):
        """
        List full configuration.

        .. :quickref: Config; List full config.

        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 406: Not Acceptable.
        """
        res = {}
        for section in config.sections(issuer=request.environ.get('issuer'), vo=request.environ.get('vo')):
            res[section] = {}
            for item in config.items(section, issuer=request.environ.get('issuer'), vo=request.environ.get('vo')):
                res[section][item[0]] = item[1]

        return jsonify(res), 200

    def post(self):
        """
        Create or set the configuration option in the requested section.
        The request body is expected to contain a json {"section": {"option": "value"}}.

        .. :quickref: Config; set config value

        :status 201: Option successfully created or updated.
        :status 400: The input data is invalid or incomplete.
        :status 401: Invalid Auth Token.
        :status 500: Configuration Error.
        """
        parameters = json_parameters()
        for section, section_config in parameters.items():
            if not isinstance(section_config, dict):
                return generate_http_error_flask(400, ValueError.__name__, '')
            for option, value in section_config.items():
                try:
                    config.set(section=section, option=option, value=value, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
                except ConfigurationError:
                    return generate_http_error_flask(400, 'ConfigurationError', f"Could not set value '{value}' for section '{section}' option '{option}'")
        return 'Created', 201


class Section(ErrorHandlingMethodView):
    """ REST API for the sections in the configuration. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, section):
        """
        List configuration of a section

        .. :quickref: Section; List config section.

        :param section: The section name.
        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: Config not found.
        :status 406: Not Acceptable.
        """
        res = {}
        for item in config.items(section, issuer=request.environ.get('issuer'), vo=request.environ.get('vo')):
            res[item[0]] = item[1]

        if res == {}:
            return generate_http_error_flask(
                status_code=404,
                exc=ConfigNotFound.__name__,
                exc_msg=f"No configuration found for section '{section}'"
            )

        return jsonify(res), 200


class OptionGetDel(ErrorHandlingMethodView):
    """ REST API for reading or deleting the options in the configuration. """

    @check_accept_header_wrapper_flask(['application/json'])
    def get(self, section, option):
        """
        Retrieve the value of an option.

        .. :quickref: OptionGetDel; get config value.

        :param section: The section name.
        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 404: Config not found.
        :status 406: Not Acceptable.
        """
        try:
            result = config.get(section=section, option=option, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
            return jsonify(result), 200
        except AccessDenied as error:
            return generate_http_error_flask(401, error, f"Access to '{section}' option '{option}' denied")
        except ConfigNotFound as error:
            return generate_http_error_flask(404, error, f"No configuration found for section '{section}' option '{option}'")

    def delete(self, section, option):
        """
        Delete an option.

        .. :quickref: OptionGetDel; delete an option.

        :status 200: OK.
        :status 401: Invalid Auth Token.
        """
        config.remove_option(section=section, option=option, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
        return '', 200


class OptionSet(ErrorHandlingMethodView):
    """ REST API for setting the options in the configuration. """

    def put(self, section, option, value):
        """
        Set the value of an option.
        If the option does not exist, create it.

        .. :quickref: OptionSet; set config value.

        :status 201: Option successfully created or updated.
        :status 401: Invalid Auth Token.
        """
        try:
            config.set(section=section, option=option, value=value, issuer=request.environ.get('issuer'), vo=request.environ.get('vo'))
            return 'Created', 201
        except ConfigurationError as error:
            return generate_http_error_flask(500, error, f"Could not set value '{value}' for section '{section}' option '{option}'")


def blueprint():
    bp = Blueprint('config', __name__, url_prefix='/config')

    option_set_view = OptionSet.as_view('option_set')
    bp.add_url_rule('/<section>/<option>/<value>', view_func=option_set_view, methods=['put', ])
    option_get_del_view = OptionGetDel.as_view('option_get_del')
    bp.add_url_rule('/<section>/<option>', view_func=option_get_del_view, methods=['get', 'delete'])
    section_view = Section.as_view('section')
    bp.add_url_rule('/<section>', view_func=section_view, methods=['get', ])
    config_view = Config.as_view('config')
    bp.add_url_rule('', view_func=config_view, methods=['get', 'post'])

    bp.before_request(request_auth_env)
    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
