#!/usr/bin/env python
# Copyright 2018 CERN for the benefit of the ATLAS collaboration.
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
#
# PY3K COMPATIBLE

import json
from logging import getLogger, StreamHandler, DEBUG
from flask import Flask, Blueprint, Response, request as request
from flask.views import MethodView
from traceback import format_exc

from rucio.api import config
from rucio.common.exception import ConfigurationError
from rucio.common.utils import generate_http_error_flask
from rucio.web.rest.flaskapi.v1.common import before_request, after_request, check_accept_header_wrapper_flask


LOGGER = getLogger("rucio.config")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)

URLS = ('/(.+)/(.+)/(.*)', 'OptionSet',
        '/(.+)/(.+)', 'OptionGetDel',
        '/(.+)', 'Section',
        '', 'Config')


class Config(MethodView):
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
        :status 500: Internal Error.
        """

        res = {}
        for section in config.sections(issuer=request.environ.get('issuer')):
            res[section] = {}
            for item in config.items(section, issuer=request.environ.get('issuer')):
                res[section][item[0]] = item[1]

        return Response(json.dumps(res), content_type="application/json")


class Section(MethodView):
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
        :status 500: Internal Error.
        """

        res = {}
        for item in config.items(section, issuer=request.environ.get('issuer')):
            res[item[0]] = item[1]

        if res == {}:
            return generate_http_error_flask(404, 'ConfigNotFound', 'No configuration found for section \'%s\'' % section)

        return Response(json.dumps(res), content_type="application/json")


class OptionGetDel(MethodView):
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
        :status 500: Internal Error.
        """

        try:
            return Response(json.dumps(config.get(section=section, option=option, issuer=request.environ.get('issuer'))), content_type="application/json")
        except Exception:
            return generate_http_error_flask(404, 'ConfigNotFound', 'No configuration found for section \'%s\' option \'%s\'' % (section, option))

    def delete(self, section, option):
        """
        Delete an option.

        .. :quickref: OptionGetDel; delete an option.

        :status 200: OK.
        :status 401: Invalid Auth Token.
        :status 500: Internal Error.
        """

        config.remove_option(section=section, option=option, issuer=request.environ.get('issuer'))


class OptionSet(MethodView):
    """ REST API for setting the options in the configuration. """

    def put(self, section, option, value):
        """
        Set the value of an option.
        If the option does not exist, create it.

        .. :quickref: OptionSet; set config value.

        :status 201: Option successfully created or updated.
        :status 401: Invalid Auth Token.
        :status 500: Configuration Error.
        """

        try:
            config.set(section=section, option=option, value=value, issuer=request.environ.get('issuer'))
        except ConfigurationError:
            return generate_http_error_flask(500, 'ConfigurationError', 'Could not set value \'%s\' for section \'%s\' option \'%s\'' % (value, section, option))
        except Exception as error:
            print(format_exc())
            return error, 500
        return "Created", 201


"""----------------------
   Web service startup
----------------------"""

bp = Blueprint('config', __name__)
option_set_view = OptionSet.as_view('option_set')
bp.add_url_rule('/<section>/<option>/<value>', view_func=option_set_view, methods=['put', ])
option_get_del_view = OptionGetDel.as_view('option_get_del')
bp.add_url_rule('/<section>/<option>', view_func=option_get_del_view, methods=['get', 'delete'])
section_view = Section.as_view('section')
bp.add_url_rule('/<section>', view_func=section_view, methods=['get', ])
config_view = Config.as_view('config')
bp.add_url_rule('/<section>', view_func=config_view, methods=['get', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/configs')
    return doc_app


if __name__ == "__main__":
    application.run()
