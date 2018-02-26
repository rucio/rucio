#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2017
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012, 2018
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

from json import dumps
from logging import getLogger, StreamHandler, DEBUG
from flask import Flask, Blueprint, Response
from flask.views import MethodView

from rucio import version
from rucio.web.rest.flaskapi.v1.common import after_request

LOGGER = getLogger("rucio.rucio")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)


class Ping(MethodView):
    '''
    Ping class
    '''

    def get(self):
        """
        Ping the server and retrieve the server version.

        .. :quickref: Ping; Ping the server.

        **Example request**:

        .. sourcecode:: http

            GET /ping HTTP/1.1
            Host: rucio-server.com
            Accept: application/json

        **Example response**:

        .. sourcecode:: http

            HTTP/1.1 200 OK
            Vary: Accept
            Content-Type: application/json

            {"version": "1.15.0"}

        :status 200: OK.
        :status 500: Internal Error.
        :returns: JSON dictionary with the version.
        """
        return Response(dumps({"version": version.version_string()}), content_type="application/json")


# ----------------------
#   Web service startup
# ----------------------
bp = Blueprint('ping', __name__)

ping_view = Ping.as_view('ping')
bp.add_url_rule('/', view_func=ping_view, methods=['get', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/ping')
    return doc_app


if __name__ == "__main__":
    application.run()
