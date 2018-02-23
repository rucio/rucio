#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2018

import json
from logging import getLogger, StreamHandler, DEBUG
from flask import Flask, Blueprint, Response, request
from flask.views import MethodView

from rucio.api.heartbeat import list_heartbeats
from rucio.common.utils import APIEncoder
from rucio.web.rest.flaskapi.v1.common import before_request, after_request


LOGGER = getLogger("rucio.heartbeat")
SH = StreamHandler()
SH.setLevel(DEBUG)
LOGGER.addHandler(SH)


class Heartbeat(MethodView):
    """ REST API for Heartbeats. """

    def get(self):
        """
        List all heartbeats.

        .. :quickref: Heartbeat; List heartbeats.

        :resheader Content-Type: application/json
        :status 200: OK.
        :status 401: Invalid Auth Token.
        :returns: List of heartbeats.
        """

        return Response(json.dumps(list_heartbeats(issuer=request.environ.get('issuer')),
                                   cls=APIEncoder, content_type="application/json"))


"""----------------------
   Web service startup
----------------------"""
bp = Blueprint('heartbeat', __name__)

heartbeat_view = Heartbeat.as_view('heartbeat')
bp.add_url_rule('/', view_func=heartbeat_view, methods=['get', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.before_request(before_request)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/heartbeats')
    return doc_app


if __name__ == "__main__":
    application.run()
