#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014-2015, 2018

import calendar
import datetime
import json
import traceback
import uuid

from flask import Flask, Blueprint, request
from flask.views import MethodView

from rucio.common.utils import generate_http_error_flask
from rucio.core.trace import trace
from rucio.web.rest.flaskapi.v1.common import after_request

URLS = (
    '/', 'Trace',
)


class Trace(MethodView):

    def post(self):
        """
        Trace endpoint used by the pilot and CLI clients to post data access information.

        .. :quickref: Trace; Send trace.

        :<json dict payload: Dictionary contain the trace information.
        :status 201: Created.
        :status 400: Cannot decode json data.
        :status 500: Internal Error.
        """
        try:
            payload = json.loads(request.data)

            # generate entry timestamp
            payload['traceTimeentry'] = datetime.datetime.utcnow()
            payload['traceTimeentryUnix'] = calendar.timegm(payload['traceTimeentry'].timetuple()) + payload['traceTimeentry'].microsecond / 1e6

            # guess client IP
            payload['ip'] = request.environ.get('HTTP_X_FORWARDED_FOR')
            if payload['ip'] is None:
                payload['ip'] = request.remote_addr

            # generate unique ID
            payload['traceId'] = str(uuid.uuid4()).replace('-', '').lower()

            trace(payload=payload)

        except ValueError:
            return generate_http_error_flask(400, 'ValueError', 'Cannot decode json parameter list')
        except Exception, e:
            print traceback.format_exc()
            return e, 500

        return "Created", 201


"""----------------------
   Web service startup
----------------------"""
bp = Blueprint('trace', __name__)

trace_view = Trace.as_view('trace')
bp.add_url_rule('/', view_func=trace_view, methods=['post', ])

application = Flask(__name__)
application.register_blueprint(bp)
application.after_request(after_request)


def make_doc():
    """ Only used for sphinx documentation to add the prefix """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(bp, url_prefix='/traces')
    return doc_app


if __name__ == "__main__":
    application.run()
