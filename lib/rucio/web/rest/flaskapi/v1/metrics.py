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

from flask import Flask, Blueprint
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView
from rucio.core.monitor import generate_prometheus_metrics


class Metrics(ErrorHandlingMethodView):
    def get(self):
        return generate_prometheus_metrics()


def blueprint(standalone=False):
    bp = Blueprint('metrics', __name__, url_prefix='/' if standalone else '/metrics')
    metrics_view = Metrics.as_view('metrics')
    bp.add_url_rule('/', view_func=metrics_view, methods=['get', ])
    return bp


def make_doc():
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
