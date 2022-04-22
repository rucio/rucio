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

from rucio.common.logging import setup_logging
from flask import Flask
from rucio.web.rest.flaskapi.v1.metrics import blueprint as metrics_blueprint

# Allow to run the /metrics endpoint as a separate application on a separate PORT

setup_logging()
application = Flask(__name__)
application.register_blueprint(metrics_blueprint(standalone=True))

if __name__ == '__main__':
    application.run()
