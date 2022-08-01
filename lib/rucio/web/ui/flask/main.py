#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright CERN since 2012
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

from flask import Flask

from rucio.common.logging import setup_logging
from rucio.web.ui.flask import bp

setup_logging()
application = Flask(__name__)

application.register_blueprint(bp.blueprint())


if __name__ == '__main__':
    application.run()
