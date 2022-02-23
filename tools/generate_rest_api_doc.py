#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2022 CERN
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
# - Joel Dierkes <joel.dierkes@cern.ch>, 2022

from apispec import APISpec
from apispec_webframeworks.flask import FlaskPlugin
from rucio.vcsversion import VERSION_INFO
from rucio.web.rest.flaskapi.v1.main import application

spec = APISpec(
    title="Rucio",
    version=VERSION_INFO['version'],
    openapi_version="3.0.2",
    plugins=[FlaskPlugin()],
)

with application.test_request_context():
    for view_func in application.view_functions.values():
        spec.path(view=view_func)
print(spec.to_yaml())
