#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 CERN
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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import importlib

from flask import Flask

BLUEPRINT_MODULES = (
    '.account',
    '.account_limit',
    '.archive',
    '.authentication',
    '.config',
    '.credential',
    '.did',
    '.dirac',
    '.exporter',
    '.heartbeat',
    '.identity',
    '.importer',
    '.lifetime_exception',
    '.lock',
    '.meta',
    # '.nongrid_trace',  # loads optional config values
    '.ping',
    '.redirect',
    '.replica',
    '.request',
    '.rse',
    '.rule',
    '.scope',
    '.subscription',
    '.temporary_did',
    '.trace',
    '.vo',
)

application = Flask(__name__)
for bpmod in BLUEPRINT_MODULES:
    bpmod = importlib.import_module(bpmod, package='rucio.web.rest.flaskapi.v1')
    if hasattr(bpmod, 'blueprint'):
        application.register_blueprint(bpmod.blueprint())
    else:
        raise RuntimeError('Module has no blueprint')


if __name__ == '__main__':
    application.run()
