#!/usr/bin/env python3
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

import importlib
import logging
from typing import TYPE_CHECKING

from flask import Flask

from rucio.common.config import config_get_list
from rucio.common.exception import ConfigurationError
from rucio.common.logging import setup_logging
from rucio.web.rest.flaskapi.v1.common import CORSMiddleware

if TYPE_CHECKING:
    from collections.abc import Iterable

DEFAULT_ENDPOINTS = {
    'accountlimits',
    'accounts',
    'auth',
    'config',
    'credentials',
    'dids',
    'dirac',
    'export',
    'heartbeats',
    'identities',
    'import',
    'lifetime_exceptions',
    'locks',
    'meta_conventions',
    'ping',
    'redirect',
    'replicas',
    'requests',
    'rses',
    'rules',
    'scopes',
    'subscriptions',
}


def apply_endpoints(app: Flask, modules: "Iterable[str]") -> None:
    for blueprint_module in modules:
        # Legacy patch - TODO Remove in 38.0.0
        if blueprint_module == "meta":
            logging.log(logging.WARNING, "Endpoint `meta` is depreciated and will be removed in future releases")
            blueprint_module = "meta_conventions"
        try:
            # searches for module names locally
            blueprint_module = importlib.import_module('.' + blueprint_module,
                                                       package='rucio.web.rest.flaskapi.v1')
        except ImportError:
            raise ConfigurationError(f'Could not load "{blueprint_module}" provided in the endpoints configuration value')

        if hasattr(blueprint_module, 'blueprint'):
            app.register_blueprint(blueprint_module.blueprint())

            if hasattr(blueprint_module, "blueprint_legacy"):
                app.register_blueprint(blueprint_module.blueprint_legacy())

        else:
            raise ConfigurationError(f'"{blueprint_module}" from the endpoints configuration value did not have a blueprint')

endpoints = set(config_get_list('api', 'endpoints', raise_exception=False, default=[]))

if not endpoints:
    endpoints = DEFAULT_ENDPOINTS

application = Flask(__name__)
application.wsgi_app = CORSMiddleware(application.wsgi_app)
apply_endpoints(application, endpoints)
setup_logging(application)


if __name__ == '__main__':
    application.run()
