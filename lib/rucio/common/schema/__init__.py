# Copyright 2017-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vgaronne@gmail.com>, 2017-2018
# - Edgar Fajardo <emfajard@ucsd.edu>, 2018
# - Martin Barisits <martin.barisits@cern.ch>, 2019
# - James Perry <j.perry@epcc.ed.ac.uk>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020

try:
    from ConfigParser import NoOptionError, NoSectionError
except ImportError:
    from configparser import NoOptionError, NoSectionError

from rucio.common import config, exception

import importlib

# dictionary of schema modules for each VO
schema_modules = {}

# TODO: load schema module for each VO in multi-VO installations

try:
    if config.config_get_bool('common', 'multi_vo'):
        GENERIC_FALLBACK = 'generic_multi_vo'
    else:
        GENERIC_FALLBACK = 'generic'
except (NoOptionError, NoSectionError) as error:
    GENERIC_FALLBACK = 'generic'

if config.config_has_section('policy'):
    try:
        POLICY = config.config_get('policy', 'package') + ".schema"
    except (NoOptionError, NoSectionError) as error:
        # fall back to old system for now
        try:
            POLICY = config.config_get('policy', 'schema')
        except (NoOptionError, NoSectionError) as error:
            POLICY = GENERIC_FALLBACK
        POLICY = 'rucio.common.schema.' + POLICY.lower()
else:
    POLICY = 'rucio.common.schema.' + GENERIC_FALLBACK.lower()

try:
    module = importlib.import_module(POLICY)
except (ImportError) as error:
    raise exception.PolicyPackageNotFound('Module ' + POLICY + ' not found')

schema_modules["def"] = module


# TODO: in both of these functions, verify that named module exists
def validate_schema(name, obj, vo='def'):
    schema_modules[vo].validate_schema(name, obj)


def get_schema_value(key, vo='def'):
    return getattr(schema_modules[vo], key)
