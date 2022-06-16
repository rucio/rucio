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

from os import environ

from configparser import NoOptionError, NoSectionError

from rucio.common import config, exception

import importlib

# dictionary of schema modules for each VO
schema_modules = {}

# list of unique SCOPE_NAME_REGEXP values from all schemas
scope_name_regexps = []

try:
    multivo = config.config_get_bool('common', 'multi_vo', check_config_table=False)
except (NoOptionError, NoSectionError):
    multivo = False

# multi-VO version loads schema per-VO on demand
# we can't get a list of VOs here because the database might not
# be available as this is imported during the bootstrapping process
if not multivo:
    GENERIC_FALLBACK = 'generic'

    if config.config_has_section('policy'):
        try:
            if 'RUCIO_POLICY_PACKAGE' in environ:
                POLICY = environ['RUCIO_POLICY_PACKAGE'] + ".schema"
            else:
                POLICY = config.config_get('policy', 'package', check_config_table=False) + ".schema"
        except (NoOptionError, NoSectionError):
            # fall back to old system for now
            try:
                POLICY = config.config_get('policy', 'schema', check_config_table=False)
            except (NoOptionError, NoSectionError):
                POLICY = GENERIC_FALLBACK
            POLICY = 'rucio.common.schema.' + POLICY.lower()
    else:
        POLICY = 'rucio.common.schema.' + GENERIC_FALLBACK.lower()

    try:
        module = importlib.import_module(POLICY)
    except ImportError:
        raise exception.PolicyPackageNotFound('Module ' + POLICY + ' not found')

    schema_modules["def"] = module
    scope_name_regexps.append(module.SCOPE_NAME_REGEXP)


def load_schema_for_vo(vo):
    GENERIC_FALLBACK = 'generic_multi_vo'
    if config.config_has_section('policy'):
        try:
            env_name = 'RUCIO_POLICY_PACKAGE_' + vo.upper()
            if env_name in environ:
                POLICY = environ[env_name] + ".schema"
            else:
                POLICY = config.config_get('policy', 'package-' + vo, check_config_table=False) + ".schema"
        except (NoOptionError, NoSectionError):
            # fall back to old system for now
            try:
                POLICY = config.config_get('policy', 'schema', check_config_table=False)
            except (NoOptionError, NoSectionError):
                POLICY = GENERIC_FALLBACK
            POLICY = 'rucio.common.schema.' + POLICY.lower()
    else:
        POLICY = 'rucio.common.schema.' + GENERIC_FALLBACK.lower()

    try:
        module = importlib.import_module(POLICY)
    except ImportError:
        raise exception.PolicyPackageNotFound('Module ' + POLICY + ' not found')

    schema_modules[vo] = module


def validate_schema(name, obj, vo='def'):
    if vo not in schema_modules:
        load_schema_for_vo(vo)
    schema_modules[vo].validate_schema(name, obj)


def get_schema_value(key, vo='def'):
    if vo not in schema_modules:
        load_schema_for_vo(vo)
    return getattr(schema_modules[vo], key)


def get_scope_name_regexps():
    """ returns a list of all unique SCOPE_NAME_REGEXPs from all schemas """

    if len(scope_name_regexps) == 0:
        # load schemas for all VOs here and add unique scope_name_regexps to list
        from rucio.core.vo import list_vos
        vos = list_vos()
        for vo in vos:
            if not vo['vo'] in schema_modules:
                load_schema_for_vo(vo['vo'])
            scope_name_regexp = schema_modules[vo['vo']].SCOPE_NAME_REGEXP
            if scope_name_regexp not in scope_name_regexps:
                scope_name_regexps.append(scope_name_regexp)
    return scope_name_regexps


def insert_scope_name(urls):
    """
    given a tuple of URLs for webpy with '%s' as a placeholder for
    SCOPE_NAME_REGEXP, return a finalised tuple of URLs that will work for all
    SCOPE_NAME_REGEXPs in all schemas
    """

    regexps = get_scope_name_regexps()
    result = []
    for i in range(0, len(urls), 2):
        if "%s" in urls[i]:
            # add a copy for each unique SCOPE_NAME_REGEXP
            for scope_name_regexp in regexps:
                result.append(urls[i] % scope_name_regexp)
                result.append(urls[i + 1])
        else:
            # pass through unmodified
            result.append(urls[i])
            result.append(urls[i + 1])
    return tuple(result)
