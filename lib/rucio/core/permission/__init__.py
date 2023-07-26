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

import importlib
from configparser import NoOptionError, NoSectionError
from os import environ
from typing import TYPE_CHECKING

from rucio.common import config, exception
from rucio.common.utils import check_policy_package_version

if TYPE_CHECKING:
    from typing import Optional
    from sqlalchemy.orm import Session

# dictionary of permission modules for each VO
permission_modules = {}

try:
    multivo = config.config_get_bool('common', 'multi_vo')
except (NoOptionError, NoSectionError):
    multivo = False

# in multi-vo mode packages are loaded on demand when needed
if not multivo:
    GENERIC_FALLBACK = 'generic'

    if config.config_has_section('permission'):
        try:
            FALLBACK_POLICY = config.config_get('permission', 'policy')
        except (NoOptionError, NoSectionError):
            FALLBACK_POLICY = GENERIC_FALLBACK
    elif config.config_has_section('policy'):
        try:
            FALLBACK_POLICY = config.config_get('policy', 'permission')
        except (NoOptionError, NoSectionError):
            FALLBACK_POLICY = GENERIC_FALLBACK
    else:
        FALLBACK_POLICY = GENERIC_FALLBACK

    if config.config_has_section('policy'):
        try:
            if 'RUCIO_POLICY_PACKAGE' in environ:
                POLICY = environ['RUCIO_POLICY_PACKAGE']
            else:
                POLICY = config.config_get('policy', 'package', check_config_table=False)
            check_policy_package_version(POLICY)
            POLICY = POLICY + ".permission"
        except (NoOptionError, NoSectionError):
            # fall back to old system for now
            POLICY = 'rucio.core.permission.' + FALLBACK_POLICY.lower()
    else:
        POLICY = 'rucio.core.permission.' + GENERIC_FALLBACK.lower()

    try:
        module = importlib.import_module(POLICY)
    except ImportError:
        raise exception.PolicyPackageNotFound('Module ' + POLICY + ' not found')

    permission_modules["def"] = module


def load_permission_for_vo(vo):
    GENERIC_FALLBACK = 'generic_multi_vo'
    if config.config_has_section('policy'):
        try:
            env_name = 'RUCIO_POLICY_PACKAGE_' + vo.upper()
            if env_name in environ:
                POLICY = environ[env_name]
            else:
                POLICY = config.config_get('policy', 'package-' + vo)
            check_policy_package_version(POLICY)
            POLICY = POLICY + ".permission"
        except (NoOptionError, NoSectionError):
            # fall back to old system for now
            try:
                POLICY = config.config_get('policy', 'permission')
            except (NoOptionError, NoSectionError):
                POLICY = GENERIC_FALLBACK
            POLICY = 'rucio.core.permission.' + POLICY.lower()
    else:
        POLICY = 'rucio.core.permission.' + GENERIC_FALLBACK.lower()

    try:
        module = importlib.import_module(POLICY)
    except ImportError:
        raise exception.PolicyPackageNotFound('Module ' + POLICY + ' not found')

    permission_modules[vo] = module


def has_permission(issuer, action, kwargs, *, session: "Optional[Session]" = None):
    if issuer.vo not in permission_modules:
        load_permission_for_vo(issuer.vo)
    return permission_modules[issuer.vo].has_permission(issuer, action, kwargs, session=session)
