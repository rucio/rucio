"""
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2016-2017
 - Thomas Beermann, <thomas.beermann@cern.ch>, 2017
 - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018
 - James Perry, <j.perry@epcc.ed.ac.uk>, 2019
 - Eli Chadwick, <eli.chadwick@stfc.ac.uk>, 2020

 PY3K COMPATIBLE
"""

try:
    from ConfigParser import NoOptionError, NoSectionError
except ImportError:
    from configparser import NoOptionError, NoSectionError
from rucio.common import config, exception

import importlib

# dictionary of permission modules for each VO
permission_modules = {}

# TODO: load permission module for each VO in multi-VO installations

try:
    if config.config_get_bool('common', 'multi_vo'):
        GENERIC_FALLBACK = 'generic_multi_vo'
    else:
        GENERIC_FALLBACK = 'generic'
except (NoOptionError, NoSectionError) as error:
    GENERIC_FALLBACK = 'generic'

if config.config_has_section('permission'):
    try:
        FALLBACK_POLICY = config.config_get('permission', 'policy')
    except (NoOptionError, NoSectionError) as error:
        FALLBACK_POLICY = GENERIC_FALLBACK
elif config.config_has_section('policy'):
    try:
        FALLBACK_POLICY = config.config_get('policy', 'permission')
    except (NoOptionError, NoSectionError) as error:
        FALLBACK_POLICY = GENERIC_FALLBACK
else:
    FALLBACK_POLICY = GENERIC_FALLBACK

if config.config_has_section('policy'):
    try:
        POLICY = config.config_get('policy', 'package') + ".permission"
    except (NoOptionError, NoSectionError) as error:
        # fall back to old system for now
        POLICY = 'rucio.core.permission.' + FALLBACK_POLICY.lower()
else:
    POLICY = 'rucio.core.permission.' + GENERIC_FALLBACK.lower()


try:
    module = importlib.import_module(POLICY)
except (ImportError) as error:
    raise exception.PolicyPackageNotFound('Module ' + POLICY + ' not found')

permission_modules["def"] = module


def has_permission(issuer, action, kwargs):
    # TODO: determine VO from issuer and call corresponding permission module
    return permission_modules["def"].has_permission(issuer, action, kwargs)
