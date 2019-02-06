"""
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2016-2017
 - Thomas Beermann, <thomas.beermann@cern.ch>, 2017
 - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018

 PY3K COMPATIBLE
"""

try:
    from ConfigParser import NoOptionError, NoSectionError
except ImportError:
    from configparser import NoOptionError, NoSectionError
from rucio.common import config

if config.config_has_section('permission'):
    try:
        POLICY = config.config_get('permission', 'policy')
    except (NoOptionError, NoSectionError) as error:
        POLICY = 'generic'
elif config.config_has_section('policy'):
    try:
        POLICY = config.config_get('policy', 'permission')
    except (NoOptionError, NoSectionError) as error:
        POLICY = 'generic'
else:
    POLICY = 'generic'

if POLICY.lower() == 'generic':
    from .generic import *  # NOQA pylint:disable=wildcard-import
elif POLICY.lower() == 'atlas':
    from .atlas import *  # NOQA pylint:disable=wildcard-import
elif POLICY.lower() == 'cms':
    from .cms import *  # NOQA pylint:disable=wildcard-import
else:
    from .generic import *  # NOQA pylint:disable=wildcard-import
