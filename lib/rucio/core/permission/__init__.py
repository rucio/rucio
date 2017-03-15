"""
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2016
 - Thomas Beermann, <thomas.beermann@cern.ch>, 2017

Init
"""

from ConfigParser import NoOptionError, NoSectionError

from rucio.common import config

if config.config_has_section('permission'):

    try:
        POLICY = config.config_get('permission', 'policy')
    except (NoOptionError, NoSectionError) as error:
        POLICY = 'generic'

    if POLICY.lower() == 'generic':
        from rucio.core.permission.generic import *  # NOQA pylint:disable=wildcard-import
    elif POLICY.lower() == 'atlas':
        from rucio.core.permission.atlas import *  # NOQA pylint:disable=wildcard-import
    else:
        from rucio.core.permission.generic import *  # NOQA pylint:disable=wildcard-import
else:
    from rucio.core.permission.generic import *  # NOQA pylint:disable=wildcard-import
