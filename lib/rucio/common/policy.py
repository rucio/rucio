"""
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Cedric Serfon <cedric.serfon@cern.ch>, 2016-2018
 - Martin Barisits <martin.barisits@cern.ch>, 2017-2018
 - Vincent Garonne <vgaronne@gmail.com>, 2017-2018
 - Brian Bockelman <bbockelm@cse.unl.edu>, 2017
 - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
 - Thomas Beermann <thomas.beermann@cern.ch>, 2021

 PY3K COMPATIBLE
"""

import json
import os

from functools import wraps

try:
    # PY2
    from ConfigParser import NoOptionError, NoSectionError
except ImportError:
    # PY3
    from configparser import NoOptionError, NoSectionError
from dogpile.cache import make_region
from dogpile.cache.api import NoValue

from rucio.common.config import config_get
from rucio.common.exception import UndefinedPolicy

REGION = make_region().configure('dogpile.cache.memory',
                                 expiration_time=1800)


def get_policy():
    policy = REGION.get('policy')
    if isinstance(policy, NoValue):
        try:
            policy = config_get('policy', 'permission')
        except (NoOptionError, NoSectionError):
            policy = 'atlas'
        REGION.set('policy', policy)
    return policy


def get_scratchdisk_lifetime():
    scratchdisk_lifetime = REGION.get('scratchdisk_lifetime')
    if isinstance(scratchdisk_lifetime, NoValue):
        try:
            scratchdisk_lifetime = config_get('policy', 'scratchdisk_lifetime')
            scratchdisk_lifetime = int(scratchdisk_lifetime)
        except (NoOptionError, NoSectionError, ValueError):
            scratchdisk_lifetime = 14
        REGION.set('scratchdisk_lifetime', scratchdisk_lifetime)
    return scratchdisk_lifetime


def get_lifetime_policy():
    lifetime_dict = REGION.get('lifetime_dict')
    if isinstance(lifetime_dict, NoValue):
        lifetime_dict = {'data': [], 'mc': [], 'valid': [], 'other': []}
        try:
            lifetime_dir = config_get('lifetime', 'directory')
        except (NoSectionError, NoOptionError):
            lifetime_dir = '/opt/rucio/etc/policies'
        for dtype in ['data', 'mc', 'valid', 'other']:
            input_file_name = '%s/config_%s.json' % (lifetime_dir, dtype)
            if os.path.isfile(input_file_name):
                with open(input_file_name, 'r') as input_file:
                    lifetime_dict[dtype] = json.load(input_file)
        REGION.set('lifetime_dict', lifetime_dict)
    return lifetime_dict


def policy_filter(function):
    mapping = {'atlas': ['get_scratch_policy', 'archive_localgroupdisk_datasets']}
    policy = get_policy()
    if policy in mapping and function.__name__ in mapping[policy]:
        @wraps(function)
        def new_funct(*args, **kwargs):
            return function(*args, **kwargs)
        return new_funct

    @wraps(function)
    def raise_funct(*args, **kwargs):
        raise UndefinedPolicy
    return raise_funct
