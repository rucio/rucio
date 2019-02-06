# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2016-2019
# - Martin Barisits <martin.barisits@cern.ch>, 2017-2018
# - Vincent Garonne <vgaronne@gmail.com>, 2017-2018
# - Brian Bockelman <bbockelm@cse.unl.edu>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
#
# PY3K COMPATIBLE

import json
import os
import re

from functools import wraps
try:
    # Python 2
    from ConfigParser import NoOptionError, NoSectionError
except ImportError:
    # Python 3
    from configparser import NoOptionError, NoSectionError
from dogpile.cache import make_region
from dogpile.cache.api import NoValue

from rucio.common.config import config_get
from rucio.common.exception import UndefinedPolicy

REGION = make_region().configure('dogpile.cache.memory',
                                 expiration_time=1800)


def construct_surl_DQ2(dsn, filename):
    """
    Defines relative SURL for new replicas. This method
    contains DQ2 convention. To be used for non-deterministic sites.
    Method imported from DQ2.

    @return: relative SURL for new replica.
    @rtype: str
    """
    # check how many dots in dsn
    fields = dsn.split('.')
    nfields = len(fields)

    if nfields == 0:
        return '/other/other/%s' % (filename)
    elif nfields == 1:
        stripped_dsn = __strip_dsn(dsn)
        return '/other/%s/%s' % (stripped_dsn, filename)
    elif nfields == 2:
        project = fields[0]
        stripped_dsn = __strip_dsn(dsn)
        return '/%s/%s/%s' % (project, stripped_dsn, filename)
    elif nfields < 5 or re.match('user*|group*', fields[0]):
        project = fields[0]
        stripped_dsn = __strip_dsn(dsn)
        return '/%s/%s/%s/%s/%s' % (project, fields[1], fields[2], stripped_dsn, filename)
    else:
        project = fields[0]
        dataset_type = fields[4]
        if nfields == 5:
            tag = 'other'
        else:
            tag = __strip_tag(fields[-1])
        stripped_dsn = __strip_dsn(dsn)
        return '/%s/%s/%s/%s/%s' % (project, dataset_type, tag, stripped_dsn, filename)


def construct_surl_T0(dsn, filename):
    """
    Defines relative SURL for new replicas. This method
    contains Tier0 convention. To be used for non-deterministic sites.

    @return: relative SURL for new replica.
    @rtype: str
    """
    fields = dsn.split('.')
    nfields = len(fields)
    if nfields >= 3:
        return '/%s/%s/%s/%s/%s' % (fields[0], fields[2], fields[1], dsn, filename)
    elif nfields == 1:
        return '/%s/%s/%s/%s/%s' % (fields[0], 'other', 'other', dsn, filename)
    elif nfields == 2:
        return '/%s/%s/%s/%s/%s' % (fields[0], fields[2], 'other', dsn, filename)
    elif nfields == 0:
        return '/other/other/other/other/%s' % (filename)


def construct_surl(dsn, filename, naming_convention=None):
    if naming_convention == 'T0':
        return construct_surl_T0(dsn, filename)
    elif naming_convention == 'DQ2':
        return construct_surl_DQ2(dsn, filename)
    return construct_surl_DQ2(dsn, filename)


def __strip_dsn(dsn):
    """
    Drop the _sub and _dis suffixes for panda datasets from the lfc path
    they will be registered in.
    Method imported from DQ2.
    """

    suffixes_to_drop = ['_dis', '_sub', '_frag']
    fields = dsn.split('.')
    last_field = fields[-1]
    try:
        for suffix in suffixes_to_drop:
            last_field = re.sub('%s.*$' % suffix, '', last_field)
    except IndexError:
        return dsn
    fields[-1] = last_field
    stripped_dsn = '.'.join(fields)
    return stripped_dsn


def __strip_tag(tag):
    """
    Drop the _sub and _dis suffixes for panda datasets from the lfc path
    they will be registered in
    Method imported from DQ2.
    """
    suffixes_to_drop = ['_dis', '_sub', '_tid']
    stripped_tag = tag
    try:
        for suffix in suffixes_to_drop:
            stripped_tag = re.sub('%s.*$' % suffix, '', stripped_tag)
    except IndexError:
        return stripped_tag
    return stripped_tag


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
    # Ideally the function mapping sdhould not be static, but would be defined in a policy package
    mapping = {'atlas': ['get_scratch_policy', 'archive_localgroupdisk_datasets', 'get_dest_path']}
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
