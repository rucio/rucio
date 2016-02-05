# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013-2016
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013

"""
Get the configuration file from /opt/rucio/etc/rucio.cfg
If it is not there, get it from $RUCIO_HOME
If it is not there, get it from $VIRTUAL_ENV
If it is not there, except.
"""

import os
import json

import ConfigParser

from rucio.common import exception


def config_get(section, option):
    """Return the string value for a given option in a section"""
    return __CONFIG.get(section, option)


def config_has_section(section):
    """Indicates whether the named section is present in the configuration. The DEFAULT section is not acknowledged.)"""
    return __CONFIG.has_section(section)


def config_get_int(section, option):
    """Return the integer value for a given option in a section"""
    return __CONFIG.getint(section, option)


def config_get_float(section, option):
    """Return the floating point value for a given option in a section"""
    return __CONFIG.getfloat(section, option)


def config_get_bool(section, option):
    """Return the boolean value for a given option in a section"""
    return __CONFIG.getboolean(section, option)


def config_get_options(section):
    """Return all options from a given section"""
    return __CONFIG.options(section)


def config_get_items(section):
    """Return all (name, value) pairs from a given section"""
    return __CONFIG.items(section)


def get_config_dir():
    """Return the rucio configuration directory"""
    configdirs = ['/opt/rucio/etc/', ]

    if 'RUCIO_HOME' in os.environ:
        configdirs.append('%s/etc/' % os.environ['RUCIO_HOME'])

    if 'VIRTUAL_ENV' in os.environ:
        configdirs.append('%s/etc/' % os.environ['VIRTUAL_ENV'])

    for configdir in configdirs:
        if os.path.exists(configdir):
            return configdir


def get_schema_dir():
    """Return the rucio json schema directory"""
    configdir = get_config_dir()
    if configdir:
        jsonschemadir = '%s/schemas/' % configdir
        if os.path.exists(jsonschemadir):
            return jsonschemadir


def get_rse_credentials(path_to_credentials_file=None):
    """ Returns credentials for RSEs. """

    path = ''
    if path_to_credentials_file:  # Use specific file for this connect
        path = path_to_credentials_file
    else:  # Use file defined in th RSEMgr
        if 'RUCIO_HOME' in os.environ:
            path = '%s/etc/rse-accounts.cfg' % os.environ['RUCIO_HOME']
        else:
            path = '/opt/rucio/etc/rse-accounts.cfg'
    try:
        # Load all user credentials
        with open(path) as cred_file:
            credentials = json.load(cred_file)
    except Exception as error:
        raise exception.ErrorLoadingCredentials(error)
    return credentials


__CONFIG = ConfigParser.SafeConfigParser(os.environ)

__CONFIGFILES = list()

if 'RUCIO_HOME' in os.environ:
    __CONFIGFILES.append('%s/etc/rucio.cfg' % os.environ['RUCIO_HOME'])

__CONFIGFILES.append('/opt/rucio/etc/rucio.cfg')

if 'VIRTUAL_ENV' in os.environ:
    __CONFIGFILES.append('%s/etc/rucio.cfg' % os.environ['VIRTUAL_ENV'])

__HAS_CONFIG = False
for configfile in __CONFIGFILES:
    __HAS_CONFIG = __CONFIG.read(configfile) == [configfile]
    if __HAS_CONFIG:
        break

if not __HAS_CONFIG:
    raise Exception('Could not load rucio configuration file rucio.cfg. \
Rucio looks in the following directories for a configuration file, in order:\
\n\t${RUCIO_HOME}/etc/rucio.cfg\n\t/opt/rucio/etc/rucio.cfg\n\t${VIRTUAL_ENV}/etc/rucio.cfg')
