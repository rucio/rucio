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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2013
# - Vincent Garonne <vgaronne@gmail.com>, 2012-2018
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013
# - Brian Bockelman <bbockelm@cse.unl.edu>, 2018
# - Martin Barisits <martin.barisits@cern.ch>, 2018
#
# PY3K COMPATIBLE

"""
Get the configuration file from /opt/rucio/etc/rucio.cfg
If it is not there, get it from $RUCIO_HOME
If it is not there, get it from $VIRTUAL_ENV
If it is not there, except.
"""

import os
import json
import sys

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

from rucio.common import exception


def config_get(section, option, raise_exception=True, default=None):
    """
    Return the string value for a given option in a section

    :param section: the named section.
    :param option: the named option.
    :param raise_exception: Boolean to raise or not NoOptionError or NoSectionError.
    :param default: the default value if not found.
.
    :returns: the configuration value.
    """
    try:
        return __CONFIG.get(section, option)
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError) as err:
        if raise_exception and default is None:
            raise err
        return default


def config_has_section(section):
    """
    Indicates whether the named section is present in the configuration. The DEFAULT section is not acknowledged.)

    :param section: Name of section in the Rucio config to verify.
    :returns: True if the section exists in the configuration; False otherwise
    """
    return __CONFIG.has_section(section)


def config_add_section(section):
    """
    Add a new section to the configuration object.  Throws DuplicateSectionError if it already exists.

    :param section: Name of section in the Rucio config to add.
    :returns: None
    """
    return __CONFIG.add_section(section)


def config_get_int(section, option):
    """Return the integer value for a given option in a section"""
    return __CONFIG.getint(section, option)


def config_get_float(section, option):
    """Return the floating point value for a given option in a section"""
    return __CONFIG.getfloat(section, option)


def config_get_bool(section, option, raise_exception=True, default=None):
    """
    Return the boolean value for a given option in a section

    :param section: the named section.
    :param option: the named option.
    :param raise_exception: Boolean to raise or not NoOptionError or NoSectionError.
    :param default: the default value if not found.
.
    :returns: the configuration value.
    """
    try:
        return __CONFIG.getboolean(section, option)
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError) as err:
        if raise_exception:
            raise err
        if default is None:
            return default
        return bool(default)


def config_get_options(section):
    """Return all options from a given section"""
    return __CONFIG.options(section)


def config_get_items(section):
    """Return all (name, value) pairs from a given section"""
    return __CONFIG.items(section)


def config_remove_option(section, option):
    """
    Remove the specified option from a given section.

    :param section: Name of section in the Rucio config.
    :param option: Name of option to remove from Rucio configuration.
    :returns: True if the option existed in the configuration, False otherwise.

    :raises NoSectionError: If the section does not exist.
    """
    return __CONFIG.remove_option(section, option)


def config_set(section, option, value):
    """
    Set a configuration option in a given section.

    :param section: Name of section in the Rucio config.
    :param option: Name of option to set in the Rucio configuration.
    :param value: New value for the option.

    :raises NoSectionError: If the section does not exist.
    """
    return __CONFIG.set(section, option, value)


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


def get_lfn2pfn_algorithm_default():
    """Returns the default algorithm name for LFN2PFN translation for this server."""
    default_lfn2pfn = "hash"
    try:
        default_lfn2pfn = config_get('policy', 'lfn2pfn_algorithm_default')
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
        pass
    return default_lfn2pfn


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

    if 'sphinx' not in sys.modules:
        # test to not fail when build the API doc
        raise Exception('Could not load rucio configuration file rucio.cfg.'
                        'Rucio looks in the following directories for a configuration file, in order:'
                        '\n\t${RUCIO_HOME}/etc/rucio.cfg'
                        '\n\t/opt/rucio/etc/rucio.cfg'
                        '\n\t${VIRTUAL_ENV}/etc/rucio.cfg')
