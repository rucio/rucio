# -*- coding: utf-8 -*-
# Copyright CERN since 2012
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

"""Provides functions to access the local configuration. The configuration locations are provided by get_config_dirs."""

import os
import json
import sys

from rucio.common.exception import ConfigNotFound, DatabaseException

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser

from rucio.common import exception


def config_get(section, option, raise_exception=True, default=None, clean_cached=False, check_config_table=True,
               session=None, use_cache=True, expiration_time=900):
    """
    Return the string value for a given option in a section

    First it looks at the configuration file and, if it is not found, check in the config table only if it is called
    from a server/daemon (and if check_config_table is set).

    :param section: the named section.
    :param option: the named option.
    :param raise_exception: Boolean to raise or not NoOptionError, NoSectionError or RuntimeError.
    :param default: the default value if not found.
    :param check_config_table: if not set, avoid looking at config table even if it is called from server/daemon
    :param session: The database session in use. Only used if not found in config file and if it is called from
                    server/daemon
    :param use_cache: Boolean if the cache should be used. Only used if not found in config file and if it is called
                      from server/daemon
    :param expiration_time: Time after that the cached value gets ignored. Only used if not found in config file and if
                            it is called from server/daemon

    :returns: the configuration value.

    :raises NoOptionError
    :raises NoSectionError
    :raises RuntimeError
    """
    global __CONFIG
    from rucio.common.utils import is_client
    client_mode = is_client()
    try:
        return get_config().get(section, option)
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError, RuntimeError) as err:
        if not client_mode and check_config_table:
            try:
                return __config_get_table(section=section, option=option, raise_exception=raise_exception,
                                          default=default, clean_cached=clean_cached, session=session,
                                          use_cache=use_cache, expiration_time=expiration_time)
            except (ConfigNotFound, DatabaseException, ImportError):
                raise err
        else:
            if raise_exception and default is None:
                raise err
            if clean_cached:
                __CONFIG = None
            return default


def config_has_section(section):
    """
    Indicates whether the named section is present in the configuration. The DEFAULT section is not acknowledged.)

    :param section: Name of section in the Rucio config to verify.
    :returns: True if the section exists in the configuration; False otherwise
    """
    return get_config().has_section(section)


def config_add_section(section):
    """
    Add a new section to the configuration object.  Throws DuplicateSectionError if it already exists.

    :param section: Name of section in the Rucio config to add.
    :returns: None
    """
    return get_config().add_section(section)


def config_get_int(section, option, raise_exception=True, default=None, check_config_table=True, session=None,
                   use_cache=True, expiration_time=900):
    """
    Return the integer value for a given option in a section

    :param section: the named section.
    :param option: the named option.
    :param raise_exception: Boolean to raise or not NoOptionError, NoSectionError or RuntimeError.
    :param default: the default value if not found.
    :param check_config_table: if not set, avoid looking at config table even if it is called from server/daemon
    :param session: The database session in use. Only used if not found in config file and if it is called from
                    server/daemon
    :param use_cache: Boolean if the cache should be used. Only used if not found in config file and if it is called
                      from server/daemon
    :param expiration_time: Time after that the cached value gets ignored. Only used if not found in config file and if
                            it is called from server/daemon

    :returns: the configuration value.

    :raises NoOptionError
    :raises NoSectionError
    :raises RuntimeError
    :raises ValueError
    """
    from rucio.common.utils import is_client
    client_mode = is_client()
    try:
        return get_config().getint(section, option)
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError, RuntimeError) as err:
        if not client_mode and check_config_table:
            try:
                return int(__config_get_table(section=section, option=option, raise_exception=raise_exception,
                                              default=default, session=session, use_cache=use_cache,
                                              expiration_time=expiration_time))
            except (ConfigNotFound, DatabaseException, ImportError):
                raise err
            except ValueError as err_:
                raise err_
        else:
            if raise_exception and default is None:
                raise err
            try:
                return int(default)
            except ValueError as err_:
                raise err_


def config_get_float(section, option, raise_exception=True, default=None, check_config_table=True, session=None,
                     use_cache=True, expiration_time=900):
    """
    Return the floating point value for a given option in a section

    :param section: the named section.
    :param option: the named option.
    :param raise_exception: Boolean to raise or not NoOptionError, NoSectionError or RuntimeError.
    :param default: the default value if not found.
    :param check_config_table: if not set, avoid looking at config table even if it is called from server/daemon
    :param session: The database session in use. Only used if not found in config file and if it is called from
                    server/daemon
    :param use_cache: Boolean if the cache should be used. Only used if not found in config file and if it is called
                      from server/daemon
    :param expiration_time: Time after that the cached value gets ignored. Only used if not found in config file and if
                            it is called from server/daemon

    :returns: the configuration value.

    :raises NoOptionError
    :raises NoSectionError
    :raises RuntimeError
    :raises ValueError
    """
    from rucio.common.utils import is_client
    client_mode = is_client()
    try:
        return get_config().getfloat(section, option)
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError, RuntimeError) as err:
        if not client_mode and check_config_table:
            try:
                return float(__config_get_table(section=section, option=option, raise_exception=raise_exception,
                                                default=default, session=session, use_cache=use_cache,
                                                expiration_time=expiration_time))
            except (ConfigNotFound, DatabaseException, ImportError):
                raise err
            except ValueError as err_:
                raise err_
        else:
            if raise_exception and default is None:
                raise err
            try:
                return float(default)
            except ValueError as err_:
                raise err_


def config_get_bool(section, option, raise_exception=True, default=None, check_config_table=True, session=None,
                    use_cache=True, expiration_time=900):
    """
    Return the boolean value for a given option in a section

    :param section: the named section.
    :param option: the named option.
    :param raise_exception: Boolean to raise or not NoOptionError, NoSectionError or RuntimeError.
    :param default: the default value if not found.
    :param check_config_table: if not set, avoid looking at config table even if it is called from server/daemon
    :param session: The database session in use. Only used if not found in config file and if it is called from
                    server/daemon
    :param use_cache: Boolean if the cache should be used. Only used if not found in config file and if it is called
                      from server/daemon
    :param expiration_time: Time after that the cached value gets ignored. Only used if not found in config file and if
                            it is called from server/daemon
.
    :returns: the configuration value.

    :raises NoOptionError
    :raises NoSectionError
    :raises RuntimeError
    :raises ValueError
    """
    from rucio.common.utils import is_client
    client_mode = is_client()
    try:
        return get_config().getboolean(section, option)
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError, RuntimeError) as err:
        if not client_mode and check_config_table:
            try:
                return bool(__config_get_table(section=section, option=option, raise_exception=raise_exception,
                                               default=default, session=session, use_cache=use_cache,
                                               expiration_time=expiration_time))
            except (ConfigNotFound, DatabaseException, ImportError):
                raise err
            except ValueError as err_:
                raise err_
        else:
            if raise_exception and default is None:
                raise err
            try:
                return bool(default)
            except ValueError as err_:
                raise err_


def __config_get_table(section, option, raise_exception=True, default=None, clean_cached=False, session=None,
                       use_cache=True, expiration_time=900):
    """
    Search for a section-option configuration parameter in the configuration table

    :param section: the named section.
    :param option: the named option.
    :param raise_exception: Boolean to raise or not ConfigNotFound.
    :param default: the default value if not found.
    :param session: The database session in use.
    :param use_cache: Boolean if the cache should be used.
    :param expiration_time: Time after that the cached value gets ignored.

    :returns: the configuration value from the config table.

    :raises ConfigNotFound
    :raises DatabaseException
    """
    global __CONFIG
    try:
        from rucio.core.config import get as core_config_get
        return core_config_get(section, option, default=default, session=session, use_cache=use_cache,
                               expiration_time=expiration_time)
    except (ConfigNotFound, DatabaseException, ImportError) as err:
        if raise_exception and default is None:
            raise err
        if clean_cached:
            __CONFIG = None
        return default


def config_get_options(section):
    """Return all options from a given section"""
    return get_config().options(section)


def config_get_items(section):
    """Return all (name, value) pairs from a given section"""
    return get_config().items(section)


def config_remove_option(section, option):
    """
    Remove the specified option from a given section.

    :param section: Name of section in the Rucio config.
    :param option: Name of option to remove from Rucio configuration.
    :returns: True if the option existed in the configuration, False otherwise.

    :raises NoSectionError: If the section does not exist.
    """
    return get_config().remove_option(section, option)


def config_set(section, option, value):
    """
    Set a configuration option in a given section.

    :param section: Name of section in the Rucio config.
    :param option: Name of option to set in the Rucio configuration.
    :param value: New value for the option.

    :raises NoSectionError: If the section does not exist.
    """
    return get_config().set(section, option, value)


def get_config_dirs():
    """
    Returns all available configuration directories in order:
    - $RUCIO_HOME/etc/
    - $VIRTUAL_ENV/etc/
    - /opt/rucio/
    """
    configdirs = []

    if 'RUCIO_HOME' in os.environ:
        configdirs.append('%s/etc/' % os.environ['RUCIO_HOME'])

    if 'VIRTUAL_ENV' in os.environ:
        configdirs.append('%s/etc/' % os.environ['VIRTUAL_ENV'])

    configdirs.append('/opt/rucio/etc/')

    return configdirs


def get_lfn2pfn_algorithm_default():
    """Returns the default algorithm name for LFN2PFN translation for this server."""
    default_lfn2pfn = "hash"
    try:
        default_lfn2pfn = config_get('policy', 'lfn2pfn_algorithm_default')
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError, RuntimeError):
        pass
    return default_lfn2pfn


def get_rse_credentials(path_to_credentials_file=None):
    """ Returns credentials for RSEs. """

    path = ''
    if path_to_credentials_file:  # Use specific file for this connect
        path = path_to_credentials_file
    else:  # Use file defined in th RSEMgr
        path = (os.path.join(confdir, 'rse-accounts.cfg') for confdir in get_config_dirs())
        path = next(iter(filter(os.path.exists, path)), None)
    try:
        # Load all user credentials
        with open(path) as cred_file:
            credentials = json.load(cred_file)
    except Exception as error:
        raise exception.ErrorLoadingCredentials(error)
    return credentials


__CONFIG = None


def get_config():
    """Factory function for the configuration class. Returns the ConfigParser instance."""
    global __CONFIG
    if __CONFIG is None:
        __CONFIG = Config()
    return __CONFIG.parser


class Config:
    """
    The configuration class reading the config file on init, located by using
    get_config_dirs or the use of the RUCIO_CONFIG environment variable.
    """
    def __init__(self):
        if sys.version_info < (3, 2):
            self.parser = ConfigParser.SafeConfigParser()
        else:
            self.parser = ConfigParser.ConfigParser()

        if 'RUCIO_CONFIG' in os.environ:
            self.configfile = os.environ['RUCIO_CONFIG']
        else:
            configs = [os.path.join(confdir, 'rucio.cfg') for confdir in get_config_dirs()]
            self.configfile = next(iter(filter(os.path.exists, configs)), None)
            if self.configfile is None:
                raise RuntimeError('Could not load Rucio configuration file. '
                                   'Rucio looked in the following paths for a configuration file, in order:'
                                   '\n\t' + '\n\t'.join(configs))

        if not self.parser.read(self.configfile) == [self.configfile]:
            raise RuntimeError('Could not load Rucio configuration file. '
                               'Rucio tried loading the following configuration file:'
                               '\n\t' + self.configfile)
