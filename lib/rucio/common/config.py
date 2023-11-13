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

"""Provides functions to access the local configuration. The configuration locations are provided by get_config_dirs."""

import configparser
import json
import os
from collections.abc import Callable
from typing import TYPE_CHECKING, overload, Optional, TypeVar, Union

from rucio.common import exception
from rucio.common.exception import ConfigNotFound, DatabaseException

_T = TypeVar('_T')
_U = TypeVar('_U')

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


def convert_to_any_type(value) -> Union[bool, int, float, str]:
    if value.lower() in ['true', 'yes', 'on']:
        return True
    elif value.lower() in ['false', 'no', 'off']:
        return False

    for conv in (int, float):
        try:
            return conv(value)
        except:
            pass

    return value


def _convert_to_boolean(value):
    if isinstance(value, bool):
        return value
    if value.lower() in ['true', 'yes', 'on', '1']:
        return True
    elif value.lower() in ['false', 'no', 'off', '0']:
        return False
    raise ValueError('Not a boolean: %s' % value)


@overload
def config_get(
        section: str,
        option: str,
        *,
        clean_cached: bool = ...,
        check_config_table: bool = ...,
        session: "Optional[Session]" = ...,
        use_cache: bool = ...,
        expiration_time: int = ...,
) -> str:
    ...


@overload
def config_get(
        section: str,
        option: str,
        *,
        default: _T = ...,
        clean_cached: bool = ...,
        check_config_table: bool = ...,
        session: "Optional[Session]" = ...,
        use_cache: bool = ...,
        expiration_time: int = ...,
) -> Union[str, _T]:
    ...


@overload
def config_get(
        section: str,
        option: str,
        raise_exception: bool,
        default: _T = ...,
        *,
        clean_cached: bool = ...,
        check_config_table: bool = ...,
        session: "Optional[Session]" = ...,
        use_cache: bool = ...,
        expiration_time: int = ...,
) -> Union[str, _T]:
    ...


@overload
def config_get(
        section: str,
        option: str,
        *,
        clean_cached: bool = ...,
        check_config_table: bool = ...,
        session: "Optional[Session]" = ...,
        use_cache: bool = ...,
        expiration_time: int = ...,
        convert_type_fnc: Callable[[str], _T],
) -> _T:
    ...


@overload
def config_get(
        section: str,
        option: str,
        *,
        default: _T = ...,
        clean_cached: bool = ...,
        check_config_table: bool = ...,
        session: "Optional[Session]" = ...,
        use_cache: bool = ...,
        expiration_time: int = ...,
        convert_type_fnc: Callable[[str], _U],
) -> Union[_T, _U]:
    ...


@overload
def config_get(
        section: str,
        option: str,
        raise_exception: bool,
        default: _T = ...,
        *,
        clean_cached: bool = ...,
        check_config_table: bool = ...,
        session: "Optional[Session]" = ...,
        use_cache: bool = ...,
        expiration_time: int = ...,
        convert_type_fnc: Callable[[str], _U],
) -> Union[_T, _U]:
    ...


def config_get(
        section: str,
        option: str,
        raise_exception: bool = True,
        default: _U = None,
        clean_cached: bool = False,
        check_config_table: bool = True,
        session: "Optional[Session]" = None,
        use_cache: bool = True,
        expiration_time: int = 900,
        convert_type_fnc: Callable[[str], _T] = lambda x: x,
) -> Union[_T, _U]:
    """
    Return the string value for a given option in a section

    First it looks at the configuration file and, if it is not found, check in the config table only if it is called
    from a server/daemon (and if check_config_table is set).

    :param section: the named section.
    :param option: the named option.
    :param raise_exception: Boolean to raise or not NoOptionError, NoSectionError or RuntimeError.
    :param default: the default value if not found.
    :param clean_cached: Deletes the cached config singleton instance if no config value is found
    :param check_config_table: if not set, avoid looking at config table even if it is called from server/daemon
    :param session: The database session in use. Only used if not found in config file and if it is called from
                    server/daemon
    :param use_cache: Boolean if the cache should be used. Only used if not found in config file and if it is called
                      from server/daemon
    :param expiration_time: Time after that the cached value gets ignored. Only used if not found in config file and if
                            it is called from server/daemon
    :param convert_type_fnc: A function used to parse the string config value into the desired destination type

    :returns: the configuration value.

    :raises NoOptionError
    :raises NoSectionError
    :raises RuntimeError
    """
    try:
        return convert_type_fnc(get_config().get(section, option))
    except (configparser.NoOptionError, configparser.NoSectionError, RuntimeError) as err:
        try:
            legacy_config = get_legacy_config(section, option)
            if legacy_config is not None:
                return convert_type_fnc(legacy_config)
        except RuntimeError:
            pass

        from rucio.common.utils import is_client
        client_mode = is_client()

        if not client_mode and check_config_table:
            try:
                return __config_get_table(section=section, option=option, raise_exception=raise_exception,
                                          default=default, clean_cached=clean_cached, session=session,
                                          use_cache=use_cache, expiration_time=expiration_time,
                                          convert_type_fnc=convert_type_fnc)
            except (ConfigNotFound, DatabaseException, ImportError):
                raise err
        else:
            if raise_exception and default is None:
                raise err
            if clean_cached:
                clean_cached_config()
            return default


def get_legacy_config(section: str, option: str):
    """
    Returns a legacy config value, if it is present.

    :param section: The section of the new config.
    :param option: The option of the new config.
    :returns: The string value of the legacy option if one is found, None otherwise.
    """
    LEGACY_SECTION_NAME = {}
    LEGACY_OPTION_NAME = {}

    section = LEGACY_SECTION_NAME.get(section, section)
    option = LEGACY_OPTION_NAME.get(option, option)

    if config_has_option(section, option):
        return get_config().get(section, option)

    return None


def config_has_section(section: str) -> bool:
    """
    Indicates whether the named section is present in the configuration. The DEFAULT section is not acknowledged.

    :param section: Name of section in the Rucio config to verify.
    :returns: True if the section exists in the configuration; False otherwise
    """
    return get_config().has_section(section)


def config_has_option(section: str, option: str) -> bool:
    """
    Indicates whether the named option is present in the configuration. The DEFAULT section is not acknowledged.

    :param section: Name of section in the Rucio config to verify.
    :param option: Name of option in the Rucio config to verify.
    :returns: True if the section and option exists in the configuration; False otherwise
    """
    return get_config().has_option(section, option)


def config_add_section(section: str):
    """
    Add a new section to the configuration object.  Throws DuplicateSectionError if it already exists.

    :param section: Name of section in the Rucio config to add.
    :returns: None
    """
    return get_config().add_section(section)


@overload
def config_get_int(
        section: str,
        option: str,
        *,
        check_config_table: bool = ...,
        session: "Optional[Session]" = ...,
        use_cache: bool = ...,
        expiration_time: int = ...,
) -> int:
    ...


@overload
def config_get_int(
        section: str,
        option: str,
        *,
        default: int = ...,
        check_config_table: bool = ...,
        session: "Optional[Session]" = ...,
        use_cache: bool = ...,
        expiration_time: int = ...,
) -> int:
    ...


@overload
def config_get_int(
        section: str,
        option: str,
        raise_exception,
        default: _T = ...,
        *,
        check_config_table: bool = ...,
        session: "Optional[Session]" = ...,
        use_cache: bool = ...,
        expiration_time: int = ...,
) -> Union[int, _T]:
    ...


def config_get_int(
        section,
        option,
        raise_exception=True,
        default=None,
        check_config_table=True,
        session=None,
        use_cache=True,
        expiration_time=900,
):
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
    return config_get(
        section,
        option,
        raise_exception=raise_exception,
        default=default,
        check_config_table=check_config_table,
        session=session,
        use_cache=use_cache,
        expiration_time=expiration_time,
        convert_type_fnc=int,
    )


@overload
def config_get_float(
        section: str,
        option: str,
        *,
        check_config_table: bool = ...,
        session: "Optional[Session]" = ...,
        use_cache: bool = ...,
        expiration_time: int = ...,
) -> float:
    ...


@overload
def config_get_float(
        section: str,
        option: str,
        *,
        default: float = ...,
        check_config_table: bool = ...,
        session: "Optional[Session]" = ...,
        use_cache: bool = ...,
        expiration_time: int = ...,
) -> float:
    ...


@overload
def config_get_float(
        section: str,
        option: str,
        raise_exception,
        default: _T = ...,
        *,
        check_config_table: bool = ...,
        session: "Optional[Session]" = ...,
        use_cache: bool = ...,
        expiration_time: int = ...,
) -> Union[float, _T]:
    ...


def config_get_float(
        section,
        option,
        raise_exception=True,
        default=None,
        check_config_table=True,
        session=None,
        use_cache=True,
        expiration_time=900,
):
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
    return config_get(
        section,
        option,
        raise_exception=raise_exception,
        default=default,
        check_config_table=check_config_table,
        session=session,
        use_cache=use_cache,
        expiration_time=expiration_time,
        convert_type_fnc=float,
    )


@overload
def config_get_bool(
        section: str,
        option: str,
        *,
        check_config_table: bool = ...,
        session: "Optional[Session]" = ...,
        use_cache: bool = ...,
        expiration_time: int = ...,
) -> bool:
    ...


@overload
def config_get_bool(
        section: str,
        option: str,
        *,
        default: bool = ...,
        check_config_table: bool = ...,
        session: "Optional[Session]" = ...,
        use_cache: bool = ...,
        expiration_time: int = ...,
) -> bool:
    ...


@overload
def config_get_bool(
        section: str,
        option: str,
        raise_exception,
        default: _T = ...,
        *,
        check_config_table: bool = ...,
        session: "Optional[Session]" = ...,
        use_cache: bool = ...,
        expiration_time: int = ...,
) -> Union[bool, _T]:
    ...


def config_get_bool(
        section,
        option,
        raise_exception=True,
        default=None,
        check_config_table=True,
        session=None,
        use_cache=True,
        expiration_time=900,
):
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
    return config_get(
        section,
        option,
        raise_exception=raise_exception,
        default=default,
        check_config_table=check_config_table,
        session=session,
        use_cache=use_cache,
        expiration_time=expiration_time,
        convert_type_fnc=_convert_to_boolean,
    )


@overload
def config_get_list(
        section: str,
        option: str,
        *,
        check_config_table: bool = ...,
        session: "Optional[Session]" = ...,
        use_cache: bool = ...,
        expiration_time: int = ...,
) -> list[str]:
    ...


@overload
def config_get_list(
        section: str,
        option: str,
        *,
        default: list[str] = ...,
        check_config_table: bool = ...,
        session: "Optional[Session]" = ...,
        use_cache: bool = ...,
        expiration_time: int = ...,
) -> list[str]:
    ...


@overload
def config_get_list(
        section: str,
        option: str,
        raise_exception,
        default: _T = ...,
        *,
        check_config_table: bool = ...,
        session: "Optional[Session]" = ...,
        use_cache: bool = ...,
        expiration_time: int = ...,
) -> Union[list[str], _T]:
    ...


def config_get_list(
        section,
        option,
        raise_exception=True,
        default=None,
        check_config_table=True,
        session=None,
        use_cache=True,
        expiration_time=900,
):
    """
    Return a list for a given option in a section

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
    value = config_get(
        section,
        option,
        raise_exception=raise_exception,
        default=default,
        check_config_table=check_config_table,
        session=session,
        use_cache=use_cache,
        expiration_time=expiration_time,
    )
    if isinstance(value, str):
        value = __convert_string_to_list(value)
    return value


def __convert_string_to_list(string: str) -> list[str]:
    """
    Convert a comma separated string to a list
    :param string: The input string.

    :returns: A list extracted from the string.
    """
    if not string or not string.strip():
        return []
    return [item.strip(' ') for item in string.split(',')]


def __config_get_table(
        section: str,
        option: str,
        *,
        raise_exception: bool = True,
        default: _T = None,
        clean_cached: bool = True,
        session: "Optional[Session]" = None,
        use_cache: bool = True,
        expiration_time: int = 900,
        convert_type_fnc: Optional[Callable[[str], _T]],
) -> _T:
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
                               expiration_time=expiration_time, convert_type_fnc=convert_type_fnc)
    except (ConfigNotFound, DatabaseException, ImportError) as err:
        if raise_exception and default is None:
            raise err
        if clean_cached:
            __CONFIG = None
        return default


def config_get_options(section: str) -> list[str]:
    """Return all options from a given section"""
    return get_config().options(section)


def config_get_items(section: str) -> list[tuple[str, str]]:
    """Return all (name, value) pairs from a given section"""
    return get_config().items(section)


def config_remove_option(section: str, option: str) -> bool:
    """
    Remove the specified option from a given section.

    :param section: Name of section in the Rucio config.
    :param option: Name of option to remove from Rucio configuration.
    :returns: True if the option existed in the configuration, False otherwise.

    :raises NoSectionError: If the section does not exist.
    """
    return get_config().remove_option(section, option)


def config_set(section: str, option: str, value: str):
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
    except (configparser.NoOptionError, configparser.NoSectionError, RuntimeError):
        pass
    return default_lfn2pfn


def get_rse_credentials(path_to_credentials_file: Optional[Union[str, os.PathLike]] = None):
    """ Returns credentials for RSEs. """

    path = ''
    if path_to_credentials_file:  # Use specific file for this connect
        path = path_to_credentials_file
    else:  # Use file defined in th RSEMgr
        for confdir in get_config_dirs():
            p = os.path.join(confdir, 'rse-accounts.cfg')
            if os.path.exists(p):
                path = p
    try:
        # Load all user credentials
        with open(path) as cred_file:
            credentials = json.load(cred_file)
    except Exception as error:
        raise exception.ErrorLoadingCredentials(error)
    return credentials


__CONFIG = None


def get_config() -> configparser.ConfigParser:
    """Factory function for the configuration class. Returns the ConfigParser instance."""
    global __CONFIG
    if __CONFIG is None:
        __CONFIG = Config()
    return __CONFIG.parser


def clean_cached_config():
    """Deletes the cached config singleton instance."""
    global __CONFIG
    __CONFIG = None


class Config:
    """
    The configuration class reading the config file on init, located by using
    get_config_dirs or the use of the RUCIO_CONFIG environment variable.
    """
    def __init__(self):
        self.parser = configparser.ConfigParser()

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
