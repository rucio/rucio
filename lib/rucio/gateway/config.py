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

from typing import Any

from rucio.common import exception
from rucio.common.config import convert_to_any_type
from rucio.common.constants import DEFAULT_VO
from rucio.core import config
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session
from rucio.gateway import permission

"""
ConfigParser compatible interface.

- File handling methods unnecessary.
- Convenience methods getint/getfloat/getboolean are superseded by auto-coercing get.
"""


def sections(issuer: str, vo: str = DEFAULT_VO) -> list[str]:
    """
    Return a list of the sections available.

    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :returns: ['section_name', ...]
    """

    kwargs = {'issuer': issuer}
    with db_session(DatabaseOperationType.READ) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='config_sections', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('%s cannot retrieve sections. %s' % (issuer, auth_result.message))
        return config.sections(session=session)


def has_section(section: str, issuer: str, vo: str = DEFAULT_VO) -> bool:
    """
    Indicates whether the named section is present in the configuration.

    :param section: The name of the section.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :returns: True/False
    """

    kwargs = {'issuer': issuer, 'section': section}
    with db_session(DatabaseOperationType.READ) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='config_has_section', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('%s cannot check existence of section %s. %s' % (issuer, section, auth_result.message))
        return config.has_section(section, session=session, use_cache=False)


def has_option(section: str, option: str, issuer: str, vo: str = DEFAULT_VO) -> bool:
    """
    Check if the given section exists and contains the given option.

    :param section: The name of the section.
    :param option: The name of the option.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :returns: True/False
    """

    kwargs = {'issuer': issuer, 'section': section, 'option': option}
    with db_session(DatabaseOperationType.READ) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='config_has_option', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('%s cannot check existence of option %s from section %s. %s' % (issuer, option, section, auth_result.message))
        return config.has_option(section, option, session=session, use_cache=False)


def get(section: str, option: str, issuer: str, vo: str = DEFAULT_VO) -> Any:
    """
    Get an option value for the named section. Value can be auto-coerced to int, float, and bool; string otherwise.

    Caveat emptor: Strings, regardless the case, matching 'on'/off', 'true'/'false', 'yes'/'no' are converted to bool.
                   0/1 are converted to int, and not to bool.

    :param section: The name of the section.
    :param option: The name of the option.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :returns: The auto-coerced value.
    """

    kwargs = {'issuer': issuer, 'section': section, 'option': option}
    with db_session(DatabaseOperationType.READ) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='config_get', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('%s cannot retrieve option %s from section %s. %s' % (issuer, option, section, auth_result.message))
        return config.get(section, option, session=session, convert_type_fnc=convert_to_any_type)


def items(section: str, issuer: str, vo: str = DEFAULT_VO) -> list[tuple[str, Any]]:
    """
    Return a list of (option, value) pairs for each option in the given section. Values are auto-coerced as in get().

    :param section: The name of the section.
    :param value: The content of the value.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :returns: [('option', auto-coerced value), ...]
    """

    kwargs = {'issuer': issuer, 'section': section}
    with db_session(DatabaseOperationType.READ) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='config_items', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('%s cannot retrieve options and values from section %s. %s' % (issuer, section, auth_result.message))
        return config.items(section, session=session, convert_type_fnc=convert_to_any_type)


def set(section: str, option: str, value: Any, issuer: str, vo: str = DEFAULT_VO) -> None:
    """
    Set the given option to the specified value.

    :param section: The name of the section.
    :param option: The name of the option.
    :param value: The content of the value.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    """

    kwargs = {'issuer': issuer, 'section': section, 'option': option, 'value': value}
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='config_set', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('%s cannot set option %s to %s in section %s. %s' % (issuer, option, value, section, auth_result.message))
        return config.set(section, option, value, session=session)


def remove_section(section: str, issuer: str, vo: str = DEFAULT_VO) -> bool:
    """
    Remove the specified option from the specified section.

    :param section: The name of the section.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :returns: True/False.
    """

    kwargs = {'issuer': issuer, 'section': section}
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='config_remove_section', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('%s cannot remove section %s. %s' % (issuer, section, auth_result.message))
        return config.remove_section(section, session=session)


def remove_option(section: str, option: str, issuer: str, vo: str = DEFAULT_VO) -> bool:
    """
    Remove the specified section from the configuration.

    :param section: The name of the section.
    :param option: The name of the option.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :returns: True/False
    """

    kwargs = {'issuer': issuer, 'section': section, 'option': option}
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='config_remove_option', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('%s cannot remove option %s from section %s. %s' % (issuer, option, section, auth_result.message))
        return config.remove_option(section, option, session=session)
