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

from rucio.api import permission
from rucio.common import exception
from rucio.core import config
from rucio.db.sqla.session import read_session, transactional_session

"""
ConfigParser compatible interface.

- File handling methods unnecessary.
- Convenience methods getint/getfloat/getboolean are superseded by auto-coercing get.
"""


@read_session
def sections(issuer=None, vo='def', session=None):
    """
    Return a list of the sections available.

    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    :returns: ['section_name', ...]
    """

    kwargs = {'issuer': issuer}
    if not permission.has_permission(issuer=issuer, vo=vo, action='config_sections', kwargs=kwargs, session=session):
        raise exception.AccessDenied('%s cannot retrieve sections' % issuer)
    return config.sections(session=session)


@transactional_session
def add_section(section, issuer=None, vo='def', session=None):
    """
    Add a section to the configuration.

    :param section: The name of the section.
    :param issuer: The issuer account.
    :param session: The database session in use.
    :param vo: The VO to act on.
    """

    kwargs = {'issuer': issuer, 'section': section}
    if not permission.has_permission(issuer=issuer, vo=vo, action='config_add_section', kwargs=kwargs, session=session):
        raise exception.AccessDenied('%s cannot add section %s' % (issuer, section))
    return config.add_section(section, session=session)


@read_session
def has_section(section, issuer=None, vo='def', session=None):
    """
    Indicates whether the named section is present in the configuration.

    :param section: The name of the section.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    :returns: True/False
    """

    kwargs = {'issuer': issuer, 'section': section}
    if not permission.has_permission(issuer=issuer, vo=vo, action='config_has_section', kwargs=kwargs, session=session):
        raise exception.AccessDenied('%s cannot check existence of section %s' % (issuer, section))
    return config.has_section(section, session=session)


@read_session
def options(section, issuer=None, vo='def', session=None):
    """
    Returns a list of options available in the specified section.

    :param section: The name of the section.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    :returns: ['option', ...]
    """

    kwargs = {'issuer': issuer, 'section': section}
    if not permission.has_permission(issuer=issuer, vo=vo, action='config_options', kwargs=kwargs, session=session):
        raise exception.AccessDenied('%s cannot retrieve options from section %s' % (issuer, section))
    return config.options(section, session=session)


@read_session
def has_option(section, option, issuer=None, vo='def', session=None):
    """
    Check if the given section exists and contains the given option.

    :param section: The name of the section.
    :param option: The name of the option.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    :returns: True/False
    """

    kwargs = {'issuer': issuer, 'section': section, 'option': option}
    if not permission.has_permission(issuer=issuer, vo=vo, action='config_has_option', kwargs=kwargs, session=session):
        raise exception.AccessDenied('%s cannot check existence of option %s from section %s' % (issuer, option, section))
    return config.has_option(section, option, session=session)


@read_session
def get(section, option, issuer=None, vo='def', session=None):
    """
    Get an option value for the named section. Value can be auto-coerced to int, float, and bool; string otherwise.

    Caveat emptor: Strings, regardless the case, matching 'on'/off', 'true'/'false', 'yes'/'no' are converted to bool.
                   0/1 are converted to int, and not to bool.

    :param section: The name of the section.
    :param option: The name of the option.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    :returns: The auto-coerced value.
    """

    kwargs = {'issuer': issuer, 'section': section, 'option': option}
    if not permission.has_permission(issuer=issuer, vo=vo, action='config_get', kwargs=kwargs, session=session):
        raise exception.AccessDenied('%s cannot retrieve option %s from section %s' % (issuer, option, section))
    return config.get(section, option, session=session)


@read_session
def items(section, issuer=None, vo='def', session=None):
    """
    Return a list of (option, value) pairs for each option in the given section. Values are auto-coerced as in get().

    :param section: The name of the section.
    :param value: The content of the value.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    :returns: [('option', auto-coerced value), ...]
    """

    kwargs = {'issuer': issuer, 'section': section}
    if not permission.has_permission(issuer=issuer, vo=vo, action='config_items', kwargs=kwargs, session=session):
        raise exception.AccessDenied('%s cannot retrieve options and values from section %s' % (issuer, section))
    return config.items(section, session=session)


@transactional_session
def set(section, option, value, issuer=None, vo='def', session=None):
    """
    Set the given option to the specified value.

    :param section: The name of the section.
    :param option: The name of the option.
    :param value: The content of the value.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """

    kwargs = {'issuer': issuer, 'section': section, 'option': option, 'value': value}
    if not permission.has_permission(issuer=issuer, vo=vo, action='config_set', kwargs=kwargs, session=session):
        raise exception.AccessDenied('%s cannot set option %s to %s in section %s' % (issuer, option, value, section))
    return config.set(section, option, value, session=session)


@transactional_session
def remove_section(section, issuer=None, vo='def', session=None):
    """
    Remove the specified option from the specified section.

    :param section: The name of the section.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    :returns: True/False.
    """

    kwargs = {'issuer': issuer, 'section': section}
    if not permission.has_permission(issuer=issuer, vo=vo, action='config_remove_section', kwargs=kwargs, session=session):
        raise exception.AccessDenied('%s cannot remove section %s' % (issuer, section))
    return config.remove_section(section, session=session)


@transactional_session
def remove_option(section, option, issuer=None, vo='def', session=None):
    """
    Remove the specified section from the configuration.

    :param section: The name of the section.
    :param option: The name of the option.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    :returns: True/False
    """

    kwargs = {'issuer': issuer, 'section': section, 'option': option}
    if not permission.has_permission(issuer=issuer, vo=vo, action='config_remove_option', kwargs=kwargs, session=session):
        raise exception.AccessDenied('%s cannot remove option %s from section %s' % (issuer, option, section))
    return config.remove_option(section, option, session=session)
