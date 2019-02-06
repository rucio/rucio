# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2019
#
# PY3K COMPATIBLE

from rucio.api import permission
from rucio.common import exception
from rucio.core import config

"""
ConfigParser compatible interface.

- File handling methods unnecessary.
- Convenience methods getint/getfloat/getboolean are superseded by auto-coercing get.
"""


def sections(issuer=None):
    """
    Return a list of the sections available.

    :param issuer: The issuer account.
    :returns: ['section_name', ...]
    """

    kwargs = {'issuer': issuer}
    if not permission.has_permission(issuer=issuer, action='config_sections', kwargs=kwargs):
        raise exception.AccessDenied('%s cannot retrieve sections' % issuer)
    return config.sections()


def add_section(section, issuer=None):
    """
    Add a section to the configuration.

    :param section: The name of the section.
    :param issuer: The issuer account.
    """

    kwargs = {'issuer': issuer, 'section': section}
    if not permission.has_permission(issuer=issuer, action='config_add_section', kwargs=kwargs):
        raise exception.AccessDenied('%s cannot add section %s' % (issuer, section))
    return config.add_section(section)


def has_section(section, issuer=None):
    """
    Indicates whether the named section is present in the configuration.

    :param section: The name of the section.
    :param issuer: The issuer account.
    :returns: True/False
    """

    kwargs = {'issuer': issuer, 'section': section}
    if not permission.has_permission(issuer=issuer, action='config_has_section', kwargs=kwargs):
        raise exception.AccessDenied('%s cannot check existence of section %s' % (issuer, section))
    return config.has_section(section)


def options(section, issuer=None):
    """
    Returns a list of options available in the specified section.

    :param section: The name of the section.
    :param issuer: The issuer account.
    :returns: ['option', ...]
    """

    kwargs = {'issuer': issuer, 'section': section}
    if not permission.has_permission(issuer=issuer, action='config_options', kwargs=kwargs):
        raise exception.AccessDenied('%s cannot retrieve options from section %s' % (issuer, section))
    return config.options(section)


def has_option(section, option, issuer=None):
    """
    Check if the given section exists and contains the given option.

    :param section: The name of the section.
    :param option: The name of the option.
    :param issuer: The issuer account.
    :returns: True/False
    """

    kwargs = {'issuer': issuer, 'section': section, 'option': option}
    if not permission.has_permission(issuer=issuer, action='config_has_option', kwargs=kwargs):
        raise exception.AccessDenied('%s cannot check existence of option %s from section %s' % (issuer, option, section))
    return config.has_option(section, option)


def get(section, option, issuer=None):
    """
    Get an option value for the named section. Value can be auto-coerced to int, float, and bool; string otherwise.

    Caveat emptor: Strings, regardless the case, matching 'on'/off', 'true'/'false', 'yes'/'no' are converted to bool.
                   0/1 are converted to int, and not to bool.

    :param section: The name of the section.
    :param option: The name of the option.
    :param issuer: The issuer account.
    :returns: The auto-coerced value.
    """

    kwargs = {'issuer': issuer, 'section': section, 'option': option}
    if not permission.has_permission(issuer=issuer, action='config_get', kwargs=kwargs):
        raise exception.AccessDenied('%s cannot retrieve option %s from section %s' % (issuer, option, section))
    return config.get(section, option)


def items(section, issuer=None):
    """
    Return a list of (option, value) pairs for each option in the given section. Values are auto-coerced as in get().

    :param section: The name of the section.
    :param value: The content of the value.
    :param issuer: The issuer account.
    :returns: [('option', auto-coerced value), ...]
    """

    kwargs = {'issuer': issuer, 'section': section}
    if not permission.has_permission(issuer=issuer, action='config_items', kwargs=kwargs):
        raise exception.AccessDenied('%s cannot retrieve options and values from section %s' % (issuer, section))
    return config.items(section)


def set(section, option, value, issuer=None):
    """
    Set the given option to the specified value.

    :param section: The name of the section.
    :param option: The name of the option.
    :param value: The content of the value.
    :param issuer: The issuer account.
    """

    kwargs = {'issuer': issuer, 'section': section, 'option': option, 'value': value}
    if not permission.has_permission(issuer=issuer, action='config_set', kwargs=kwargs):
        raise exception.AccessDenied('%s cannot set option %s to %s in section %s' % (issuer, option, value, section))
    return config.set(section, option, value)


def remove_section(section, issuer=None):
    """
    Remove the specified option from the specified section.

    :param section: The name of the section.
    :param issuer: The issuer account.
    :returns: True/False.
    """

    kwargs = {'issuer': issuer, 'section': section}
    if not permission.has_permission(issuer=issuer, action='config_remove_section', kwargs=kwargs):
        raise exception.AccessDenied('%s cannot remove section %s' % (issuer, section))
    return config.remove_section(section)


def remove_option(section, option, issuer=None):
    """
    Remove the specified section from the configuration.

    :param section: The name of the section.
    :param option: The name of the option.
    :param issuer: The issuer account.
    :returns: True/False
    """

    kwargs = {'issuer': issuer, 'section': section, 'option': option}
    if not permission.has_permission(issuer=issuer, action='config_remove_option', kwargs=kwargs):
        raise exception.AccessDenied('%s cannot remove option %s from section %s' % (issuer, option, section))
    return config.remove_option(section, option)
