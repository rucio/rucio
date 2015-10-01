# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

from rucio.common.exception import ConfigNotFound
from rucio.db.sqla import models
from rucio.db.sqla.session import read_session, transactional_session


@read_session
def sections(session=None):
    """
    Return a list of the sections available.

    :param session: The database session in use.
    :returns: ['section_name', ...]
    """

    tmp = session.query(models.Config.section).distinct().all()

    res = []
    for t in tmp:
        res.append(t[0])

    return res


@transactional_session
def add_section(section, session=None):
    """
    Add a section to the configuration.
    :param session: The database session in use.
    :param section: The name of the section.
    """

    raise NotImplementedError('Irrelevant - sections cannot exist without options')


@read_session
def has_section(section, session=None):
    """
    Indicates whether the named section is present in the configuration.

    :param section: The name of the section.
    :param session: The database session in use.
    :returns: True/False
    """

    query = session.query(models.Config).filter_by(section=section)

    return True if query.first() else False


@read_session
def options(section, session=None):
    """
    Returns a list of options available in the specified section.

    :param section: The name of the section.
    :param session: The database session in use.
    :returns: ['option', ...]
    """

    tmp = session.query(models.Config.opt).filter_by(section=section).distinct().all()

    res = []
    for t in tmp:
        res.append(t[0])

    return res


@read_session
def has_option(section, option, session=None):
    """
    Check if the given section exists and contains the given option.

    :param section: The name of the section.
    :param option: The name of the option.
    :param session: The database session in use.
    :returns: True/False
    """

    query = session.query(models.Config).filter_by(section=section, opt=option)

    return True if query.first() else False


@read_session
def get(section, option, session=None):
    """
    Get an option value for the named section. Value can be auto-coerced to string, int, float, bool, None.

    Caveat emptor: Strings, regardless the case, matching 'on'/off', 'true'/'false', 'yes'/'no' are converted to bool.
                   0/1 are converted to int, and not to bool.

    :param section: The name of the section.
    :param option: The name of the option.
    :param session: The database session in use.
    :returns: The auto-coerced value.
    """

    tmp = session.query(models.Config.value).filter_by(section=section, opt=option).first()

    if tmp is not None:
        return __convert_type(tmp[0])
    else:
        raise ConfigNotFound()


@read_session
def items(section, session=None):
    """
    Return a list of (option, value) pairs for each option in the given section. Values are auto-coerced as in get().

    :param section: The name of the section.
    :param value: The content of the value.
    :param session: The database session in use.
    :returns: [('option', auto-coerced value), ...]
    """

    tmp = session.query(models.Config.opt, models.Config.value).filter_by(section=section).all()

    res = []
    for t in tmp:
        res.append((t[0], __convert_type(t[1])))

    return res


@transactional_session
def set(section, option, value, session=None):
    """
    Set the given option to the specified value. If the option doesn't exist, it is created.

    :param section: The name of the section.
    :param option: The name of the option.
    :param value: The content of the value.
    :param session: The database session in use.
    """

    if not has_option(section=section, option=option, session=session):
        new_option = models.Config(section=section, opt=option, value=value)
        new_option.save(session=session)
    else:
        old_option = models.Config.__history_mapper__.class_(section=section,
                                                             opt=option,
                                                             value=session.query(models.Config.value).filter_by(section=section,
                                                                                                                opt=option).first()[0])
        old_option.save(session=session)
        session.query(models.Config).filter_by(section=section, opt=option).update({'value': str(value)})


@transactional_session
def remove_section(section, session=None):
    """
    Remove the specified section from the specified section.

    :param section: The name of the section.
    :param session: The database session in use.
    :returns: True/False.
    """

    if not has_section(section=section, session=session):
        return False
    else:
        for old in session.query(models.Config.value).filter_by(section=section).all():
            old_option = models.Config.__history_mapper__.class_(section=old[0],
                                                                 opt=old[1],
                                                                 value=old[2])
            old_option.save(session=session)
        session.query(models.Config).filter_by(section=section).delete()
        return True


@transactional_session
def remove_option(section, option, session=None):
    """
    Remove the specified option from the configuration.

    :param section: The name of the section.
    :param option: The name of the option.
    :param session: The database session in use.
    :returns: True/False
    """

    if not has_option(section=section, option=option, session=session):
        return False
    else:
        old_option = models.Config.__history_mapper__.class_(section=section,
                                                             opt=option,
                                                             value=session.query(models.Config.value).filter_by(section=section,
                                                                                                                opt=option).first()[0])
        old_option.save(session=session)
        session.query(models.Config).filter_by(section=section, opt=option).delete()
        return True


def __convert_type(value):
    if value.lower() in ['true', 'yes', 'on']:
        return True
    elif value.lower() in ['false', 'no', 'off']:
        return False

    for c in (int, float):
        try:
            return c(value)
        except:
            pass

    return value
