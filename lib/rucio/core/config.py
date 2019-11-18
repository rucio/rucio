# Copyright 2014-2019 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2019
# - Vincent Garonne <vgaronne@gmail.com>, 2015-2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Brandon White <bjwhite@fnal.gov>, 2019-2020
#
# PY3K COMPATIBLE

from dogpile.cache import make_region
from dogpile.cache.api import NoValue

from rucio.common.exception import ConfigNotFound
from rucio.common.config import config_get
from rucio.db.sqla import models
from rucio.db.sqla.session import read_session, transactional_session


REGION = make_region().configure('dogpile.cache.memcached',
                                 expiration_time=3600,
                                 arguments={'url': config_get('cache', 'url', False, '127.0.0.1:11211'), 'distributed_lock': True})


@read_session
def sections(use_cache=True, expiration_time=3600, session=None):
    """
    Return a list of the sections available.

    :param use_cache: Boolean if the cache should be used.
    :param expiration_time: Time after that the cached value gets ignored.
    :param session: The database session in use.
    :returns: ['section_name', ...]
    """

    sections_key = 'sections'
    all_sections = NoValue()
    if use_cache:
        all_sections = read_from_cache(sections_key, expiration_time)
    if isinstance(all_sections, NoValue):
        query = session.query(models.Config.section).distinct().all()
        all_sections = [section[0] for section in query]
        write_to_cache(sections_key, all_sections)

    return all_sections


@transactional_session
def add_section(section, session=None):
    """
    Add a section to the configuration.
    :param session: The database session in use.
    :param section: The name of the section.
    """

    raise NotImplementedError('Irrelevant - sections cannot exist without options')


@read_session
def has_section(section, use_cache=True, expiration_time=3600, session=None):
    """
    Indicates whether the named section is present in the configuration.

    :param section: The name of the section.
    :param use_cache: Boolean if the cache should be used.
    :param expiration_time: Time after that the cached value gets ignored.
    :param session: The database session in use.
    :returns: True/False
    """
    has_section_key = 'has_section_%s' % section
    has_section = NoValue()
    if use_cache:
        has_section = read_from_cache(has_section_key, expiration_time)
    if isinstance(has_section, NoValue):
        query = session.query(models.Config).filter_by(section=section)
        has_section = True if query.first() else False
        write_to_cache(has_section_key, has_section)
    return has_section


@read_session
def options(section, use_cache=True, expiration_time=3600, session=None):
    """
    Returns a list of options available in the specified section.

    :param section: The name of the section.
    :param use_cache: Boolean if the cache should be used.
    :param expiration_time: Time after that the cached value gets ignored.
    :param session: The database session in use.
    :returns: ['option', ...]
    """
    options_key = 'options'
    options = NoValue()
    if use_cache:
        options = read_from_cache(options_key, expiration_time)
    if isinstance(options, NoValue):
        query = session.query(models.Config.opt).filter_by(section=section).distinct().all()
        options = [option[0] for option in query]
        write_to_cache(options_key, options)
    return options


@read_session
def has_option(section, option, use_cache=True, expiration_time=3600, session=None):
    """
    Check if the given section exists and contains the given option.

    :param section: The name of the section.
    :param option: The name of the option.
    :param use_cache: Boolean if the cache should be used.
    :param expiration_time: Time after that the cached value gets ignored.
    :param session: The database session in use.
    :returns: True/False
    """
    has_option_key = 'has_option_%s_%s' % (section, option)
    has_option = NoValue()
    if use_cache:
        has_option = read_from_cache(has_option_key, expiration_time)
    if isinstance(has_option, NoValue):
        query = session.query(models.Config).filter_by(section=section, opt=option)
        has_option = True if query.first() else False
        write_to_cache(has_option_key, has_option)
    return has_option


@read_session
def get(section, option, default=None, use_cache=True, expiration_time=3600, session=None):
    """
    Get an option value for the named section. Value can be auto-coerced to string, int, float, bool, None.

    Caveat emptor: Strings, regardless the case, matching 'on'/off', 'true'/'false', 'yes'/'no' are converted to bool.
                   0/1 are converted to int, and not to bool.

    :param section: The name of the section.
    :param option: The name of the option.
    :param default: The default value if no value is found.
    :param use_cache: Boolean if the cache should be used.
    :param expiration_time: Time after that the cached value gets ignored.
    :param session: The database session in use.
    :returns: The auto-coerced value.
    """
    value_key = 'get_%s_%s' % (section, option)
    value = NoValue()
    if use_cache:
        value = read_from_cache(value_key, expiration_time)
    if isinstance(value, NoValue):
        tmp = session.query(models.Config.value).filter_by(section=section, opt=option).first()
        if tmp is not None:
            value = __convert_type(tmp[0])
            write_to_cache(value_key, tmp[0])
        elif default is None:
            raise ConfigNotFound
        else:
            value = default
            write_to_cache(value_key, str(value))  # Also write default to cache
    else:
        value = __convert_type(value)
    return value


@read_session
def items(section, use_cache=True, expiration_time=3600, session=None):
    """
    Return a list of (option, value) pairs for each option in the given section. Values are auto-coerced as in get().

    :param section: The name of the section.
    :param use_cache: Boolean if the cache should be used.
    :param expiration_time: Time after that the cached value gets ignored.
    :param session: The database session in use.
    :returns: [('option', auto-coerced value), ...]
    """
    items_key = 'items_%s' % section
    items = NoValue()
    if use_cache:
        items = read_from_cache(items_key, expiration_time)
    if isinstance(items, NoValue):
        items = session.query(models.Config.opt, models.Config.value).filter_by(section=section).all()
        write_to_cache(items_key, items)
    return [(item[0], __convert_type(item[1])) for item in items]


@transactional_session
def set(section, option, value, session=None):
    """
    Set the given option to the specified value. If the option doesn't exist, it is created.

    :param section: The name of the section.
    :param option: The name of the option.
    :param value: The content of the value.
    :param session: The database session in use.
    """

    if not has_option(section=section, option=option, use_cache=False, session=session):
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

    if not has_option(section=section, option=option, session=session, use_cache=False):
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
    '''
    __convert_type
    '''
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


def read_from_cache(key, expiration_time=3600):
    """
    Try to read a value from a cache.

    :param key: Key that stores the value.
    :param expiration_time: Time in seconds that a value should not be older than.
    """
    key = key.replace(' ', '')
    value = REGION.get(key, expiration_time=expiration_time)
    return value


def write_to_cache(key, value):
    """
    Set a value on a key in a cache.

    :param key: Key that stores the value.
    :param value: Value to be stored.
    """
    key = key.replace(' ', '')
    REGION.set(key, value)
