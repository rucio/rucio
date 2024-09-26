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

from typing import TYPE_CHECKING, Any, Optional, TypeVar

from dogpile.cache.api import NoValue
from sqlalchemy import and_, delete, func, select, update

from rucio.common.cache import CacheKey, MemcacheRegion
from rucio.common.exception import ConfigNotFound
from rucio.db.sqla import models
from rucio.db.sqla.session import read_session, transactional_session

T = TypeVar('T')

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.orm import Session


REGION = MemcacheRegion(expiration_time=900)

SECTIONS_CACHE_KEY = 'sections'


@read_session
def sections(
        *,
        use_cache: bool = True,
        expiration_time: int = 900,
        session: "Session"
) -> list[str]:
    """
    Return a list of the sections available.

    :param use_cache: Boolean if the cache should be used.
    :param expiration_time: Time after that the cached value gets ignored.
    :param session: The database session in use.
    :returns: ['section_name', ...]
    """

    all_sections = NoValue()
    if use_cache:
        all_sections = read_from_cache(SECTIONS_CACHE_KEY, expiration_time)
    if isinstance(all_sections, NoValue):
        stmt = select(
            models.Config.section
        ).distinct(
        )
        all_sections = list(session.execute(stmt).scalars().all())
        write_to_cache(SECTIONS_CACHE_KEY, all_sections)

    return all_sections


@transactional_session
def add_section(section: str, *, session: "Session") -> None:
    """
    Add a section to the configuration.
    :param session: The database session in use.
    :param section: The name of the section.
    """

    raise NotImplementedError('Irrelevant - sections cannot exist without options')


@read_session
def has_section(
        section: str,
        *,
        use_cache: bool = True,
        expiration_time: int = 900,
        session: "Session"
) -> bool:
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
        stmt = select(
            models.Config
        ).where(
            models.Config.section == section
        )
        has_section = session.execute(stmt).first() is not None
        write_to_cache(has_section_key, has_section)
    return has_section


@read_session
def options(
        section: str,
        *,
        use_cache: bool = True,
        expiration_time: int = 900,
        session: "Session"
) -> list[str]:
    """
    Returns a list of options available in the specified section.

    :param section: The name of the section.
    :param use_cache: Boolean if the cache should be used.
    :param expiration_time: Time after that the cached value gets ignored.
    :param session: The database session in use.
    :returns: ['option', ...]
    """
    options_key = CacheKey.options(section)
    options = NoValue()
    if use_cache:
        options = read_from_cache(options_key, expiration_time)
    if isinstance(options, NoValue):
        stmt = select(
            models.Config.opt
        ).where(
            models.Config.section == section
        ).distinct()
        options = list(session.execute(stmt).scalars().all())
        write_to_cache(options_key, options)
    return options


@read_session
def has_option(
        section: str,
        option: str,
        *,
        use_cache: bool = True,
        expiration_time: int = 900,
        session: "Session"
) -> bool:
    """
    Check if the given section exists and contains the given option.

    :param section: The name of the section.
    :param option: The name of the option.
    :param use_cache: Boolean if the cache should be used.
    :param expiration_time: Time after that the cached value gets ignored.
    :param session: The database session in use.
    :returns: True/False
    """
    has_option_key = CacheKey.has_option(section, option)
    has_option = NoValue()
    if use_cache:
        has_option = read_from_cache(has_option_key, expiration_time)
    if isinstance(has_option, NoValue):
        stmt = select(
            models.Config
        ).where(
            and_(models.Config.section == section,
                 models.Config.opt == option)
        )
        has_option = session.execute(stmt).first() is not None
        write_to_cache(has_option_key, has_option)
    return has_option


@read_session
def get(
        section: str,
        option: str,
        *,
        default: Optional[T] = None,
        use_cache: bool = True,
        expiration_time: int = 900,
        convert_type_fnc: 'Callable[[str], T]',
        session: "Session"
) -> T:
    """
    Get an option value for the named section. Value can be auto-coerced to string, int, float, bool, None.

    Caveat emptor: Strings, regardless the case, matching 'on'/off', 'true'/'false', 'yes'/'no' are converted to bool.
                   0/1 are converted to int, and not to bool.

    :param section: The name of the section.
    :param option: The name of the option.
    :param default: The default value if no value is found.
    :param use_cache: Boolean if the cache should be used.
    :param expiration_time: Time after that the cached value gets ignored.
    :param convert_type_fnc: A function used to parse the string config value into the desired destination type
    :param session: The database session in use.
    :returns: The auto-coerced value.
    """
    value_key = CacheKey.value(section, option)
    value = NoValue()
    if use_cache:
        value = read_from_cache(value_key, expiration_time)
    if isinstance(value, NoValue):
        stmt = select(
            models.Config.value
        ).where(
            and_(models.Config.section == section,
                 models.Config.opt == option)
        )
        tmp = session.execute(stmt).first()
        if tmp is not None:
            value = convert_type_fnc(tmp[0])
            write_to_cache(value_key, tmp[0])
        elif default is None:
            raise ConfigNotFound
        else:
            value = default
            write_to_cache(value_key, value)  # Also write default to cache
    else:
        value = convert_type_fnc(value)
    return value


@read_session
def items(
        section: str,
        use_cache: bool = True,
        expiration_time: int = 900,
        *,
        convert_type_fnc: 'Callable[[str], T]',
        session: "Session"
) -> list[tuple[str, T]]:
    """
    Return a list of (option, value) pairs for each option in the given section. Values are auto-coerced as in get().

    :param section: The name of the section.
    :param use_cache: Boolean if the cache should be used.
    :param expiration_time: Time after that the cached value gets ignored.
    :param convert_type_fnc: A function used to parse the string config value into the desired destination type
    :param session: The database session in use.
    :returns: [('option', auto-coerced value), ...]
    """
    items_key = CacheKey.items(section)
    items = NoValue()
    if use_cache:
        items = read_from_cache(items_key, expiration_time)
    if isinstance(items, NoValue):
        stmt = select(
            models.Config.opt,
            models.Config.value
        ).where(
            models.Config.section == section
        )
        items = session.execute(stmt).all()
        write_to_cache(items_key, items)
    return [(opt, convert_type_fnc(val)) for opt, val in items]


@transactional_session
def set(
        section: str,
        option: str,
        value: Any,
        *,
        session: "Session"
) -> None:
    """
    Set the given option to the specified value. If the option doesn't exist, it is created.

    :param section: The name of the section.
    :param option: The name of the option.
    :param value: The content of the value.
    :param session: The database session in use.
    """

    if not has_option(section=section, option=option, use_cache=False, session=session):
        section_existed = has_section(section=section)

        new_option = models.Config(section=section, opt=option, value=value)
        new_option.save(session=session)

        delete_from_cache(key=CacheKey.value(section, option))
        delete_from_cache(key=CacheKey.has_option(section, option))
        delete_from_cache(key=CacheKey.items(section))
        if not section_existed:
            delete_from_cache(key=SECTIONS_CACHE_KEY)
            delete_from_cache(key=CacheKey.has_section(section))
    else:
        stmt = select(
            models.Config.value
        ).where(
            and_(models.Config.section == section,
                 models.Config.opt == option)
        )
        old_value = session.execute(stmt).scalar_one_or_none()
        if old_value != str(value):
            old_option = models.ConfigHistory(section=section,
                                              opt=option,
                                              value=old_value)
            old_option.save(session=session)
            stmt = update(
                models.Config
            ).where(
                and_(models.Config.section == section,
                     models.Config.opt == option)
            ).values({
                models.Config.value: str(value)
            })
            session.execute(stmt)
            delete_from_cache(key=CacheKey.value(section, option))
            delete_from_cache(key=CacheKey.items(section))


@transactional_session
def remove_section(section: str, *, session: "Session") -> bool:
    """
    Remove the specified section from the specified section.

    :param section: The name of the section.
    :param session: The database session in use.
    :returns: True/False.
    """

    if not has_section(section=section, session=session):
        return False
    else:
        stmt = select(
            models.Config.value
        ).where(
            models.Config.section == section
        )
        for old in session.execute(stmt).all():
            old_option = models.ConfigHistory(section=old[0],
                                              opt=old[1],
                                              value=old[2])
            old_option.save(session=session)
            delete_from_cache(key=CacheKey.has_option(old[0], old[1]))
            delete_from_cache(key=CacheKey.value(old[0], old[1]))

        stmt = delete(
            models.Config
        ).where(
            models.Config.section == section
        )
        session.execute(stmt)
        delete_from_cache(key=SECTIONS_CACHE_KEY)
        delete_from_cache(key=CacheKey.items(section))
        return True


@transactional_session
def remove_option(section: str, option: str, *, session: "Session") -> bool:
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
        stmt = select(
            models.Config.value
        ).where(
            and_(models.Config.section == section,
                 models.Config.opt == option)
        )
        result = session.execute(stmt).scalar_one_or_none()
        old_option = models.ConfigHistory(section=section,
                                          opt=option,
                                          value=result)
        old_option.save(session=session)

        stmt = delete(
            models.Config
        ).where(
            and_(models.Config.section == section,
                 models.Config.opt == option)
        )
        session.execute(stmt)

        stmt = select(
            func.count()
        ).select_from(
            models.Config
        ).where(
            models.Config.section == section
        )
        if not session.execute(stmt).scalar_one_or_none():
            # we deleted the last config entry in the section. Invalidate the section cache
            delete_from_cache(key=SECTIONS_CACHE_KEY)
            delete_from_cache(key=CacheKey.has_section(section))
        delete_from_cache(key=CacheKey.items(section))
        delete_from_cache(key=CacheKey.has_option(section, option))
        delete_from_cache(key=CacheKey.value(section, option))
        return True


def read_from_cache(key: str, expiration_time: int = 900) -> Any:
    """
    Try to read a value from a cache.

    :param key: Key that stores the value.
    :param expiration_time: Time in seconds that a value should not be older than.
    """
    key = key.replace(' ', '')
    value = REGION.get(key, expiration_time=expiration_time)
    return value


def write_to_cache(key: str, value: Any) -> None:
    """
    Set a value on a key in a cache.

    :param key: Key that stores the value.
    :param value: Value to be stored.
    """
    key = key.replace(' ', '')
    REGION.set(key, value)


def delete_from_cache(key: str) -> None:
    """
    Delete from cache any data stored for the given key

    :param key: Key that stores the value.
    """
    key = key.replace(' ', '')
    REGION.delete(key)
