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

import functools
import importlib
import logging
from configparser import NoOptionError, NoSectionError
from os import environ
from typing import TYPE_CHECKING, Any

from jsonschema import ValidationError, validate

from rucio.common import config, exception
from rucio.common.constants import DEFAULT_VO
from rucio.common.plugins import check_policy_module_version
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session

if TYPE_CHECKING:
    from types import ModuleType

LOGGER = logging.getLogger('policy')

# dictionary of schema modules for each VO
schema_modules: dict[str, "ModuleType"] = {}

# list of unique SCOPE_NAME_REGEXP values from all schemas
scope_name_regexps: list[str] = []


# cached function to check for multivo
@functools.cache
def _is_multivo():
    try:
        return config.config_get_bool('common', 'multi_vo', check_config_table=False)
    except (NoOptionError, NoSectionError):
        return False


# cached function to get generic schema module
@functools.cache
def _get_generic_schema_module():
    generic_fallback = 'generic_multi_vo' if _is_multivo() else 'generic'
    return importlib.import_module('rucio.common.schema.' + generic_fallback)


# multi-VO version loads schema per-VO on demand
# we can't get a list of VOs here because the database might not
# be available as this is imported during the bootstrapping process
if not _is_multivo():
    GENERIC_FALLBACK = 'generic'

    try:
        if 'RUCIO_POLICY_PACKAGE' in environ:
            policy = environ['RUCIO_POLICY_PACKAGE']
        else:
            policy = config.config_get('policy', 'package', check_config_table=False, raise_exception=True)
        package_module = importlib.import_module(policy)
        check_policy_module_version(package_module)
        policy = policy + ".schema"
    except (NoOptionError, NoSectionError):
        policy = 'rucio.common.schema.' + GENERIC_FALLBACK.lower()
    except ModuleNotFoundError:
        if config.is_client():
            # policy package may not be required/installed on client, but client may
            # share config file with server, so only a warning for this case
            LOGGER.warning('Unable to find policy package %s', policy)
            policy = 'rucio.common.schema.' + GENERIC_FALLBACK.lower()
        else:
            raise exception.PolicyPackageNotFound(policy)
    except ImportError:
        raise exception.ErrorLoadingPolicyPackage(policy)

    try:
        module = importlib.import_module(policy)
    except ModuleNotFoundError:
        # if policy package does not contain schema module, load fallback module instead
        # this allows a policy package to omit modules that do not need customisation
        try:
            LOGGER.warning('Unable to load schema module %s from policy package, falling back to %s',
                           policy, GENERIC_FALLBACK)
            policy = 'rucio.common.schema.' + GENERIC_FALLBACK.lower()
            module = importlib.import_module(policy)
        except ModuleNotFoundError:
            raise exception.PolicyPackageNotFound(policy)
        except ImportError:
            raise exception.ErrorLoadingPolicyPackage(policy)
    except ImportError:
        raise exception.ErrorLoadingPolicyPackage(policy)

    schema_modules[DEFAULT_VO] = module
    if hasattr(module, 'SCOPE_NAME_REGEXP'):
        scope_name_regexps.append(module.SCOPE_NAME_REGEXP)


def load_schema_for_vo(vo: str) -> None:
    generic_fallback = 'generic_multi_vo'
    try:
        env_name = 'RUCIO_POLICY_PACKAGE_' + vo.upper()
        if env_name in environ:
            policy = environ[env_name]
        else:
            policy = config.config_get('policy', 'package-' + vo, check_config_table=False, raise_exception=True)
        package_module = importlib.import_module(policy)
        check_policy_module_version(package_module)
        policy = policy + ".schema"
    except (NoOptionError, NoSectionError):
        policy = 'rucio.common.schema.' + generic_fallback.lower()
    except ModuleNotFoundError:
        if config.is_client():
            LOGGER.warning('Unable to find policy package %s', policy)
            policy = 'rucio.common.schema.' + generic_fallback.lower()
        else:
            raise exception.PolicyPackageNotFound(policy)
    except ImportError:
        raise exception.ErrorLoadingPolicyPackage(policy)

    try:
        module = importlib.import_module(policy)
    except ModuleNotFoundError:
        # if policy package does not contain schema module, load fallback module instead
        # this allows a policy package to omit modules that do not need customisation
        try:
            LOGGER.warning('Unable to load schema module %s from policy package, falling back to %s',
                           policy, generic_fallback)
            policy = 'rucio.common.schema.' + generic_fallback.lower()
            module = importlib.import_module(policy)
        except ModuleNotFoundError:
            raise exception.PolicyPackageNotFound(policy)
        except ImportError:
            raise exception.ErrorLoadingPolicyPackage(policy)
    except ImportError:
        raise exception.ErrorLoadingPolicyPackage(policy)

    schema_modules[vo] = module


def validate_schema(name: str, obj: Any, vo: str = DEFAULT_VO) -> None:
    if obj:
        if vo not in schema_modules:
            load_schema_for_vo(vo)
        if hasattr(schema_modules[vo], 'SCHEMAS') and name in schema_modules[vo].SCHEMAS:
            schema = schema_modules[vo].SCHEMAS.get(name, {})
        else:
            # if schema not available in VO module, fall back to generic module
            schema = _get_generic_schema_module().SCHEMAS.get(name, {})
        try:
            validate(obj, schema)
        except ValidationError as error:
            raise exception.InvalidObject(f'Problem validating {name}: {error}')


def get_schema_value(key: str, vo: str = DEFAULT_VO) -> Any:
    if vo not in schema_modules:
        load_schema_for_vo(vo)
    if not hasattr(schema_modules[vo], key):
        return getattr(_get_generic_schema_module(), key)
    return getattr(schema_modules[vo], key)


def get_scope_name_regexps() -> list[str]:
    """ returns a list of all unique SCOPE_NAME_REGEXPs from all schemas """

    if len(scope_name_regexps) == 0:
        # load schemas for all VOs here and add unique scope_name_regexps to list
        from rucio.core.vo import list_vos
        with db_session(DatabaseOperationType.READ) as session:
            vos = list_vos(session=session)
        for vo in vos:
            if vo['vo'] not in schema_modules:
                load_schema_for_vo(vo['vo'])
            scope_name_regexp = schema_modules[vo['vo']].SCOPE_NAME_REGEXP
            if scope_name_regexp not in scope_name_regexps:
                scope_name_regexps.append(scope_name_regexp)
    return scope_name_regexps


def insert_scope_name(urls: tuple[str, ...]) -> tuple[str, str]:
    """
    given a tuple of URLs for webpy with '%s' as a placeholder for
    SCOPE_NAME_REGEXP, return a finalised tuple of URLs that will work for all
    SCOPE_NAME_REGEXPs in all schemas
    """

    regexps = get_scope_name_regexps()
    result = []
    for i in range(0, len(urls), 2):
        if "%s" in urls[i]:
            # add a copy for each unique SCOPE_NAME_REGEXP
            for scope_name_regexp in regexps:
                result.append(urls[i] % scope_name_regexp)
                result.append(urls[i + 1])
        else:
            # pass through unmodified
            result.append(urls[i])
            result.append(urls[i + 1])
    return tuple(result)
