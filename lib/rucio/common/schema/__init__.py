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
from typing import TYPE_CHECKING, Any, Optional

from jsonschema import ValidationError, validate

from rucio.common import config, exception
from rucio.common.plugins import check_policy_package_version

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


def resolve_placeholders(schema: Any, fallback_module: "ModuleType", module: Optional["ModuleType"] = None) -> Any:
    if isinstance(schema, dict):
        result = {}
        for k, v in schema.items():
            result[k] = resolve_placeholders(v, fallback_module, module)
    elif isinstance(schema, list):
        result = []
        for v in schema:
            result.append(resolve_placeholders(v, fallback_module, module))
    elif isinstance(schema, str):
        result = schema
        if schema.startswith("%%"):
            name = schema[2:]
            # allow adding or subtracting a constant
            constant = 0
            if "-" in name:
                pos = name.find("-")
                constant = -int(name[pos + 1:].strip())
                name = name[:pos].strip()
            if "+" in name:
                pos = name.find("+")
                constant = int(name[pos + 1:].strip())
                name = name[:pos].strip()
            if module is not None and hasattr(module, name):
                result = getattr(module, name)
            else:
                result = getattr(fallback_module, name)
            result = resolve_placeholders(result, fallback_module, module)
            if constant != 0:
                if not isinstance(result, int):
                    raise exception.InvalidType("Cannot perform arithmetic on non-integer schema value")
                result += constant
    else:
        result = schema
    return result


def load_schema_for_vo(vo: str) -> None:
    generic_fallback = 'generic_multi_vo' if _is_multivo() else 'generic'
    if config.config_has_section('policy'):
        try:
            env_name = 'RUCIO_POLICY_PACKAGE_' + vo.upper() if _is_multivo() else 'RUCIO_POLICY_PACKAGE'
            if env_name in environ:
                policy = environ[env_name]
            else:
                cfg_key = 'package-' + vo if _is_multivo() else 'package'
                policy = config.config_get('policy', cfg_key, check_config_table=False)
            check_policy_package_version(policy)
            policy = policy + ".schema"
        except (NoOptionError, NoSectionError):
            # fall back to old system for now
            try:
                policy = config.config_get('policy', 'schema', check_config_table=False)
            except (NoOptionError, NoSectionError):
                policy = generic_fallback
            policy = 'rucio.common.schema.' + policy.lower()
    else:
        policy = 'rucio.common.schema.' + generic_fallback.lower()

    try:
        module = importlib.import_module(policy)
    except ModuleNotFoundError:
        # if policy package does not contain schema module, load fallback module instead
        # this allows a policy package to omit modules that do not need customisation
        try:
            LOGGER.warning('Unable to load schema module %s from policy package, falling back to %s'
                           % (policy, generic_fallback))
            policy = 'rucio.common.schema.' + generic_fallback.lower()
            module = importlib.import_module(policy)
        except ModuleNotFoundError:
            raise exception.PolicyPackageNotFound(policy)
        except ImportError:
            raise exception.ErrorLoadingPolicyPackage(policy)
    except ImportError:
        raise exception.ErrorLoadingPolicyPackage(policy)

    schema_modules[vo] = module
    if not _is_multivo():
        if hasattr(module, 'SCOPE_NAME_REGEXP'):
            scope_name_regexps.append(module.SCOPE_NAME_REGEXP)


def validate_schema(name: str, obj: Any, vo: str = 'def') -> None:
    if vo not in schema_modules:
        load_schema_for_vo(vo)
    schemas = getattr(schema_modules[vo], "SCHEMAS") if hasattr(schema_modules[vo], "SCHEMAS") else getattr(_get_generic_schema_module(), "SCHEMAS")
    schema = schemas.get(name, {})
    schema = resolve_placeholders(schema, _get_generic_schema_module(), schema_modules[vo])
    try:
        if obj:
            validate(obj, schema)
    except ValidationError as error:  # NOQA, pylint: disable=W0612
        raise exception.InvalidObject(f'Problem validating {name}: {error}')


def get_schema_value(key: str, vo: str = 'def') -> Any:
    if vo not in schema_modules:
        load_schema_for_vo(vo)
    return resolve_placeholders("%%" + key, _get_generic_schema_module(), schema_modules[vo])


def get_scope_name_regexps() -> list[str]:
    """ returns a list of all unique SCOPE_NAME_REGEXPs from all schemas """

    if len(scope_name_regexps) == 0:
        # load schemas for all VOs here and add unique scope_name_regexps to list
        from rucio.core.vo import list_vos
        vos = list_vos()
        for vo in vos:
            if not vo['vo'] in schema_modules:
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
