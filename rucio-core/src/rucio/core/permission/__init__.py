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

import importlib
import logging
from configparser import NoOptionError, NoSectionError
from os import environ
from typing import TYPE_CHECKING, Any

import rucio.core.permission.generic
from rucio.core.common import config, exception
from rucio.core.common.plugins import check_policy_package_version

if TYPE_CHECKING:
    from typing import Optional

    from sqlalchemy.orm import Session

    from rucio.core.common.types import InternalAccount

LOGGER = logging.getLogger('policy')

# dictionary of permission modules for each VO
permission_modules = {}

try:
    multivo = config.config_get_bool('common', 'multi_vo')
except (NoOptionError, NoSectionError):
    multivo = False

# in multi-vo mode packages are loaded on demand when needed
if not multivo:
    GENERIC_FALLBACK = 'generic'

    if config.config_has_section('permission'):
        try:
            FALLBACK_POLICY = config.config_get('permission', 'policy')
        except (NoOptionError, NoSectionError):
            FALLBACK_POLICY = GENERIC_FALLBACK
    elif config.config_has_section('policy'):
        try:
            FALLBACK_POLICY = config.config_get('policy', 'permission')
        except (NoOptionError, NoSectionError):
            FALLBACK_POLICY = GENERIC_FALLBACK
    else:
        FALLBACK_POLICY = GENERIC_FALLBACK

    if config.config_has_section('policy'):
        try:
            if 'RUCIO_POLICY_PACKAGE' in environ:
                POLICY = environ['RUCIO_POLICY_PACKAGE']
            else:
                POLICY = config.config_get('policy', 'package', check_config_table=False)
            check_policy_package_version(POLICY)
            POLICY = POLICY + ".permission"
        except (NoOptionError, NoSectionError):
            # fall back to old system for now
            POLICY = 'rucio.core.permission.' + FALLBACK_POLICY.lower()
    else:
        POLICY = 'rucio.core.permission.' + GENERIC_FALLBACK.lower()

    try:
        module = importlib.import_module(POLICY)
    except ModuleNotFoundError:
        # if policy package does not contain permission module, load fallback module instead
        # this allows a policy package to omit modules that do not need customisation
        try:
            LOGGER.warning('Unable to load permission module %s from policy package, falling back to %s'
                           % (POLICY, FALLBACK_POLICY))
            POLICY = 'rucio.core.permission.' + FALLBACK_POLICY.lower()
            module = importlib.import_module(POLICY)
        except ModuleNotFoundError:
            raise exception.PolicyPackageNotFound(POLICY)
        except ImportError:
            raise exception.ErrorLoadingPolicyPackage(POLICY)
    except ImportError:
        raise exception.ErrorLoadingPolicyPackage(POLICY)

    permission_modules["def"] = module


def load_permission_for_vo(vo: str) -> None:
    GENERIC_FALLBACK = 'generic_multi_vo'
    if config.config_has_section('policy'):
        try:
            env_name = 'RUCIO_POLICY_PACKAGE_' + vo.upper()
            if env_name in environ:
                POLICY = environ[env_name]
            else:
                POLICY = config.config_get('policy', 'package-' + vo)
            check_policy_package_version(POLICY)
            POLICY = POLICY + ".permission"
        except (NoOptionError, NoSectionError):
            # fall back to old system for now
            try:
                POLICY = config.config_get('policy', 'permission')
            except (NoOptionError, NoSectionError):
                POLICY = GENERIC_FALLBACK
            POLICY = 'rucio.core.permission.' + POLICY.lower()
    else:
        POLICY = 'rucio.core.permission.' + GENERIC_FALLBACK.lower()

    try:
        module = importlib.import_module(POLICY)
    except ModuleNotFoundError:
        # if policy package does not contain permission module, load fallback module instead
        # this allows a policy package to omit modules that do not need customisation
        try:
            LOGGER.warning('Unable to load permission module %s from policy package, falling back to %s'
                           % (POLICY, GENERIC_FALLBACK))
            POLICY = 'rucio.core.permission.' + GENERIC_FALLBACK.lower()
            module = importlib.import_module(POLICY)
        except ModuleNotFoundError:
            raise exception.PolicyPackageNotFound(POLICY)
        except ImportError:
            raise exception.ErrorLoadingPolicyPackage(POLICY)
        raise exception.PolicyPackageNotFound(POLICY)
    except ImportError:
        raise exception.ErrorLoadingPolicyPackage(POLICY)

    permission_modules[vo] = module


class PermissionResult:
    """
    Represents the result of a permission check, allowing an optional message to be
    included to give the user more information.
    """
    def __init__(self, allowed: bool, message: "Optional[str]" = "") -> None:
        self.allowed = allowed
        self.message = message

    # allow this to be tested as a bool for backwards compatibility
    def __bool__(self) -> bool:
        return self.allowed


def has_permission(
        issuer: "InternalAccount",
        action: str,
        kwargs: dict[str, Any],
        *,
        session: "Optional[Session]" = None
) -> PermissionResult:
    if issuer.vo not in permission_modules:
        load_permission_for_vo(issuer.vo)
    try:
        result = permission_modules[issuer.vo].has_permission(issuer, action, kwargs, session=session)
    except TypeError:
        # will be thrown if policy package is missing the action in its perm dictionary
        result = None
    # if this permission is missing from the policy package, fallback to generic
    if result is None:
        result = rucio.core.permission.generic.has_permission(issuer, action, kwargs, session=session)
    # continue to support policy packages that just return a boolean and no message
    if isinstance(result, bool):
        result = PermissionResult(result)
    return result
