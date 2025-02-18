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
from rucio.common import config, exception
from rucio.common.plugins import check_policy_package_version
from rucio.common.policy import get_policy

if TYPE_CHECKING:
    from typing import Optional

    from sqlalchemy.orm import Session

    from rucio.common.types import InternalAccount

LOGGER = logging.getLogger('policy')

# dictionary of permission modules for each VO
permission_modules = {}

try:
    multivo = config.config_get_bool('common', 'multi_vo')
except (NoOptionError, NoSectionError):
    multivo = False

# in multi-vo mode packages are loaded on demand when needed
if not multivo:
    generic_fallback = 'generic'

    fallback_policy = get_policy()
    if fallback_policy == 'def':
        fallback_policy = generic_fallback

    if config.config_has_section('policy'):
        try:
            if 'RUCIO_POLICY_PACKAGE' in environ:
                policy = environ['RUCIO_POLICY_PACKAGE']
            else:
                policy = config.config_get('policy', 'package', check_config_table=False)
            check_policy_package_version(policy)
            policy = policy + ".permission"
        except (NoOptionError, NoSectionError):
            # fall back to old system for now
            policy = 'rucio.core.permission.' + fallback_policy.lower()
    else:
        policy = 'rucio.core.permission.' + generic_fallback.lower()

    try:
        module = importlib.import_module(policy)
    except ModuleNotFoundError:
        # if policy package does not contain permission module, load fallback module instead
        # this allows a policy package to omit modules that do not need customisation
        try:
            LOGGER.warning('Unable to load permission module %s from policy package, falling back to %s'
                           % (policy, fallback_policy))
            policy = 'rucio.core.permission.' + fallback_policy.lower()
            module = importlib.import_module(policy)
        except ModuleNotFoundError:
            raise exception.PolicyPackageNotFound(policy)
        except ImportError:
            raise exception.ErrorLoadingPolicyPackage(policy)
    except ImportError:
        raise exception.ErrorLoadingPolicyPackage(policy)

    permission_modules["def"] = module


def load_permission_for_vo(vo: str) -> None:
    generic_fallback = 'generic_multi_vo'
    if config.config_has_section('policy'):
        try:
            env_name = 'RUCIO_POLICY_PACKAGE_' + vo.upper()
            if env_name in environ:
                policy = environ[env_name]
            else:
                policy = config.config_get('policy', 'package-' + vo)
            check_policy_package_version(policy)
            policy = policy + ".permission"
        except (NoOptionError, NoSectionError):
            # fall back to old system for now
            try:
                policy = config.config_get('policy', 'permission')
            except (NoOptionError, NoSectionError):
                policy = generic_fallback
            policy = 'rucio.core.permission.' + policy.lower()
    else:
        policy = 'rucio.core.permission.' + generic_fallback.lower()

    try:
        module = importlib.import_module(policy)
    except ModuleNotFoundError:
        # if policy package does not contain permission module, load fallback module instead
        # this allows a policy package to omit modules that do not need customisation
        try:
            LOGGER.warning('Unable to load permission module %s from policy package, falling back to %s'
                           % (policy, generic_fallback))
            policy = 'rucio.core.permission.' + generic_fallback.lower()
            module = importlib.import_module(policy)
        except ModuleNotFoundError:
            raise exception.PolicyPackageNotFound(policy)
        except ImportError:
            raise exception.ErrorLoadingPolicyPackage(policy)
        raise exception.PolicyPackageNotFound(policy)
    except ImportError:
        raise exception.ErrorLoadingPolicyPackage(policy)

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
