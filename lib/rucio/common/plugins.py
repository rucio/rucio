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
import os
from configparser import NoOptionError, NoSectionError
from typing import TYPE_CHECKING, Any, Optional, TypeVar

from packaging.specifiers import SpecifierSet

from rucio.common import config
from rucio.common.client import get_client_vo
from rucio.common.constants import DEFAULT_VO, POLICY_ALGORITHM_TYPES, POLICY_ALGORITHM_TYPES_LITERAL
from rucio.common.exception import InvalidAlgorithmName, InvalidPolicyPackageAlgorithmType, PolicyPackageIsNotVersioned, PolicyPackageVersionError
from rucio.version import current_version

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import ModuleType

    from rucio.common.types import LoggerFunction

LOGGER = logging.getLogger('policy')

PolicyPackageAlgorithmsT = TypeVar('PolicyPackageAlgorithmsT', bound='PolicyPackageAlgorithms')


def check_policy_module_version(module: 'ModuleType', logger: 'LoggerFunction' = logging.log) -> None:

    '''
    Checks that the Rucio version supported by the policy module is compatible
    with this version. Raises an exception if not.
    :param module: the top level module of the policy package
    '''
    try:
        supported_versionset = _get_supported_versions_from_policy_package(module)
    except PolicyPackageIsNotVersioned:
        logger(logging.DEBUG, 'Policy package %s does not include information about which Rucio versions it supports' % module.__name__)
        return

    rucio_version = current_version()
    if rucio_version not in supported_versionset:
        raise PolicyPackageVersionError(rucio_version=rucio_version, supported_versionset=str(supported_versionset), package=module.__name__)


def _get_supported_versions_from_policy_package(module: 'ModuleType') -> SpecifierSet:
    if not hasattr(module, 'SUPPORTED_VERSION'):
        raise PolicyPackageIsNotVersioned(module.__name__)

    supported_versionset = module.SUPPORTED_VERSION

    if isinstance(supported_versionset, list):
        supported_versionset = ','.join(supported_versionset)

    return SpecifierSet(supported_versionset)


class PolicyPackageAlgorithms:
    """
    Base class for Rucio Policy Package Algorithms

    ALGORITHMS is a dict where:
        - the key is the algorithm type
        - the value is a dictionary of algorithm names and their callables
    """
    _ALGORITHMS: dict[POLICY_ALGORITHM_TYPES_LITERAL, dict[str, 'Callable[..., Any]']] = {}
    _loaded_policy_modules = False
    _default_algorithms: dict[str, Optional['Callable[..., Any]']] = {}

    def __init__(self) -> None:
        if not self._loaded_policy_modules:
            self._register_all_policy_package_algorithms()
            self._loaded_policy_modules = True

    @classmethod
    def _get_default_algorithm(cls: type[PolicyPackageAlgorithmsT], algorithm_type: POLICY_ALGORITHM_TYPES_LITERAL, vo: str = "") -> Optional['Callable[..., Any]']:
        """
        Gets the default algorithm of this type, if present in the policy package.
        The default algorithm is the function named algorithm_type within the module named algorithm_type.
        Returns None if no default algorithm present.
        """
        if algorithm_type not in POLICY_ALGORITHM_TYPES:
            raise InvalidPolicyPackageAlgorithmType(algorithm_type)

        # check if default algorithm for this VO is already cached
        type_for_vo = vo + "_" + algorithm_type
        if type_for_vo in cls._default_algorithms:
            return cls._default_algorithms[type_for_vo]

        default_algorithm = None
        try:
            if vo == DEFAULT_VO:
                vo = ''
            package = cls._get_policy_package_name(vo)
        except (NoOptionError, NoSectionError):
            cls._default_algorithms[type_for_vo] = default_algorithm
            return default_algorithm

        module_name = package + "." + algorithm_type
        LOGGER.info('Attempting to find algorithm %s in default location %s...', algorithm_type, module_name)
        try:
            module = importlib.import_module(module_name)

            if hasattr(module, algorithm_type):
                default_algorithm = getattr(module, algorithm_type)
        except ModuleNotFoundError:
            LOGGER.info('Algorithm %s not found in default location %s', algorithm_type, module_name)
        except ImportError:
            LOGGER.info('Algorithm %s found in default location %s, but could not be loaded', algorithm_type, module_name)
        # if the default algorithm is not present, this will store None and we will
        # not attempt to load the same algorithm again
        cls._default_algorithms[type_for_vo] = default_algorithm
        return default_algorithm

    @classmethod
    def _get_one_algorithm(cls: type[PolicyPackageAlgorithmsT], algorithm_type: POLICY_ALGORITHM_TYPES_LITERAL, name: str) -> 'Callable[..., Any]':
        """
        Get the algorithm from the dictionary of algorithms
        """
        if algorithm_type not in POLICY_ALGORITHM_TYPES:
            raise InvalidPolicyPackageAlgorithmType(algorithm_type)
        return cls._ALGORITHMS[algorithm_type][name]

    @classmethod
    def _get_algorithms(cls: type[PolicyPackageAlgorithmsT], algorithm_type: POLICY_ALGORITHM_TYPES_LITERAL) -> dict[str, 'Callable[..., Any]']:
        """
        Get the dictionary of algorithms for a given type
        """
        if algorithm_type not in POLICY_ALGORITHM_TYPES:
            raise InvalidPolicyPackageAlgorithmType(algorithm_type)
        return cls._ALGORITHMS[algorithm_type]

    @classmethod
    def _register(
            cls: type[PolicyPackageAlgorithmsT],
            algorithm_type: POLICY_ALGORITHM_TYPES_LITERAL,
            algorithm_dict: dict[str, 'Callable[..., Any]']) -> None:
        """
        Provided a dictionary of callable function,
        and the associated algorithm type,
        register it as one of the valid algorithms.
        """
        if algorithm_type not in POLICY_ALGORITHM_TYPES:
            raise InvalidPolicyPackageAlgorithmType(algorithm_type)

        if algorithm_type in cls._ALGORITHMS:
            cls._ALGORITHMS[algorithm_type].update(algorithm_dict)
        else:
            cls._ALGORITHMS[algorithm_type] = algorithm_dict

    @classmethod
    def _supports(
            cls: type[PolicyPackageAlgorithmsT],
            algorithm_type: POLICY_ALGORITHM_TYPES_LITERAL,
            name: str) -> bool:
        """
        Check if a algorithm is supported by the plugin
        """
        if algorithm_type not in POLICY_ALGORITHM_TYPES:
            raise InvalidPolicyPackageAlgorithmType(algorithm_type)
        return name in cls._ALGORITHMS.get(algorithm_type, {})

    @classmethod
    def _register_all_policy_package_algorithms(cls: type[PolicyPackageAlgorithmsT]) -> None:
        '''
        Loads all the algorithms of a given type from the policy package(s) and registers them
        :param algorithm_type: the type of algorithm to register (e.g. 'lfn2pfn')
        :param dictionary: the dictionary to register them in
        :param vo: the name of the relevant VO (None for single VO)
        '''
        try:
            multivo = config.config_get_bool('common', 'multi_vo')
        except (NoOptionError, NoSectionError):
            multivo = False
        if not multivo:
            # single policy package
            cls._try_importing_policy()
        else:
            # on client, only register algorithms for selected VO
            if config.is_client():
                vo = get_client_vo()
                cls._try_importing_policy(vo)
            # on server, list all VOs and register their algorithms
            else:
                from rucio.core.vo import list_vos
                from rucio.db.sqla.constants import DatabaseOperationType
                from rucio.db.sqla.session import db_session
                # policy package per VO
                with db_session(DatabaseOperationType.READ) as session:
                    vos = list_vos(session=session)
                for vo in vos:
                    cls._try_importing_policy(vo['vo'])

    @classmethod
    def _get_policy_package_name(cls: type[PolicyPackageAlgorithmsT], vo: str = "") -> str:
        env_name = 'RUCIO_POLICY_PACKAGE' + ('' if not vo else '_' + vo.upper())
        package = os.getenv(env_name, "")
        if not package:
            package = str(config.config_get('policy', 'package' + ('' if not vo else '-' + vo)))
        return package

    @classmethod
    def _try_importing_policy(cls: type[PolicyPackageAlgorithmsT], vo: str = "") -> None:
        try:
            package = cls._get_policy_package_name(vo)
            module = importlib.import_module(package)
            check_policy_module_version(module)

            if hasattr(module, 'get_algorithms'):
                all_algorithms = module.get_algorithms()

                # check that the names are correctly prefixed for multi-VO
                if vo:
                    for _, algorithms in all_algorithms.items():
                        for k in algorithms.keys():
                            if not k.lower().startswith(vo.lower()):
                                raise InvalidAlgorithmName(k, vo)

                # Updates the dictionary with the algorithms from the policy package
                for algorithm_type, algorithm_dict in all_algorithms.items():
                    cls._register(algorithm_type, algorithm_dict)

        except (NoOptionError, NoSectionError, ImportError):
            pass
