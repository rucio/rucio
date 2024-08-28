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
from typing import TYPE_CHECKING, Any, TypeVar

from rucio.common import config
from rucio.common.client import get_client_vo, is_client
from rucio.common.exception import InvalidAlgorithmName, PolicyPackageIsNotVersioned, PolicyPackageVersionError
from rucio.version import current_version

if TYPE_CHECKING:
    from collections.abc import Callable

PolicyPackageAlgorithmsT = TypeVar('PolicyPackageAlgorithmsT', bound='PolicyPackageAlgorithms')

if TYPE_CHECKING:
    from rucio.common.types import LoggerFunction


def check_policy_package_version(package: str, logger: 'LoggerFunction' = logging.log) -> None:

    '''
    Checks that the Rucio version supported by the policy package is compatible
    with this version. Raises an exception if not.
    :param package: the fully qualified name of the policy package
    '''
    try:
        supported_version = _get_supported_version_from_policy_package(package)
    except ImportError:
        logger(logging.DEBUG, 'Policy package %s not found' % package)
        return
    except PolicyPackageIsNotVersioned:
        logger(logging.DEBUG, 'Policy package %s does not include information about which Rucio versions it supports' % package)
        return

    rucio_version = current_version()
    if rucio_version not in supported_version:
        raise PolicyPackageVersionError(rucio_version=rucio_version, supported_versions=supported_version, package=package)


def _get_supported_version_from_policy_package(package: str) -> list[str]:
    try:
        module = importlib.import_module(package)
    except ImportError as e:
        raise e

    if not hasattr(module, 'SUPPORTED_VERSION'):
        raise PolicyPackageIsNotVersioned(package)

    if isinstance(module.SUPPORTED_VERSION, list):
        return module.SUPPORTED_VERSION
    else:
        return [module.SUPPORTED_VERSION]


class PolicyPackageAlgorithms:
    """
    Base class for Rucio Policy Package Algorithms

    ALGORITHMS is a dict where:
        - the key is the algorithm type
        - the value is a dictionary of algorithm names and their callables
    """
    _ALGORITHMS: dict[str, dict[str, 'Callable[..., Any]']] = {}
    _loaded_policy_modules = False

    def __init__(self) -> None:
        if not self._loaded_policy_modules:
            self._register_all_policy_package_algorithms()
            self._loaded_policy_modules = True

    @classmethod
    def _get_one_algorithm(cls: type[PolicyPackageAlgorithmsT], algorithm_type: str, name: str) -> 'Callable[..., Any]':
        """
        Get the algorithm from the dictionary of algorithms
        """
        return cls._ALGORITHMS[algorithm_type][name]

    @classmethod
    def _get_algorithms(cls: type[PolicyPackageAlgorithmsT], algorithm_type: str) -> dict[str, 'Callable[..., Any]']:
        """
        Get the dictionary of algorithms for a given type
        """
        return cls._ALGORITHMS[algorithm_type]

    @classmethod
    def _register(
            cls: type[PolicyPackageAlgorithmsT],
            algorithm_type: str, algorithm_dict: dict[str, 'Callable[..., Any]']) -> None:
        """
        Provided a dictionary of callable function,
        and the associated algorithm type,
        register it as one of the valid algorithms.
        """
        if algorithm_type in cls._ALGORITHMS:
            cls._ALGORITHMS[algorithm_type].update(algorithm_dict)
        else:
            cls._ALGORITHMS[algorithm_type] = algorithm_dict

    @classmethod
    def _supports(cls: type[PolicyPackageAlgorithmsT], algorithm_type: str, name: str) -> bool:
        """
        Check if a algorithm is supported by the plugin
        """
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
            if is_client():
                vo = get_client_vo()
                cls._try_importing_policy(vo)
            # on server, list all VOs and register their algorithms
            else:
                from rucio.core.vo import list_vos
                # policy package per VO
                vos = list_vos()
                for vo in vos:
                    cls._try_importing_policy(vo['vo'])

    @classmethod
    def _try_importing_policy(cls: type[PolicyPackageAlgorithmsT], vo: str = "") -> None:
        try:
            # import from utils here to avoid circular import

            env_name = 'RUCIO_POLICY_PACKAGE' + ('' if not vo else '_' + vo.upper())
            package = getattr(os.environ, env_name, "")
            if not package:
                package = str(config.config_get('policy', 'package' + ('' if not vo else '-' + vo)))

            check_policy_package_version(package)
            module = importlib.import_module(package)

            if hasattr(module, 'get_algorithms'):
                all_algorithms = module.get_algorithms()

                # for backward compatibility, rename 'surl' to 'non_deterministic_pfn' here
                if 'surl' in all_algorithms:
                    all_algorithms['non_deterministic_pfn'] = all_algorithms['surl']

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
