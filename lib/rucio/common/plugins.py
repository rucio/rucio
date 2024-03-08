# -*- coding: utf-8 -*-
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
import os
from configparser import NoOptionError, NoSectionError
from typing import Any, Callable, Dict, TypeVar, Type

from rucio.common import config
from rucio.common.exception import InvalidAlgorithmName


PolicyPackageAlgorithmsT = TypeVar('PolicyPackageAlgorithmsT', bound='PolicyPackageAlgorithms')


class PolicyPackageAlgorithms():
    """
    Base class for Rucio Policy Package Algorithms

    ALGORITHMS is of type Dict[str, Dict[str. Callable[..., Any]]]
    where the key is the algorithm type and the value is a dictionary of algorithm names and their callables
    """
    _ALGORITHMS: Dict[str, Dict[str, Callable[..., Any]]] = {}
    _loaded_policy_modules = False

    def __init__(self) -> None:
        if not self._loaded_policy_modules:
            self._register_all_policy_package_algorithms()
            self._loaded_policy_modules = True

    @classmethod
    def _get_one_algorithm(cls: Type[PolicyPackageAlgorithmsT], algorithm_type: str, name: str) -> Callable[..., Any]:
        """
        Get the algorithm from the dictionary of algorithms
        """
        return cls._ALGORITHMS[algorithm_type][name]

    @classmethod
    def _get_algorithms(cls: Type[PolicyPackageAlgorithmsT], algorithm_type: str) -> Dict[str, Callable[..., Any]]:
        """
        Get the dictionary of algorithms for a given type
        """
        return cls._ALGORITHMS[algorithm_type]

    @classmethod
    def _register(
            cls: Type[PolicyPackageAlgorithmsT],
            algorithm_type: str, algorithm_dict: Dict[str, Callable[..., Any]]) -> None:
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
    def _supports(cls: Type[PolicyPackageAlgorithmsT], algorithm_type: str, name: str) -> bool:
        """
        Check if a algorithm is supported by the plugin
        """
        return name in cls._ALGORITHMS.get(algorithm_type, {})

    @classmethod
    def _register_all_policy_package_algorithms(cls: Type[PolicyPackageAlgorithmsT]) -> None:
        '''
        Loads all the algorithms of a given type from the policy package(s) and registers them
        :param algorithm_type: the type of algorithm to register (e.g. 'surl', 'lfn2pfn')
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
            # determine whether on client or server
            client = False
            if 'RUCIO_CLIENT_MODE' not in os.environ:
                if not config.config_has_section('database') and config.config_has_section('client'):
                    client = True
            else:
                if os.environ['RUCIO_CLIENT_MODE']:
                    client = True

            # on client, only register algorithms for selected VO
            if client:
                if 'RUCIO_VO' in os.environ:
                    vo = os.environ['RUCIO_VO']
                else:
                    try:
                        vo = str(config.config_get('client', 'vo'))
                    except (NoOptionError, NoSectionError):
                        vo = 'def'
                cls._try_importing_policy(vo)
            # on server, list all VOs and register their algorithms
            else:
                from rucio.core.vo import list_vos
                # policy package per VO
                vos = list_vos()
                for vo in vos:
                    cls._try_importing_policy(vo['vo'])

    @classmethod
    def _try_importing_policy(cls: Type[PolicyPackageAlgorithmsT], vo: str = "") -> None:
        try:
            # import from utils here to avoid circular import
            from rucio.common.utils import check_policy_package_version

            env_name = 'RUCIO_POLICY_PACKAGE' + ('' if not vo else '_' + vo.upper())
            package = getattr(os.environ, env_name, "")
            if not package:
                package = str(config.config_get('policy', 'package' + ('' if not vo else '-' + vo)))

            check_policy_package_version(package)
            module = importlib.import_module(package)

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
