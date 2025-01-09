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
import hashlib
import logging
from configparser import NoOptionError, NoSectionError
from typing import TYPE_CHECKING, Any, Optional

from rucio.common import config
from rucio.common.constants import RseAttr
from rucio.common.exception import ConfigNotFound
from rucio.common.plugins import PolicyPackageAlgorithms

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


class RSEDeterministicScopeTranslation(PolicyPackageAlgorithms):
    """
        Translates a pfn dictionary into a scope and name
    """

    _algorithm_type = "pfn2lfn"

    def __init__(self, vo: str = 'def'):
        super().__init__()

        logger = logging.getLogger(__name__)

        try:
            algorithm_name = config.config_get('policy', self._algorithm_type)
        except (ConfigNotFound, NoOptionError, NoSectionError, RuntimeError):
            logger.debug("PFN2LFN: no algorithm specified in the config.")
            if super()._supports(self._algorithm_type, vo):
                algorithm_name = vo
            else:
                algorithm_name = "def"
            logger.debug("PFN2LFN: Falling back to %s algorithm.", 'default' if algorithm_name == 'def' else algorithm_name)

        self.parser = self.get_parser(algorithm_name)

    @classmethod
    def _module_init_(cls) -> None:
        """
        Registers the included scope extraction algorithms
        """
        cls.register(cls._default, "def")

    @classmethod
    def get_parser(cls, algorithm_name: str) -> 'Callable[..., Any]':
        return super()._get_one_algorithm(cls._algorithm_type, algorithm_name)

    @classmethod
    def register(
        cls,
        pfn2lfn_callable: 'Callable',
        name: Optional[str] = None
    ) -> None:
        """
        Provided a callable function, register it as one of the valid PFN2LFN algorithms.


        :param pfn2lfn_callable: Callable function to use.
        :param name: Algorithm name used for registration.
        """
        if name is None:
            name = pfn2lfn_callable.__name__
        algorithm_dict = {name: pfn2lfn_callable}
        super()._register(cls._algorithm_type, algorithm_dict)

    @staticmethod
    def _default(parsed_pfn: 'Mapping[str, str]') -> tuple[str, str]:
        """ Translate pfn to name/scope pair

        :param parsed_pfn: dictionary representing pfn containing:
            - path: str,
            - name: str
        :return: tuple containing name, scope
        """
        path = parsed_pfn['path']
        scope = path.lstrip('/').split('/')[0]
        name = parsed_pfn['name']
        return name, scope


RSEDeterministicScopeTranslation._module_init_()  # pylint: disable=protected-access


class RSEDeterministicTranslation(PolicyPackageAlgorithms):
    """
    Execute the logic for translating a LFN to a path.
    """

    _DEFAULT_LFN2PFN = "hash"
    _algorithm_type = "lfn2pfn"

    def __init__(self, rse=None, rse_attributes=None, protocol_attributes=None):
        """
        Initialize a translator object from the RSE, its attributes, and the protocol-specific
        attributes.

        :param rse: Name of RSE for this translation.
        :param rse_attributes: A dictionary of RSE-specific attributes for use in the translation.
        :param protocol_attributes: A dictionary of RSE/protocol-specific attributes.
        """
        super().__init__()
        self.rse = rse
        self.rse_attributes = rse_attributes if rse_attributes else {}
        self.protocol_attributes = protocol_attributes if protocol_attributes else {}

    @classmethod
    def supports(cls, name):
        """
        Check to see if a specific algorithm is supported.

        :param name: Name of the deterministic algorithm.
        :returns: True if `name` is an algorithm supported by the translator class, False otherwise
        """
        return super()._supports(cls._algorithm_type, name)

    @classmethod
    def register(cls, lfn2pfn_callable, name=None):
        """
        Provided a callable function, register it as one of the valid LFN2PFN algorithms.

        The callable will receive five arguments:
         - scope: Scope of the LFN.
         - name: LFN's path name
         - rse: RSE name the translation is being done for.
         - rse_attributes: Attributes of the RSE.
         - protocol_attributes: Attributes of the RSE's protocol
        The return value should be the last part of the PFN - it will be appended to the
        rest of the URL.

        :param lfn2pfn_callable: Callable function to use for generating paths.
        :param name: Algorithm name used for registration.  If None, then `lfn2pfn_callable.__name__` is used.
        """
        if name is None:
            name = lfn2pfn_callable.__name__
        algorithm_dict = {name: lfn2pfn_callable}
        super()._register(cls._algorithm_type, algorithm_dict)

    @staticmethod
    def __hash(scope, name, rse, rse_attrs, protocol_attrs):
        """
        Given a LFN, turn it into a sub-directory structure using a hash function.

        This takes the MD5 of the LFN and uses the first four characters as a subdirectory
        name.

        :param scope: Scope of the LFN.
        :param name: File name of the LFN.
        :param rse: RSE for PFN (ignored)
        :param rse_attrs: RSE attributes for PFN (ignored)
        :param protocol_attrs: RSE protocol attributes for PFN (ignored)
        :returns: Path for use in the PFN generation.
        """
        del rse
        del rse_attrs
        del protocol_attrs
        hstr = hashlib.md5(('%s:%s' % (scope, name)).encode('utf-8')).hexdigest()
        if scope.startswith('user') or scope.startswith('group'):
            scope = scope.replace('.', '/')
        return '%s/%s/%s/%s' % (scope, hstr[0:2], hstr[2:4], name)

    @staticmethod
    def __identity(scope, name, rse, rse_attrs, protocol_attrs):
        """
        Given a LFN, convert it directly to a path using the mapping:

            scope:path -> scope/path

        :param scope: Scope of the LFN.
        :param name: File name of the LFN.
        :param rse: RSE for PFN (ignored)
        :param rse_attrs: RSE attributes for PFN (ignored)
        :param protocol_attrs: RSE protocol attributes for PFN (ignored)
        :returns: Path for use in the PFN generation.
        """
        del rse
        del rse_attrs
        del protocol_attrs
        if scope.startswith('user') or scope.startswith('group'):
            scope = scope.replace('.', '/')
        return '%s/%s' % (scope, name)

    @staticmethod
    def __xenon(scope, name, rse, rse_attrs, protocol_attrs):
        """
        Given a LFN, turn it into a two level sub-directory structure based on the scope
        plus a third level based on the name
        :param scope: Scope of the LFN.
        :param name: File name of the LFN.
        :param rse: RSE for PFN (ignored)
        :param rse_attrs: RSE attributes for PFN (ignored)
        :param protocol_attrs: RSE protocol attributes for PFN (ignored)
        :returns: Path for use in the PFN generation.
        """
        del rse
        del rse_attrs
        del protocol_attrs

        return '%s/%s/%s/%s' % (scope[0:7], scope[4:len(scope)], name.split('-')[0] + "-" + name.split('-')[1], name)

    @classmethod
    def _module_init_(cls):
        """
        Initialize the class object on first module load.
        """
        cls.register(cls.__hash, "hash")
        cls.register(cls.__identity, "identity")
        cls.register(cls.__xenon, "xenon")
        policy_module = None
        try:
            policy_module = config.config_get('policy', 'lfn2pfn_module')
        except (ConfigNotFound, NoOptionError, NoSectionError):
            pass
        if policy_module:
            # TODO: The import of importlib is done like this due to a dependency issue with python 2.6 and incompatibility of the module with py3.x
            # More information https://github.com/rucio/rucio/issues/875
            import importlib
            importlib.import_module(policy_module)

        cls._DEFAULT_LFN2PFN = config.get_lfn2pfn_algorithm_default()

    def path(self, scope, name):
        """ Transforms the logical file name into a PFN's path.

            :param lfn: filename
            :param scope: scope

            :returns: RSE specific URI of the physical file
        """
        algorithm = self.rse_attributes.get(RseAttr.LFN2PFN_ALGORITHM, 'default')
        if algorithm == 'default':
            algorithm = RSEDeterministicTranslation._DEFAULT_LFN2PFN
        algorithm_callable = super()._get_one_algorithm(RSEDeterministicTranslation._algorithm_type, algorithm)
        return algorithm_callable(scope, name, self.rse, self.rse_attributes, self.protocol_attributes)


RSEDeterministicTranslation._module_init_()  # pylint: disable=protected-access
