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

"""
This module defines the base class for implementing a transfer protocol,
along with some of the default methods for LFN2PFN translations.
"""
import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Optional, Union
from urllib.parse import urlparse

from rucio.common import exception
from rucio.rse import rsemanager
from rucio.rse.translation import RSEDeterministicTranslation

if getattr(rsemanager, 'CLIENT_MODE', None):
    from rucio.client.rseclient import RSEClient

if getattr(rsemanager, 'SERVER_MODE', None):
    from rucio.core import replica
    from rucio.core.rse import get_rse_vo

if getattr(rsemanager, 'SERVER_MODE', None) or TYPE_CHECKING:
    from rucio.common.types import InternalScope, LFNDict, LoggerFunction, RSESettingsDict

if TYPE_CHECKING:
    from collections.abc import Iterable

    from rucio.common.types import DIDDict


class RSEProtocol(ABC):
    """ This class is virtual and acts as a base to inherit new protocols from. It further provides some common functionality which applies for the majority of the protocols."""

    def __init__(
            self,
            protocol_attr: dict[str, Any],
            rse_settings: "RSESettingsDict",
            logger: "LoggerFunction" = logging.log
    ):
        """ Initializes the object with information about the referred RSE.

            :param protocol_attr:  Properties of the requested protocol.
            :param rse_settting:   The RSE settings.
            :param logger:         Optional decorated logger that can be passed from the calling daemons or servers.
        """

        if 'auth_token' not in protocol_attr:
            raise exception.NoAuthInformation('No authentication token passed for the RSE protocol')

        self.auth_token = protocol_attr['auth_token']
        protocol_attr.pop('auth_token')
        self.attributes = protocol_attr
        self.translator = None
        self.renaming = True
        self.overwrite = False
        self.rse = rse_settings
        self.logger = logger
        if self.rse['deterministic']:
            if getattr(rsemanager, 'SERVER_MODE', None):
                vo = get_rse_vo(self.rse['id'])
            if getattr(rsemanager, 'CLIENT_MODE', None):
                # assume client has only one VO policy package configured
                vo = ''
                if not RSEDeterministicTranslation.supports(self.rse.get('lfn2pfn_algorithm')):
                    # Remote server has an algorithm we don't understand; always make the server do the lookup.
                    setattr(self, 'lfns2pfns', self.__lfns2pfns_client)
            self.translator = RSEDeterministicTranslation(self.rse['rse'], rse_settings, self.attributes, vo)
        else:
            if getattr(rsemanager, 'CLIENT_MODE', None):
                setattr(self, 'lfns2pfns', self.__lfns2pfns_client)
            if getattr(rsemanager, 'SERVER_MODE', None):
                setattr(self, '_get_path', self._get_path_nondeterministic_server)

    def lfns2pfns(
            self,
            lfns: Union[list["LFNDict"], "LFNDict"]
    ) -> dict[str, str]:
        """
            Returns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.
        """
        pfns = {}
        prefix = self.attributes['prefix']

        if not prefix.startswith('/'):
            prefix = ''.join(['/', prefix])
        if not prefix.endswith('/'):
            prefix = ''.join([prefix, '/'])

        lfns = [lfns] if isinstance(lfns, dict) else lfns
        for lfn in lfns:
            scope, name = str(lfn['scope']), lfn['name']
            if 'path' in lfn and lfn['path'] is not None:
                pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'],
                                                         '://',
                                                         self.attributes['hostname'],
                                                         ':',
                                                         str(self.attributes['port']),
                                                         prefix,
                                                         lfn['path'] if not lfn['path'].startswith('/') else lfn['path'][1:]
                                                         ])
            else:
                try:
                    pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'],
                                                             '://',
                                                             self.attributes['hostname'],
                                                             ':',
                                                             str(self.attributes['port']),
                                                             prefix,
                                                             self._get_path(scope=scope, name=name)
                                                             ])
                except exception.ReplicaNotFound as e:
                    self.logger(logging.WARNING, str(e))
        return pfns

    def __lfns2pfns_client(
            self,
            lfns: Union[list["DIDDict"], "DIDDict"]
    ) -> dict[str, str]:
        """ Provides the path of a replica for non-deterministic sites. Will be assigned to get path by the __init__ method if necessary.

            :param scope: list of DIDs

            :returns: dict with scope:name as keys and PFN as value (in case of errors the Rucio exception si assigned to the key)
        """
        client = RSEClient()  # pylint: disable=E0601

        lfns = [lfns] if isinstance(lfns, dict) else lfns
        lfn_query = ["%s:%s" % (lfn['scope'], lfn['name']) for lfn in lfns]
        return client.lfns2pfns(self.rse['rse'], lfn_query, scheme=self.attributes['scheme'])

    def _get_path(
            self,
            scope: str,
            name: str):
        """ Transforms the logical file name into a PFN.
            Suitable for sites implementing the RUCIO naming convention.
            This implementation is only invoked if the RSE is deterministic.

            :param scope: scope
            :param name: filename

            :returns: RSE specific URI of the physical file
        """
        return self.translator.path(scope, name)  # type: ignore (translator could be none)

    def _get_path_nondeterministic_server(  # pylint: disable=invalid-name
            self,
            scope: str,
            name: str
    ) -> str:
        """ Provides the path of a replica for non-deterministic sites. Will be assigned to get path by the __init__ method if necessary. """
        vo = get_rse_vo(self.rse['id'])  # pylint: disable=E0601
        internal_scope = InternalScope(scope, vo=vo)  # pylint: disable=E0601
        rep = replica.get_replica(scope=internal_scope, name=name, rse_id=self.rse['id'])  # pylint: disable=E0601
        if 'path' in rep and rep['path'] is not None:
            path = rep['path']
        elif 'state' in rep and (rep['state'] is None or rep['state'] == 'UNAVAILABLE'):
            raise exception.ReplicaUnAvailable('Missing path information and state is UNAVAILABLE for replica %s:%s on non-deterministic storage named %s' % (internal_scope, name, self.rse['rse']))
        else:
            raise exception.ReplicaNotFound('Missing path information for replica %s:%s on non-deterministic storage named %s' % (internal_scope, name, self.rse['rse']))
        if path.startswith('/'):
            path = path[1:]
        if path.endswith('/'):
            path = path[:-1]
        return path

    def parse_pfns(
            self,
            pfns: Union['Iterable[str]', str]
    ) -> dict[str, dict[str, str]]:
        """
            Splits the given PFN into the parts known by the protocol. It is also checked if the provided protocol supports the given PFNs.

            :param pfns: a list of a fully qualified PFNs

            :returns: dic with PFN as key and a dict with path and name as value

            :raises RSEFileNameNotSupported: if the provided PFN doesn't match with the protocol settings
        """
        ret = dict()
        pfns = [pfns] if isinstance(pfns, str) else pfns

        for pfn in pfns:
            parsed = urlparse(pfn)
            scheme = parsed.scheme
            hostname = parsed.netloc.partition(':')[0]
            port = int(parsed.netloc.partition(':')[2]) if parsed.netloc.partition(':')[2] != '' else 0
            while '//' in parsed.path:
                parsed = parsed._replace(path=parsed.path.replace('//', '/'))
            path = parsed.path
            prefix = self.attributes['prefix']
            while '//' in prefix:
                prefix = prefix.replace('//', '/')

            # Protect against 'lazy' defined prefixes for RSEs in the repository
            if not prefix.startswith('/'):
                prefix = '/' + prefix
            if not prefix.endswith('/'):
                prefix += '/'

            if self.attributes['hostname'] != hostname:
                if self.attributes['hostname'] != 'localhost':  # In the database empty hostnames are replaced with localhost but for some URIs (e.g. file) a hostname is not included
                    raise exception.RSEFileNameNotSupported('Invalid hostname: provided \'%s\', expected \'%s\'' % (hostname, self.attributes['hostname']))

            if self.attributes['port'] != port:
                raise exception.RSEFileNameNotSupported('Invalid port: provided \'%s\', expected \'%s\'' % (port, self.attributes['port']))

            if not path.startswith(prefix):
                raise exception.RSEFileNameNotSupported('Invalid prefix: provided \'%s\', expected \'%s\'' % ('/'.join(path.split('/')[0:len(prefix.split('/')) - 1]),
                                                                                                              prefix))  # len(...)-1 due to the leading '/

            # Splitting parsed.path into prefix, path, filename
            path = path.partition(prefix)[2]
            name = path.split('/')[-1]
            path = '/'.join(path.split('/')[:-1])
            if not path.startswith('/'):
                path = '/' + path
            if path != '/' and not path.endswith('/'):
                path = path + '/'
            ret[pfn] = {'path': path, 'name': name, 'scheme': scheme, 'prefix': prefix, 'port': port, 'hostname': hostname, }

        return ret

    def exists(
            self,
            path: Optional[str]
    ) -> bool:
        """
            Checks if the requested file is known by the referred RSE.

            :param path: Physical file name

            :returns: True if the file exists, False if it doesn't

            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        raise NotImplementedError

    @abstractmethod
    def connect(self) -> None:
        """
            Establishes the actual connection to the referred RSE.

            :raises RSEAccessDenied: if no connection could be established.
        """
        raise NotImplementedError

    @abstractmethod
    def close(self) -> None:
        """ Closes the connection to RSE."""
        raise NotImplementedError

    @abstractmethod
    def get(
            self,
            path: str,
            dest: str,
            transfer_timeout: Optional[int] = None
    ) -> None:
        """
            Provides access to files stored inside connected the RSE.

            :param path: Physical file name of requested file
            :param dest: Name and path of the files when stored at the client
            :param transfer_timeout: Transfer timeout (in seconds)

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occurred in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
         """
        raise NotImplementedError

    @abstractmethod
    def put(
            self,
            source: str,
            target: str,
            source_dir: Optional[str],
            transfer_timeout: Optional[int] = None
    ) -> None:
        """
            Allows to store files inside the referred RSE.

            :param source: path to the source file on the client file system
            :param target: path to the destination file on the storage
            :param source_dir: Path where the to be transferred files are stored in the local file system
            :param transfer_timeout: Transfer timeout (in seconds)

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occurred in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        raise NotImplementedError

    @abstractmethod
    def delete(
            self,
            path: str
    ) -> None:
        """
            Deletes a file from the connected RSE.

            :param path: path to the to be deleted file

            :raises ServiceUnavailable: if some generic error occurred in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        raise NotImplementedError

    @abstractmethod
    def rename(
            self,
            path: str,
            new_path: str
    ) -> None:
        """ Allows to rename a file stored inside the connected RSE.

            :param path: path to the current file on the storage
            :param new_path: path to the new file on the storage

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occurred in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        raise NotImplementedError

    def get_space_usage(self) -> tuple[int, int]:
        """
            Get RSE space usage information.

            :returns: a tuple 'totalsize' and 'unusedsize'

            :raises ServiceUnavailable: if some generic error occurred in the library.
        """
        raise NotImplementedError

    def stat(self, path: str) -> dict[str, Any]:
        """
            Returns the stats of a file.

            :param path: path to file

            :raises ServiceUnavailable: if some generic error occurred in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.

            :returns: a dict with two keys, filesize and adler32 of the file provided in path.
        """
        raise NotImplementedError
