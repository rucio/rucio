# Copyright 2013-2019 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Matt Snyder <msnyder@rcf.rhic.bnl.gov>, 2019
# - Martin Barisits <martin.barisits@cern.ch>, 2019

from rucio.common import exception
from rucio.core.rse import get_rse_attribute
from rucio.rse import rsemanager
from rucio.rse.protocols.protocol import RSEProtocol
from rucio.transfertool.globusLibrary import send_delete_task

try:
    # PY2
    from ConfigParser import NoOptionError, NoSectionError
    from urlparse import urlparse
except ImportError:
    # PY3
    from configparser import NoOptionError, NoSectionError
    from urllib.parse import urlparse
from six import string_types

if getattr(rsemanager, 'CLIENT_MODE', None):
    from rucio.client.rseclient import RSEClient

if getattr(rsemanager, 'SERVER_MODE', None):
    from rucio.core import replica


class GlobusRSEProtocol(RSEProtocol):
    """ This class is to support Globus as a Rucio RSE protocol.  Inherits from abstract base class RSEProtocol."""

    def __init__(self, protocol_attr, rse_settings, logger=None):
        """ Initializes the object with information about the referred RSE.

            :param props: Properties of the requested protocol
        """
        super(GlobusRSEProtocol, self).__init__(protocol_attr, rse_settings, logger=logger)
        self.attributes = protocol_attr
        self.rse = rse_settings
        self.globus_endpoint_id = get_rse_attribute(key='globus_endpoint_id', rse_id=self.rse.get('id'))

    def lfns2pfns(self, lfns):
        """
            Retruns a fully qualified PFN for the file referred by path.

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
            scope, name = lfn['scope'], lfn['name']
            if 'path' in lfn and lfn['path'] is not None:
                pfns['%s:%s' % (scope, name)] = ''.join([prefix, lfn['path'] if not lfn['path'].startswith('/') else lfn['path'][1:]])
            else:
                pfns['%s:%s' % (scope, name)] = ''.join([prefix, self._get_path(scope=scope, name=name)])
        return pfns

    def __lfns2pfns_client(self, lfns):
        """ Provides the path of a replica for non-deterministic sites. Will be assigned to get path by the __init__ method if neccessary.

            :param scope: list of DIDs

            :returns: dict with scope:name as keys and PFN as value (in case of errors the Rucio exception si assigned to the key)
        """
        client = RSEClient()

        lfns = [lfns] if isinstance(lfns, dict) else lfns
        lfn_query = ["%s:%s" % (lfn['scope'], lfn['name']) for lfn in lfns]
        return client.lfns2pfns(self.rse['rse'], lfn_query, scheme=self.attributes['scheme'])

    def _get_path(self, scope, name):
        """ Transforms the logical file name into a PFN.
            Suitable for sites implementing the RUCIO naming convention.
            This implementation is only invoked if the RSE is deterministic.

            :param scope: scope
            :param name: filename

            :returns: RSE specific URI of the physical file
        """
        return self.translator.path(scope, name)

    def _get_path_nondeterministic_server(self, scope, name):  # pylint: disable=invalid-name
        """ Provides the path of a replica for non-deterministic sites. Will be assigned to get path by the __init__ method if neccessary. """
        rep = replica.get_replica(rse_id=self.rse['id'], scope=scope, name=name)
        if 'path' in rep and rep['path'] is not None:
            path = rep['path']
        elif 'state' in rep and (rep['state'] is None or rep['state'] == 'UNAVAILABLE'):
            raise exception.ReplicaUnAvailable('Missing path information and state is UNAVAILABLE for replica %s:%s on non-deterministic storage named %s' % (scope, name, self.rse['rse']))
        else:
            raise exception.ReplicaNotFound('Missing path information for replica %s:%s on non-deterministic storage named %s' % (scope, name, self.rse['rse']))
        if path.startswith('/'):
            path = path[1:]
        if path.endswith('/'):
            path = path[:-1]
        return path

    def parse_pfns(self, pfns):
        """
            Splits the given PFN into the parts known by the protocol. It is also checked if the provided protocol supportes the given PFNs.

            :param pfns: a list of a fully qualified PFNs

            :returns: dic with PFN as key and a dict with path and name as value

            :raises RSEFileNameNotSupported: if the provided PFN doesn't match with the protocol settings
        """
        ret = dict()
        pfns = [pfns] if isinstance(pfns, string_types) else pfns

        for pfn in pfns:
            parsed = urlparse(pfn)
            scheme = parsed.scheme
            hostname = parsed.netloc.partition(':')[0]
            port = int(parsed.netloc.partition(':')[2]) if parsed.netloc.partition(':')[2] != '' else 0
            while '//' in parsed.path:
                parsed = parsed._replace(path=parsed.path.replace('//', '/'))
            path = parsed.path

            # Protect against 'lazy' defined prefixes for RSEs in the repository
            if not self.attributes['prefix'].startswith('/'):
                self.attributes['prefix'] = '/' + self.attributes['prefix']
            if not self.attributes['prefix'].endswith('/'):
                self.attributes['prefix'] += '/'

            if self.attributes['hostname'] != hostname:
                if self.attributes['hostname'] != 'localhost':  # In the database empty hostnames are replaced with localhost but for some URIs (e.g. file) a hostname is not included
                    raise exception.RSEFileNameNotSupported('Invalid hostname: provided \'%s\', expected \'%s\'' % (hostname, self.attributes['hostname']))

            if self.attributes['port'] != port:
                raise exception.RSEFileNameNotSupported('Invalid port: provided \'%s\', expected \'%s\'' % (port, self.attributes['port']))

            if not path.startswith(self.attributes['prefix']):
                raise exception.RSEFileNameNotSupported('Invalid prefix: provided \'%s\', expected \'%s\'' % ('/'.join(path.split('/')[0:len(self.attributes['prefix'].split('/')) - 1]),
                                                                                                              self.attributes['prefix']))  # len(...)-1 due to the leading '/

            # Spliting parsed.path into prefix, path, filename
            prefix = self.attributes['prefix']
            path = path.partition(self.attributes['prefix'])[2]
            name = path.split('/')[-1]
            path = '/'.join(path.split('/')[:-1])
            if not path.startswith('/'):
                path = '/' + path
            if path != '/' and not path.endswith('/'):
                path = path + '/'
            ret[pfn] = {'path': path, 'name': name, 'scheme': scheme, 'prefix': prefix, 'port': port, 'hostname': hostname, }

        return ret

    def exists(self, path):
        """
            Checks if the requested file is known by the referred RSE.

            :param path: Physical file name

            :returns: True if the file exists, False if it doesn't

            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        raise NotImplementedError
        # pass

    def connect(self):
        """
            Establishes the actual connection to the referred RSE.

            :raises RSEAccessDenied: if no connection could be established.
        """
        # raise NotImplementedError
        pass

    def close(self):
        """ Closes the connection to RSE."""
        # raise NotImplementedError
        pass

    def get(self, path, dest, transfer_timeout=None):
        """
            Provides access to files stored inside connected the RSE.

            :param path: Physical file name of requested file
            :param dest: Name and path of the files when stored at the client
            :param transfer_timeout: Transfer timeout (in seconds)

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
         """
        raise NotImplementedError

    def put(self, source, target, source_dir, transfer_timeout=None):
        """
            Allows to store files inside the referred RSE.

            :param source: path to the source file on the client file system
            :param target: path to the destination file on the storage
            :param source_dir: Path where the to be transferred files are stored in the local file system
            :param transfer_timeout: Transfer timeout (in seconds)

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        raise NotImplementedError

    def delete(self, path):
        """
            Deletes a file from the connected RSE.

            :param path: path to the to be deleted file

            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        try:
            delete_response = send_delete_task(endpoint_id=self.globus_endpoint_id[0], path=path)
            if delete_response['code'] != 'Accepted':
                raise exception.RucioException(delete_response['code'])
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def rename(self, path, new_path):
        """ Allows to rename a file stored inside the connected RSE.

            :param path: path to the current file on the storage
            :param new_path: path to the new file on the storage

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        raise NotImplementedError

    def get_space_usage(self):
        """
            Get RSE space usage information.

            :returns: a list with dict containing 'totalsize' and 'unusedsize'

            :raises ServiceUnavailable: if some generic error occured in the library.
        """
        raise NotImplementedError

    def stat(self, path):
        """
            Returns the stats of a file.

            :param path: path to file

            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.

            :returns: a dict with two keys, filesize and adler32 of the file provided in path.
        """
        raise NotImplementedError
