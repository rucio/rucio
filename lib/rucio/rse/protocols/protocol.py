# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012-2014
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2016
# - Wen Guan, <wen.guan@cern.ch>, 2014
# - Cheng-Hsi Chao, <cheng-hsi.chao@cern.ch>, 2014

import hashlib

from exceptions import NotImplementedError
from urlparse import urlparse

from rucio.common import exception
from rucio.rse import rsemanager

if rsemanager.CLIENT_MODE:
    from rucio.client.replicaclient import ReplicaClient

if rsemanager.SERVER_MODE:
    from rucio.core import replica


class RSEProtocol(object):
    """ This class is virtual and acts as a base to inherit new protocols from. It further provides some common functionality which applies for the amjority of the protocols."""

    def __init__(self, protocol_attr, rse_settings):
        """ Initializes the object with information about the referred RSE.

            :param props: Properties of the reuested protocol
        """
        self.attributes = protocol_attr
        self.renaming = True
        self.overwrite = False
        self.rse = rse_settings
        if not self.rse['deterministic']:
            if rsemanager.CLIENT_MODE:
                setattr(self, 'lfns2pfns', self.__lfns2pfns_client)
            if rsemanager.SERVER_MODE:
                setattr(self, '_get_path', self._get_path_nondeterministic_server)
        else:
            self.attributes['determinism_type'] = 'default'

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

        lfns = [lfns] if type(lfns) == dict else lfns
        for lfn in lfns:
            scope, name = lfn['scope'], lfn['name']
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
                pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'],
                                                         '://',
                                                         self.attributes['hostname'],
                                                         ':',
                                                         str(self.attributes['port']),
                                                         prefix,
                                                         self._get_path(scope=scope, name=name)
                                                         ])
        return pfns

    def __lfns2pfns_client(self, lfns):
        """ Provides the path of a replica for non-deterministic sites. Will be assigned to get path by the __init__ method if neccessary.

            :param scope: list of DIDs

            :returns: dict with scope:name as keys and PFN as value (in case of errors the Rucio exception si assigned to the key)
        """
        client = ReplicaClient()
        pfns = {}

        lfns = [lfns] if type(lfns) == dict else lfns
        for lfn in lfns:
            scope = lfn['scope']
            name = lfn['name']
            replicas = [r for r in client.list_replicas([{'scope': scope, 'name': name}, ], schemes=[self.attributes['scheme'], ])]  # schemes is used to narrow down the response message.
            if len(replicas) > 1:
                pfns['%s:%s' % (scope, name)] = exception.RSEOperationNotSupported('This operation can only be performed for files.')
            if not len(replicas):
                pfns['%s:%s' % (scope, name)] = exception.RSEOperationNotSupported('File not found.')
            pfns['%s:%s' % (scope, name)] = replicas[0]['rses'][self.rse['rse']][0] if (self.rse['rse'] in replicas[0]['rses'].keys()) else exception.RSEOperationNotSupported('Replica not found on given RSE.')
        return pfns

    def _get_path(self, scope, name):
        """ Transforms the logical file name into a PFN.
            Suitable for sites implementing the RUCIO naming convention.

            :param lfn: filename
            :param scope: scope

            :returns: RSE specific URI of the physical file
        """
        hstr = hashlib.md5('%s:%s' % (scope, name)).hexdigest()
        if scope.startswith('user') or scope.startswith('group'):
            scope = scope.replace('.', '/')
        return '%s/%s/%s/%s' % (scope, hstr[0:2], hstr[2:4], name)

    def _get_path_nondeterministic_server(self, scope, name):
        """ Provides the path of a replica for non-deterministic sites. Will be assigned to get path by the __init__ method if neccessary. """
        r = replica.get_replica(rse=self.rse['rse'], scope=scope, name=name, rse_id=self.rse['id'])
        if 'path' in r and r['path'] is not None:
            path = r['path']
        elif 'state' in r and (r['state'] is None or r['state'] == 'UNAVAILABLE'):
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
        pfns = [pfns] if ((type(pfns) == str) or (type(pfns) == unicode)) else pfns

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
            path = path.partition(name)[0]
            if not path.startswith('/'):
                path = '/' + path
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

    def connect(self):
        """
            Establishes the actual connection to the referred RSE.

            :raises RSEAccessDenied: if no connection could be established.
        """
        raise NotImplementedError

    def close(self):
        """ Closes the connection to RSE."""
        raise NotImplementedError

    def get(self, path, dest):
        """
            Provides access to files stored inside connected the RSE.

            :param path: Physical file name of requested file
            :param dest: Name and path of the files when stored at the client

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
         """
        raise NotImplementedError

    def put(self, source, target, source_dir):
        """
            Allows to store files inside the referred RSE.

            :param source: path to the source file on the client file system
            :param target: path to the destination file on the storage
            :param source_dir: Path where the to be transferred files are stored in the local file system

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
        raise NotImplementedError

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
