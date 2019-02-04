"""
Copyright European Organization for Nuclear Research (CERN)

Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Authors:
- Ralph Vigne, <ralph.vigne@cern.ch>, 2012-2014
- Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2016
- Wen Guan, <wen.guan@cern.ch>, 2014
- Cheng-Hsi Chao, <cheng-hsi.chao@cern.ch>, 2014
- Mario Lassnig, <mario.lassnig@cern.ch>, 2017
- Brian Bockelman, <bbockelm@cse.unl.edu>, 2018
- Martin Barisits, <martin.barisits@cern.ch>, 2018
- Nicolo Magini, <nicolo.magini@cern.ch>, 2018
- Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2019

PY3K COMPATIBLE

This module defines the base class for implementing a transfer protocol,
along with some of the default methods for LFN2PFN translations.
"""

import hashlib

try:
    # PY2
    from ConfigParser import NoOptionError, NoSectionError
    from urlparse import urlparse
except ImportError:
    # PY3
    from configparser import NoOptionError, NoSectionError
    from urllib.parse import urlparse
from six import string_types

from rucio.common import config, exception
from rucio.rse import rsemanager

if getattr(rsemanager, 'CLIENT_MODE', None):
    from rucio.client.rseclient import RSEClient

if getattr(rsemanager, 'SERVER_MODE', None):
    from rucio.core import replica


class RSEDeterministicTranslation(object):
    """
    Execute the logic for translating a LFN to a path.
    """

    _LFN2PFN_ALGORITHMS = {}
    _DEFAULT_LFN2PFN = "hash"

    def __init__(self, rse=None, rse_attributes=None, protocol_attributes=None):
        """
        Initialize a translator object from the RSE, its attributes, and the protocol-specific
        attributes.

        :param rse: Name of RSE for this translation.
        :param rse_attributes: A dictionary of RSE-specific attributes for use in the translation.
        :param protocol_attributes: A dictionary of RSE/protocol-specific attributes.
        """
        self.rse = rse
        self.rse_attributes = rse_attributes if rse_attributes else {}
        self.protocol_attributes = protocol_attributes if protocol_attributes else {}

    @classmethod
    def supports(cls, name):
        """
        Check to see if a specific algorithm is supported.

        :param name: Name of the deterministic algorithm.
        :returns: True if `name` is an algorithm supported by the translator class, False otherwise.
        """
        return name in cls._LFN2PFN_ALGORITHMS

    @staticmethod
    def register(lfn2pfn_callable, name=None):
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
        RSEDeterministicTranslation._LFN2PFN_ALGORITHMS[name] = lfn2pfn_callable

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
        hstr = hashlib.md5('%s:%s' % (scope, name)).hexdigest()
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

    @classmethod
    def _module_init_(cls):
        """
        Initialize the class object on first module load.
        """
        cls.register(cls.__hash, "hash")
        cls.register(cls.__identity, "identity")
        policy_module = None
        try:
            policy_module = config.config_get('policy', 'lfn2pfn_module')
        except (NoOptionError, NoSectionError):
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
        algorithm = self.rse_attributes.get('lfn2pfn_algorithm', 'default')
        if algorithm == 'default':
            algorithm = RSEDeterministicTranslation._DEFAULT_LFN2PFN
        algorithm_callable = RSEDeterministicTranslation._LFN2PFN_ALGORITHMS[algorithm]
        return algorithm_callable(scope, name, self.rse, self.rse_attributes, self.protocol_attributes)


RSEDeterministicTranslation._module_init_()  # pylint: disable=protected-access


class RSEProtocol(object):
    """ This class is virtual and acts as a base to inherit new protocols from. It further provides some common functionality which applies for the amjority of the protocols."""

    def __init__(self, protocol_attr, rse_settings):
        """ Initializes the object with information about the referred RSE.

            :param props: Properties of the requested protocol
        """
        self.attributes = protocol_attr
        self.translator = None
        self.renaming = True
        self.overwrite = False
        self.rse = rse_settings
        if self.rse['deterministic']:
            self.translator = RSEDeterministicTranslation(self.rse['rse'], rse_settings, self.attributes)
            if getattr(rsemanager, 'CLIENT_MODE', None) and \
                    not RSEDeterministicTranslation.supports(self.rse.get('lfn2pfn_algorithm')):
                # Remote server has an algorithm we don't understand; always make the server do the lookup.
                setattr(self, 'lfns2pfns', self.__lfns2pfns_client)
        else:
            if getattr(rsemanager, 'CLIENT_MODE', None):
                setattr(self, 'lfns2pfns', self.__lfns2pfns_client)
            if getattr(rsemanager, 'SERVER_MODE', None):
                setattr(self, '_get_path', self._get_path_nondeterministic_server)

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
        rep = replica.get_replica(rse=self.rse['rse'], scope=scope, name=name, rse_id=self.rse['id'])
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

    def connect(self):
        """
            Establishes the actual connection to the referred RSE.

            :raises RSEAccessDenied: if no connection could be established.
        """
        raise NotImplementedError

    def close(self):
        """ Closes the connection to RSE."""
        raise NotImplementedError

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
