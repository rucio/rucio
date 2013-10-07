# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013

import hashlib

from exceptions import NotImplementedError
from urlparse import urlparse

from rucio.common import exception


class RSEProtocol(object):
    """ This class is virtual and acts as a base to inherit new protocols from. It further provides some common functionality which applies for the amjority of the protocols."""

    def __init__(self, props):
        """ Initializes the object with information about the referred RSE.

            :param props: Properties derived from the RSE Repository
        """
        self.rse = props

    def get_path(self, lfn, scope):
        """ Transforms the physical file name into the local URI in the referred RSE.
            Suitable for sites implementoing the RUCIO naming convention.

            :param lfn: filename
            :param scope: scope

            :returns: RSE specific URI of the physical file
        """
        hstr = hashlib.md5('%s:%s' % (scope, lfn)).hexdigest()
        correctedscope = "/".join(scope.split('.'))
        return '%s%s/%s/%s/%s' % (self.rse['prefix'], correctedscope, hstr[0:2], hstr[2:4], lfn)

    def path2pfn(self, path):
        """
            Retruns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.

        """
        return ''.join([self.rse['scheme'], '://', self.rse['hostname'], ':', str(self.rse['port']), path])

    def exists(self, path):
        """
            Checks if the requested file is known by the referred RSE.

            :param path: Physical file name

            :returns: True if the file exists, False if it doesn't

            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        raise NotImplementedError

    def connect(self, credentials):
        """
            Establishes the actual connection to the referred RSE.

            :param: credentials needed to establish a connection with the stroage.

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

    def split_pfn(self, pfn):
        """
            Splits the given PFN into the parts known by the protocol. During parsing the PFN is also checked for
            validity on the given RSE with the given protocol.

            As this method is strongly connected to the protocol itself it is very likely that it will be overwritten
            in the specific protocol classes.

            The default implementation parses a PFN for: scheme, hostname, port, prefix, path, filename and checks if the
            derived data matches with data provided in the RSE repository for this RSE/protocol.

            :param pfn: a fully qualified PFN

            :returns: a dict containing all known parts of the PFN for the protocol e.g. scheme, hostname, port, prefix, path, filename

            :raises RSEFileNameNotSupported: if the provided PFN doesn't match with the protocol settings
        """
        parsed = urlparse(pfn)
        ret = dict()
        ret['scheme'] = parsed.scheme
        ret['hostname'] = parsed.netloc.partition(':')[0]
        ret['port'] = int(parsed.netloc.partition(':')[2]) if parsed.netloc.partition(':')[2] != '' else 0
        ret['path'] = parsed.path

        # Protect against 'lazy' defined prefixes for RSEs in the repository
        self.rse['prefix'] = '' if self.rse['prefix'] is None else self.rse['prefix']
        if not self.rse['prefix'].startswith('/'):
            self.rse['prefix'] = '/' + self.rse['prefix']
        if not self.rse['prefix'].endswith('/'):
            self.rse['prefix'] += '/'

        if self.rse['hostname'] != ret['hostname']:
            if self.rse['hostname'] != 'localhost':  # In the database empty hostnames are replaced with localhost but for some URIs (e.g. file) a hostname is not included
                raise exception.RSEFileNameNotSupported('Invalid hostname: provided \'%s\', expected \'%s\'' % (ret['hostname'], self.rse['hostname']))

        if self.rse['port'] != ret['port']:
            raise exception.RSEFileNameNotSupported('Invalid port: provided \'%s\', expected \'%s\'' % (ret['port'], self.rse['port']))

        if not ret['path'].startswith(self.rse['prefix']):
            raise exception.RSEFileNameNotSupported('Invalid prefix: provided \'%s\', expected \'%s\'' % ('/'.join(ret['path'].split('/')[0:len(self.rse['prefix'].split('/')) - 1]),
                                                                                                          self.rse['prefix']))  # len(...)-1 due to the leading '/

        # Spliting parsed.path into prefix, path, filename
        ret['prefix'] = self.rse['prefix']
        ret['path'] = ret['path'].partition(self.rse['prefix'])[2]
        ret['filename'] = ret['path'].split('/')[-1]
        ret['path'] = ret['path'].partition(ret['filename'])[0]

        return ret
