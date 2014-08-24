# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - WeiJen Chang, <wchang@cern.ch>, 2013
# - Cheng-Hsi Chao, <cheng-hsi.chao@cern.ch>, 2014

import os

from rucio.common import exception
from rucio.rse.protocols import protocol
from urlparse import urlparse
from rucio.common.utils import execute


class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using the XRootD protocol."""

    def __init__(self, protocol_attr, rse_settings):
        """ Initializes the object with information about the referred RSE.

            :param props Properties derived from the RSE Repository
        """
        super(Default, self).__init__(protocol_attr, rse_settings)
        self.scheme = self.attributes['scheme']
        self.hostname = self.attributes['hostname']
        self.port = str(self.attributes['port'])

    def get_path(self, lfn, scope):
        """ Transforms the physical file name into the local URI in the referred RSE.
            Suitable for sites implementoing the RUCIO naming convention.

            :param lfn: filename
            :param scope: scope

            :returns: RSE specific URI of the physical file
        """
        return '%s/%s/%s' % (self.rse['prefix'], scope, lfn)

    def path2pfn(self, path):
        """
            Returns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.

        """
        if not path.startswith('xroot'):
            return '%s://%s:%s/%s' % (self.scheme, self.hostname, self.port, path)
        else:
            return path

    def exists(self, pfn):
        """ Checks if the requested file is known by the referred RSE.

            :param pfn Physical file name

            :returns: True if the file exists, False if it doesn't

            :raise  ServiceUnavailable
        """
        try:
            cmd = 'xrdfs %s:%s stat %s' % (self.hostname, self.port, pfn)
            status, out, err = execute(cmd)
            if not status == 0:
                return False
        except Exception as e:
            raise exception.ServiceUnavailable(e)

        return True

    def connect(self, credentials):
        """ Establishes the actual connection to the referred RSE.

            :param credentials Provides information to establish a connection
                to the referred storage system. For S3 connections these are
                access_key, secretkey, host_base, host_bucket, progress_meter
                and skip_existing.

            :raises RSEAccessDenied
        """
        try:
            cmd = 'xrdfs %s:%s query stats %s:%s' % (self.hostname, self.port, self.hostname, self.port)
            status, out, err = execute(cmd)
            if not status == 0:
                raise exception.RSEAccessDenied(err)
        except Exception as e:
            raise exception.RSEAccessDenied(e)

    def close(self):
        """ Closes the connection to RSE."""
        pass

    def get(self, pfn, dest):
        """ Provides access to files stored inside connected the RSE.

            :param pfn Physical file name of requested file
            :param dest Name and path of the files when stored at the client

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        path = self.path2pfn(pfn)

        if not self.exists(pfn):
            raise exception.SourceNotFound()
        try:
            cmd = 'xrdcp -f %s %s' % (path, dest)
            status, out, err = execute(cmd)
            if not status == 0:
                raise exception.RucioException(err)
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def put(self, filename, target, source_dir):
        """
            Allows to store files inside the referred RSE.

            :param source: path to the source file on the client file system
            :param target: path to the destination file on the storage
            :param source_dir: Path where the to be transferred files are stored in the local file system

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        source_url = '%s/%s' % (source_dir, filename)
        path = self.path2pfn(target)

        if not os.path.exists(source_url):
            raise exception.SourceNotFound()
        try:
            cmd = 'xrdcp -f %s %s' % (source_url, path)
            status, out, err = execute(cmd)
            if not status == 0:
                raise exception.RucioException(err)
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def delete(self, path):
        """
            Deletes a file from the connected RSE.

            :param path: path to the to be deleted file

            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        if not self.exists(path):
            raise exception.SourceNotFound()
        try:
            cmd = 'xrdfs %s:%s rm %s' % (self.hostname, self.port, path)
            status, out, err = execute(cmd)
            if not status == 0:
                raise exception.RucioException(err)
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
        if not self.exists(path):
            raise exception.SourceNotFound()
        try:
            cmd = 'xrdfs %s:%s mv %s %s' % (self.hostname, self.port, path, new_path)
            status, out, err = execute(cmd)
            if not status == 0:
                raise exception.RucioException(err)
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def split_pfn(self, pfn):
        """
            Splits the given PFN into the parts known by the protocol. During parsing the PFN is also checked for
            validity on the given RSE with the given protocol.

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
            raise exception.RSEFileNameNotSupported('Invalid hostname: provided \'%s\', expected \'%s\'' % (ret['hostname'], self.rse['hostname']))
        if self.rse['port'] != ret['port']:
            raise exception.RSEFileNameNotSupported('Invalid port: provided \'%s\', expected \'%s\'' % (ret['port'], self.rse['port']))
        if not ret['path'].startswith('/' + self.rse['prefix']):
            raise exception.RSEFileNameNotSupported('Invalid prefix: provided \'%s\', expected \'%s\'' % ('/'.join(ret['path'].split('/')[0:len(self.rse['prefix'].split('/')) - 1]),
                                                                                                          self.rse['prefix']))  # len(...)-1 due to the leading '/

        # Spliting parsed.path into prefix, path, filename
        ret['prefix'] = self.rse['prefix']
        ret['path'] = ret['path'].partition(self.rse['prefix'])[2]
        ret['name'] = ret['path'].split('/')[-1]
        ret['path'] = ret['path'].partition(ret['name'])[0]
        return ret
