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
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2016

import os

from rucio.common import exception
from rucio.rse.protocols import protocol
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

    def path2pfn(self, path):
        """
            Returns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.

        """
        if not path.startswith('xroot'):
            if path.startswith('/'):
                return '%s://%s:%s/%s' % (self.scheme, self.hostname, self.port, path)
            else:
                return '%s://%s:%s//%s' % (self.scheme, self.hostname, self.port, path)
        else:
            return path

    def exists(self, pfn):
        """ Checks if the requested file is known by the referred RSE.

            :param pfn Physical file name

            :returns: True if the file exists, False if it doesn't

            :raise  ServiceUnavailable
        """
        try:
            path = self.pfn2path(pfn)
            cmd = 'xrdfs %s:%s stat %s' % (self.hostname, self.port, path)
            status, out, err = execute(cmd)
            if not status == 0:
                return False
        except Exception as e:
            raise exception.ServiceUnavailable(e)

        return True

    def pfn2path(self, pfn):
        parse_pfns = self.parse_pfns(pfn)[pfn]
        path = parse_pfns['prefix'] + parse_pfns['path'] + parse_pfns['name']
        return path

    def lfns2pfns(self, lfns):
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

        lfns = [lfns] if type(lfns) == dict else lfns
        for lfn in lfns:
            scope, name = lfn['scope'], lfn['name']
            if 'path' in lfn and lfn['path'] is not None:
                pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'], '://', self.attributes['hostname'], ':', str(self.attributes['port']), '/', prefix, lfn['path']])
            else:
                pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'], '://', self.attributes['hostname'], ':', str(self.attributes['port']), '/', prefix, self._get_path(scope=scope, name=name)])
        return pfns

    def connect(self):
        """ Establishes the actual connection to the referred RSE.

            :param credentials Provides information to establish a connection
                to the referred storage system. For S3 connections these are
                access_key, secretkey, host_base, host_bucket, progress_meter
                and skip_existing.

            :raises RSEAccessDenied
        """
        try:
            # The query stats call is not implemented on some xroot doors.
            # Workaround: fail, if server does not reply within 10 seconds for static config query
            cmd = 'XRD_REQUESTTIMEOUT=10 xrdfs %s:%s query config %s:%s' % (self.hostname, self.port, self.hostname, self.port)
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

        try:
            cmd = 'xrdcp -f %s %s' % (pfn, dest)
            status, out, err = execute(cmd)
            if status == 54:
                raise exception.SourceNotFound()
            elif status != 0:
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

    def delete(self, pfn):
        """
            Deletes a file from the connected RSE.

            :param pfn Physical file name

            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        if not self.exists(pfn):
            raise exception.SourceNotFound()
        try:
            path = self.pfn2path(pfn)
            cmd = 'xrdfs %s:%s rm %s' % (self.hostname, self.port, path)
            status, out, err = execute(cmd)
            if not status == 0:
                raise exception.RucioException(err)
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def rename(self, pfn, new_pfn):
        """ Allows to rename a file stored inside the connected RSE.

            :param pfn      Current physical file name
            :param new_pfn  New physical file name
            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        if not self.exists(pfn):
            raise exception.SourceNotFound()
        try:
            path = self.pfn2path(pfn)
            new_path = self.pfn2path(new_pfn)
            new_dir = new_path[:new_path.rindex('/') + 1]
            cmd = 'xrdfs %s:%s mkdir -p %s' % (self.hostname, self.port, new_dir)
            status, out, err = execute(cmd)
            cmd = 'xrdfs %s:%s mv %s %s' % (self.hostname, self.port, path, new_path)
            status, out, err = execute(cmd)
            if not status == 0:
                raise exception.RucioException(err)
        except Exception as e:
            raise exception.ServiceUnavailable(e)
