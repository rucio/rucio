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

import os
import logging

from rucio.common import exception
from rucio.rse.protocols import protocol
from rucio.common.utils import execute, PREFERRED_CHECKSUM


class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using the XRootD protocol using GSI authentication."""

    def __init__(self, protocol_attr, rse_settings, logger=logging.log):
        """ Initializes the object with information about the referred RSE.

            :param props: Properties derived from the RSE Repository
        """
        super(Default, self).__init__(protocol_attr, rse_settings, logger=logger)

        self.scheme = self.attributes['scheme']
        self.hostname = self.attributes['hostname']
        self.port = str(self.attributes['port'])
        self.logger = logger

    def path2pfn(self, path):
        """
            Returns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.

        """
        self.logger(logging.DEBUG, 'xrootd.path2pfn: path: {}'.format(path))
        if not path.startswith('xroot') and not path.startswith('root'):
            if path.startswith('/'):
                return '%s://%s:%s/%s' % (self.scheme, self.hostname, self.port, path)
            else:
                return '%s://%s:%s//%s' % (self.scheme, self.hostname, self.port, path)
        else:
            return path

    def exists(self, pfn):
        """ Checks if the requested file is known by the referred RSE.

            :param pfn: Physical file name

            :returns: True if the file exists, False if it doesn't

            :raise  ServiceUnavailable
        """
        self.logger(logging.DEBUG, 'xrootd.exists: pfn: {}'.format(pfn))
        try:
            path = self.pfn2path(pfn)
            cmd = 'XrdSecPROTOCOL=gsi xrdfs %s:%s stat %s' % (self.hostname, self.port, path)
            self.logger(logging.DEBUG, 'xrootd.exists: cmd: {}'.format(cmd))
            status, out, err = execute(cmd)
            if status != 0:
                return False
        except Exception as e:
            raise exception.ServiceUnavailable(e)

        return True

    def stat(self, path):
        """
        Returns the stats of a file.

        :param path: path to file

        :raises ServiceUnavailable: if some generic error occured in the library.

        :returns: a dict with two keys, filesize and an element of GLOBALLY_SUPPORTED_CHECKSUMS.
        """
        self.logger(logging.DEBUG, 'xrootd.stat: path: {}'.format(path))
        ret = {}
        chsum = None
        if path.startswith('root:'):
            path = self.pfn2path(path)

        try:
            # xrdfs stat for getting filesize
            cmd = 'XrdSecPROTOCOL=gsi xrdfs %s:%s stat %s' % (self.hostname, self.port, path)
            self.logger(logging.DEBUG, 'xrootd.stat: filesize cmd: {}'.format(cmd))
            status_stat, out, err = execute(cmd)
            if status_stat == 0:
                ret['filesize'] = out.split('\n')[2].split()[-1]

            # xrdfs query checksum for getting checksum
            cmd = 'XrdSecPROTOCOL=gsi xrdfs %s:%s query checksum %s' % (self.hostname, self.port, path)
            self.logger(logging.DEBUG, 'xrootd.stat: checksum cmd: {}'.format(cmd))
            status_query, out, err = execute(cmd)
            if status_query == 0:
                chsum, value = out.strip('\n').split()
                ret[chsum] = value

        except Exception as e:
            raise exception.ServiceUnavailable(e)

        if 'filesize' not in ret:
            raise exception.ServiceUnavailable('Filesize could not be retrieved.')
        if PREFERRED_CHECKSUM != chsum or not chsum:
            msg = '{} does not match with {}'.format(chsum, PREFERRED_CHECKSUM)
            raise exception.RSEChecksumUnavailable(msg)

        return ret

    def pfn2path(self, pfn):
        """
        Returns the path of a file given the pfn, i.e. scheme and hostname are subtracted from the pfn.

        :param path: pfn of a file

        :returns: path.
        """
        self.logger(logging.DEBUG, 'xrootd.pfn2path: pfn: {}'.format(pfn))
        if pfn.startswith('//'):
            return pfn
        elif pfn.startswith('/'):
            return '/' + pfn
        else:
            prefix = self.attributes['prefix']
            path = pfn.partition(self.attributes['prefix'])[2]
            path = prefix + path
            return path

    def lfns2pfns(self, lfns):
        """
        Returns a fully qualified PFN for the file referred by path.

        :param path: The path to the file.

        :returns: Fully qualified PFN.
        """
        self.logger(logging.DEBUG, 'xrootd.lfns2pfns: lfns: {}'.format(lfns))
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
                pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'], '://', self.attributes['hostname'], ':', str(self.attributes['port']), prefix, lfn['path']])
            else:
                pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'], '://', self.attributes['hostname'], ':', str(self.attributes['port']), prefix, self._get_path(scope=scope, name=name)])
        return pfns

    def connect(self):
        """ Establishes the actual connection to the referred RSE.

            :param credentials: Provides information to establish a connection
                to the referred storage system. For S3 connections these are
                access_key, secretkey, host_base, host_bucket, progress_meter
                and skip_existing.

            :raises RSEAccessDenied
        """
        self.logger(logging.DEBUG, 'xrootd.connect: port: {}, hostname {}'.format(self.port, self.hostname))
        try:
            # The query stats call is not implemented on some xroot doors.
            # Workaround: fail, if server does not reply within 10 seconds for static config query
            cmd = 'XrdSecPROTOCOL=gsi XRD_REQUESTTIMEOUT=10 xrdfs %s:%s query config %s:%s' % (self.hostname, self.port, self.hostname, self.port)
            self.logger(logging.DEBUG, 'xrootd.connect: cmd: {}'.format(cmd))
            status, out, err = execute(cmd)
            if status != 0:
                raise exception.RSEAccessDenied(err)
        except Exception as e:
            raise exception.RSEAccessDenied(e)

    def close(self):
        """ Closes the connection to RSE."""
        pass

    def get(self, pfn, dest, transfer_timeout=None):
        """ Provides access to files stored inside connected the RSE.

            :param pfn: Physical file name of requested file
            :param dest: Name and path of the files when stored at the client
            :param transfer_timeout: Transfer timeout (in seconds) - dummy

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        self.logger(logging.DEBUG, 'xrootd.get: pfn: {}'.format(pfn))
        try:
            cmd = 'XrdSecPROTOCOL=gsi xrdcp -f %s %s' % (pfn, dest)
            self.logger(logging.DEBUG, 'xrootd.get: cmd: {}'.format(cmd))
            status, out, err = execute(cmd)
            if status == 54:
                raise exception.SourceNotFound()
            elif status != 0:
                raise exception.RucioException(err)
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def put(self, filename, target, source_dir, transfer_timeout=None):
        """
            Allows to store files inside the referred RSE.

            :param source: path to the source file on the client file system
            :param target: path to the destination file on the storage
            :param source_dir: Path where the to be transferred files are stored in the local file system
            :param transfer_timeout: Transfer timeout (in seconds) - dummy

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        self.logger(logging.DEBUG, 'xrootd.put: filename: {} target: {}'.format(filename, target))
        source_dir = source_dir or '.'
        source_url = '%s/%s' % (source_dir, filename)
        self.logger(logging.DEBUG, 'xrootd put: source url: {}'.format(source_url))
        path = self.path2pfn(target)
        if not os.path.exists(source_url):
            raise exception.SourceNotFound()
        try:
            cmd = 'XrdSecPROTOCOL=gsi xrdcp -f %s %s' % (source_url, path)
            self.logger(logging.DEBUG, 'xrootd.put: cmd: {}'.format(cmd))
            status, out, err = execute(cmd)
            if status != 0:
                raise exception.RucioException(err)
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def delete(self, pfn):
        """
            Deletes a file from the connected RSE.

            :param pfn: Physical file name

            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        self.logger(logging.DEBUG, 'xrootd.delete: pfn: {}'.format(pfn))
        if not self.exists(pfn):
            raise exception.SourceNotFound()
        try:
            path = self.pfn2path(pfn)
            cmd = 'XrdSecPROTOCOL=gsi xrdfs %s:%s rm %s' % (self.hostname, self.port, path)
            self.logger(logging.DEBUG, 'xrootd.delete: cmd: {}'.format(cmd))
            status, out, err = execute(cmd)
            if status != 0:
                raise exception.RucioException(err)
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def rename(self, pfn, new_pfn):
        """ Allows to rename a file stored inside the connected RSE.

            :param pfn:      Current physical file name
            :param new_pfn  New physical file name
            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        self.logger(logging.DEBUG, 'xrootd.rename: pfn: {}'.format(pfn))
        if not self.exists(pfn):
            raise exception.SourceNotFound()
        try:
            path = self.pfn2path(pfn)
            new_path = self.pfn2path(new_pfn)
            new_dir = new_path[:new_path.rindex('/') + 1]
            cmd = 'XrdSecPROTOCOL=gsi xrdfs %s:%s mkdir -p %s' % (self.hostname, self.port, new_dir)
            self.logger(logging.DEBUG, 'xrootd.stat: mkdir cmd: {}'.format(cmd))
            status, out, err = execute(cmd)
            cmd = 'XrdSecPROTOCOL=gsi xrdfs %s:%s mv %s %s' % (self.hostname, self.port, path, new_path)
            self.logger(logging.DEBUG, 'xrootd.stat: rename cmd: {}'.format(cmd))
            status, out, err = execute(cmd)
            if status != 0:
                raise exception.RucioException(err)
        except Exception as e:
            raise exception.ServiceUnavailable(e)
