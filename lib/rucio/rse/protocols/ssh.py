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

import logging
import os
import re

from rucio.common import exception
from rucio.common.utils import execute, PREFERRED_CHECKSUM
from rucio.rse.protocols import protocol


class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using the SSH protocol."""

    def __init__(self, protocol_attr, rse_settings, logger=logging.log):
        """ Initializes the object with information about the referred RSE.

            :param props: Properties derived from the RSE Repository
        """
        super(Default, self).__init__(protocol_attr, rse_settings, logger=logger)

        self.scheme = self.attributes['scheme']
        self.hostname = self.attributes['hostname']
        self.port = str(self.attributes['port'])
        self.path = None
        if self.attributes['extended_attributes'] is not None and\
           'user' in list(self.attributes['extended_attributes'].keys()):
            self.sshuser = self.attributes['extended_attributes']['user'] + '@'
        else:
            self.sshuser = ''
        self.logger = logger

    def path2pfn(self, path):
        """
            Returns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.

        """
        self.logger(logging.DEBUG, 'ssh.path2pfn: path: {}'.format(path))
        if not path.startswith(str(self.scheme) + '://'):
            return '%s://%s%s:%s/%s' % (self.scheme, self.sshuser, self.hostname, self.port, path)
        else:
            return path

    def exists(self, pfn):
        """ Checks if the requested file is known by the referred RSE.

            :param pfn: Physical file name

            :returns: True if the file exists, False if it doesn't

            :raise  ServiceUnavailable
        """
        self.logger(logging.DEBUG, 'ssh.exists: pfn: {}'.format(pfn))
        try:
            path = self.pfn2path(pfn)
            cmd = 'ssh -p %s %s%s find %s' % (self.port, self.sshuser, self.hostname, path)
            self.logger(logging.DEBUG, 'ssh.exists: cmd: {}'.format(cmd))
            status, out, err = execute(cmd)
            if status:
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
        self.logger(logging.DEBUG, 'ssh.stat: path: {}'.format(path))
        ret = {}
        chsum = None
        path = self.pfn2path(path)

        try:
            # ssh stat for getting filesize
            cmd = 'ssh -p {0} {1}{2} stat --printf="%s" {3}'.format(self.port, self.sshuser, self.hostname, path)
            self.logger(logging.DEBUG, 'ssh.stat: filesize cmd: {}'.format(cmd))
            status_stat, out, err = execute(cmd)
            if status_stat == 0:
                ret['filesize'] = out

            # ssh query checksum for getting md5 checksum
            cmd = 'ssh -p %s %s%s md5sum %s' % (self.port, self.sshuser, self.hostname, path)
            self.logger(logging.DEBUG, 'ssh.stat: checksum cmd: {}'.format(cmd))
            status_query, out, err = execute(cmd)

            if status_query == 0:
                chsum = 'md5'
                val = out.strip(' ').split()
                ret[chsum] = val[0]

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
        Returns the path of a file given the pfn, i.e. scheme, user and hostname are subtracted from the pfn.

        :param path: pfn of a file

        :returns: path.
        """
        path = pfn
        if pfn.startswith(str(self.scheme) + '://'):
            self.logger(logging.DEBUG, 'ssh.pfn2path: pfn: {}'.format(pfn))
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
        self.logger(logging.DEBUG, 'ssh.lfns2pfns: lfns: {}'.format(lfns))
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
                pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'], '://', self.sshuser, self.hostname, ':', self.port, prefix, lfn['path']])
            else:
                pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'], '://', self.sshuser, self.hostname, ':', self.port, prefix, self._get_path(scope=scope, name=name)])
        return pfns

    def connect(self):
        """ Establishes the actual connection to the referred RSE.

            :raises RSEAccessDenied
        """
        self.logger(logging.DEBUG, 'ssh.connect: port: {}, hostname {}, ssh-user {}'.format(self.port, self.hostname, self.sshuser))
        try:
            cmd = 'ssh -p %s %s%s echo ok 2>&1' % (self.port, self.sshuser, self.hostname)
            status, out, err = execute(cmd)
            checker = re.search(r'ok', out)
            if not checker:
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
        self.logger(logging.DEBUG, 'ssh.get: pfn: {}'.format(pfn))
        try:
            path = self.pfn2path(pfn)
            destdir = os.path.dirname(dest)
            cmd = 'mkdir -p %s' % (destdir)
            self.logger(logging.DEBUG, 'ssh.get: cmd: {}'.format(cmd))
            status, out, err = execute(cmd)
            cmd = 'scp %s%s:%s %s' % (self.sshuser, self.hostname, path, dest)
            self.logger(logging.DEBUG, 'ssh.get: cmd: {}'.format(cmd))
            status, out, err = execute(cmd)
            if status:
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
        self.logger(logging.DEBUG, 'ssh.put: filename: {} target: {}'.format(filename, target))
        source_dir = source_dir or '.'
        source_url = '%s/%s' % (source_dir, filename)
        self.logger(logging.DEBUG, 'ssh.put: source url: {}'.format(source_url))

        path = self.pfn2path(target)
        pathdir = os.path.dirname(path)
        if not os.path.exists(source_url):
            raise exception.SourceNotFound()
        try:
            cmd = 'ssh %s%s "mkdir -p %s" && scp %s %s%s:%s' % (self.sshuser, self.hostname, pathdir, source_url, self.sshuser, self.hostname, path)
            self.logger(logging.DEBUG, 'ssh.put: cmd: {}'.format(cmd))
            status, out, err = execute(cmd)
            if status:
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
        self.logger(logging.DEBUG, 'ssh.delete: pfn: {}'.format(pfn))
        if not self.exists(pfn):
            raise exception.SourceNotFound()
        try:
            path = self.pfn2path(pfn)
            cmd = 'ssh -p %s %s%s rm %s' % (self.port, self.sshuser, self.hostname, path)
            self.logger(logging.DEBUG, 'ssh.delete: cmd: {}'.format(cmd))
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
        self.logger(logging.DEBUG, 'ssh.rename: pfn: {}'.format(pfn))
        if not self.exists(pfn):
            raise exception.SourceNotFound()
        try:
            path = self.pfn2path(pfn)
            new_path = self.pfn2path(new_pfn)
            new_dir = new_path[:new_path.rindex('/') + 1]
            cmd = 'ssh -p %s %s%s "mkdir -p %s"' % (self.port, self.sshuser, self.hostname, new_dir)
            self.logger(logging.DEBUG, 'ssh.rename: mkdir cmd: {}'.format(cmd))
            status, out, err = execute(cmd)
            cmd = 'ssh -p %s %s%s mv %s %s' % (self.port, self.sshuser, self.hostname, path, new_path)
            self.logger(logging.DEBUG, 'ssh.rename: rename cmd: {}'.format(cmd))
            status, out, err = execute(cmd)
            if status != 0:
                raise exception.RucioException(err)
        except Exception as e:
            raise exception.ServiceUnavailable(e)


class Rsync(Default):
    """ Implementing access to RSEs using the ssh.Rsync implementation."""

    def stat(self, path):
        """
        Returns the stats of a file.

        :param path: path to file

        :raises ServiceUnavailable: if some generic error occured in the library.

        :returns: a dict with two keys, filesize and an element of GLOBALLY_SUPPORTED_CHECKSUMS.
        """
        self.logger(logging.DEBUG, 'rsync.stat: path: {}'.format(path))
        ret = {}
        chsum = None
        path = self.pfn2path(path)

        try:
            # rsync stat for getting filesize
            cmd = "rsync -an --size-only -e 'ssh -p {0}' --remove-source-files  {1}{2}:{3}".format(self.port, self.sshuser, self.hostname, path)
            self.logger(logging.DEBUG, 'rsync.stat: filesize cmd: {}'.format(cmd))
            status_stat, out, err = execute(cmd)
            if status_stat == 0:
                sizestr = out.split(" ")[-4]
                ret['filesize'] = sizestr.replace(',', '')

            # rsync query checksum for getting md5 checksum
            cmd = 'ssh -p %s %s%s md5sum %s' % (self.port, self.sshuser, self.hostname, path)
            self.logger(logging.DEBUG, 'rsync.stat: checksum cmd: {}'.format(cmd))
            status_query, out, err = execute(cmd)

            if status_query == 0:
                chsum = 'md5'
                val = out.strip(' ').split()
                ret[chsum] = val[0]

        except Exception as e:
            raise exception.ServiceUnavailable(e)

        if 'filesize' not in ret:
            raise exception.ServiceUnavailable('Filesize could not be retrieved.')
        if PREFERRED_CHECKSUM != chsum or not chsum:
            msg = '{} does not match with {}'.format(chsum, PREFERRED_CHECKSUM)
            raise exception.RSEChecksumUnavailable(msg)

        return ret

    def connect(self):
        """ Establishes the actual connection to the referred RSE.

            :raises RSEAccessDenied
        """
        self.logger(logging.DEBUG, 'rsync.connect: port: {}, hostname {}, ssh-user {}'.format(self.port, self.hostname, self.sshuser))
        try:
            cmd = 'ssh -p %s %s%s echo ok 2>&1' % (self.port, self.sshuser, self.hostname)
            status, out, err = execute(cmd)
            checker = re.search(r'ok', out)
            if not checker:
                raise exception.RSEAccessDenied(err)
            cmd = 'ssh -p %s %s%s type rsync' % (self.port, self.sshuser, self.hostname)
            status, out, err = execute(cmd)
            checker = re.search(r'rsync is', out)
            if not checker:
                raise exception.RSEAccessDenied(err)
            self.path = out.split(" ")[2][:-1]

        except Exception as e:
            raise exception.RSEAccessDenied(e)

    def get(self, pfn, dest, transfer_timeout=None):
        """ Provides access to files stored inside connected the RSE.

            :param pfn: Physical file name of requested file
            :param dest: Name and path of the files when stored at the client
            :param transfer_timeout: Transfer timeout (in seconds) - dummy

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        self.logger(logging.DEBUG, 'rsync.get: pfn: {}'.format(pfn))
        try:
            path = self.pfn2path(pfn)
            destdir = os.path.dirname(dest)
            cmd = 'mkdir -p %s && rsync -az -e "ssh -p %s" --append-verify %s%s:%s %s' % (destdir, self.port, self.sshuser, self.hostname, path, dest)
            self.logger(logging.DEBUG, 'rsync.get: cmd: {}'.format(cmd))
            status, out, err = execute(cmd)
            if status:
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
        self.logger(logging.DEBUG, 'rsync.put: filename: {} target: {}'.format(filename, target))
        source_dir = source_dir or '.'
        source_url = '%s/%s' % (source_dir, filename)
        self.logger(logging.DEBUG, 'rsync.put: source url: {}'.format(source_url))

        path = self.pfn2path(target)
        pathdir = os.path.dirname(path)
        if not os.path.exists(source_url):
            raise exception.SourceNotFound()

        try:
            cmd = 'ssh -p %s %s%s "mkdir -p %s" && rsync -az -e "ssh -p %s" --append-verify %s %s%s:%s' % (self.port, self.sshuser, self.hostname, pathdir, self.port, source_url, self.sshuser, self.hostname, path)
            self.logger(logging.DEBUG, 'rsync.put: cmd: {}'.format(cmd))
            status, out, err = execute(cmd)
            if status:
                raise exception.RucioException(err)
        except Exception as e:
            raise exception.ServiceUnavailable(e)
