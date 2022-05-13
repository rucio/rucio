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

import json
import os
import logging

from rucio.common import exception
from rucio.common.config import get_config_dirs
from rucio.common.utils import execute, PREFERRED_CHECKSUM
from rucio.rse.protocols import protocol


def load_conf_file(file_name):
    config_dir = next(filter(lambda d: os.path.exists(os.path.join(d, file_name)), get_config_dirs()))
    with open(os.path.join(config_dir, file_name)) as f:
        return json.load(f)


class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using the rclone protocol."""

    def __init__(self, protocol_attr, rse_settings, logger=logging.log):
        """ Initializes the object with information about the referred RSE.

            :param props: Properties derived from the RSE Repository
        """
        super(Default, self).__init__(protocol_attr, rse_settings, logger=logger)
        if len(rse_settings['protocols']) == 1:
            raise exception.RucioException('rclone initialization requires at least one other protocol defined on the RSE. (from ssh, sftp, posix, webdav)')
        self.scheme = self.attributes['scheme']
        setuprclone = False
        for protocols in reversed(rse_settings['protocols']):
            if protocol_attr['impl'] == protocols['impl']:
                continue
            else:
                setuprclone = self.setuphostname(protocols)
                if setuprclone:
                    break

        if not setuprclone:
            raise exception.RucioException('rclone could not be initialized.')
        self.logger = logger

    def setuphostname(self, protocols):
        """ Initializes the rclone object with information about protocols in the referred RSE.

            :param protocols: Protocols in the RSE
        """
        if protocols['scheme'] in ['scp', 'rsync', 'sftp']:
            self.hostname = 'ssh_rclone_rse'
            self.host = protocols['hostname']
            self.port = str(protocols['port'])
            if protocols['extended_attributes'] is not None and 'user' in list(protocols['extended_attributes'].keys()):
                self.user = protocols['extended_attributes']['user']
            else:
                self.user = None
            try:
                data = load_conf_file('rclone-init.cfg')
                key_file = data[self.host + '_ssh']['key_file']
            except KeyError:
                self.logger(logging.ERROR, 'rclone.init: rclone-init.cfg:- Field value missing for "{}_ssh: key_file"'.format(self.host))
                return False
            try:
                if self.user:
                    cmd = 'rclone config create {0} sftp host {1} user {2} port {3} key_file {4}'.format(self.hostname, self.host, self.user, str(self.port), key_file)
                    self.logger(logging.DEBUG, 'rclone.init: cmd: {}'.format(cmd))
                    status, out, err = execute(cmd)
                    if status:
                        return False
                else:
                    cmd = 'rclone config create {0} sftp host {1} port {2} key_file {3}'.format(self.hostname, self.host, str(self.port), key_file)
                    self.logger(logging.DEBUG, 'rclone.init: cmd: {}'.format(cmd))
                    status, out, err = execute(cmd)
                    if status:
                        return False
            except Exception as e:
                raise exception.ServiceUnavailable(e)

        elif protocols['scheme'] == 'file':
            self.hostname = '%s_rclone_rse' % (protocols['scheme'])
            self.host = 'localhost'
            try:
                cmd = 'rclone config create {0} local'.format(self.hostname)
                self.logger(logging.DEBUG, 'rclone.init: cmd: {}'.format(cmd))
                status, out, err = execute(cmd)
                if status:
                    return False
            except Exception as e:
                raise exception.ServiceUnavailable(e)

        elif protocols['scheme'] in ['davs', 'https']:
            self.hostname = '%s_rclone_rse' % (protocols['scheme'])
            self.host = protocols['hostname']
            url = '%s://%s:%s%s' % (protocols['scheme'], protocols['hostname'], str(protocols['port']), protocols['prefix'])
            try:
                data = load_conf_file('rclone-init.cfg')
                bearer_token = data[self.host + '_webdav']['bearer_token']
            except KeyError:
                self.logger(logging.ERROR, 'rclone.init: rclone-init.cfg:- Field value missing for "{}_webdav: bearer_token"'.format(self.host))
                return False
            try:
                cmd = 'rclone config create {0} webdav url {1} vendor other bearer_token {2}'.format(self.hostname, url, bearer_token)
                self.logger(logging.DEBUG, 'rclone.init: cmd: {}'.format(cmd))
                status, out, err = execute(cmd)
                if status:
                    return False
            except Exception as e:
                raise exception.ServiceUnavailable(e)

        else:
            self.logger(logging.DEBUG, 'rclone.init: {} protocol impl not supported by rucio rclone'.format(protocols['impl']))
            return False

        return True

    def path2pfn(self, path):
        """
            Returns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.

        """
        self.logger(logging.DEBUG, 'rclone.path2pfn: path: {}'.format(path))
        if not path.startswith('rclone://'):
            return '%s://%s/%s' % (self.scheme, self.host, path)
        else:
            return path

    def exists(self, pfn):
        """ Checks if the requested file is known by the referred RSE.

            :param pfn: Physical file name

            :returns: True if the file exists, False if it doesn't

            :raise  ServiceUnavailable
        """
        self.logger(logging.DEBUG, 'rclone.exists: pfn: {}'.format(pfn))
        try:
            path = self.pfn2path(pfn)
            cmd = 'rclone lsf %s:%s' % (self.hostname, path)
            self.logger(logging.DEBUG, 'rclone.exists: cmd: {}'.format(cmd))
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
        self.logger(logging.DEBUG, 'rclone.stat: path: {}'.format(path))
        ret = {}
        chsum = None
        if path.startswith('rclone://'):
            path = self.pfn2path(path)

        try:
            # rclone stat for getting filesize
            cmd = 'rclone size {0}:{1}'.format(self.hostname, path)
            self.logger(logging.DEBUG, 'rclone.stat: filesize cmd: {}'.format(cmd))
            status_stat, out, err = execute(cmd)
            if status_stat == 0:
                fsize = (out.split('\n')[1]).split(' ')[4][1:]
                ret['filesize'] = fsize

            # rclone query checksum for getting md5 checksum
            cmd = 'rclone md5sum %s:%s' % (self.hostname, path)
            self.logger(logging.DEBUG, 'rclone.stat: checksum cmd: {}'.format(cmd))
            status_query, out, err = execute(cmd)

            if status_query == 0:
                chsum = 'md5'
                val = out.strip('  ').split()
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
        if pfn.startswith('rclone://'):
            self.logger(logging.DEBUG, 'rclone.pfn2path: pfn: {}'.format(pfn))
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
        self.logger(logging.DEBUG, 'rclone.lfns2pfns: lfns: {}'.format(lfns))
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
                pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'], '://', self.host, ':', prefix, lfn['path']])
            else:
                pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'], '://', self.host, ':', prefix, self._get_path(scope=scope, name=name)])
        return pfns

    def connect(self):
        """ Establishes the actual connection to the referred RSE.

            :raises RSEAccessDenied
        """
        self.logger(logging.DEBUG, 'rclone.connect: hostname {}'.format(self.hostname))
        try:
            cmd = 'rclone lsd %s:' % (self.hostname)
            status, out, err = execute(cmd)
            if status:
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
        self.logger(logging.DEBUG, 'rclone.get: pfn: {}'.format(pfn))
        try:
            path = self.pfn2path(pfn)
            cmd = 'rclone copyto %s:%s %s' % (self.hostname, path, dest)
            self.logger(logging.DEBUG, 'rclone.get: cmd: {}'.format(cmd))
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
        self.logger(logging.DEBUG, 'rclone.put: filename: {} target: {}'.format(filename, target))
        source_dir = source_dir or '.'
        source_url = '%s/%s' % (source_dir, filename)
        self.logger(logging.DEBUG, 'rclone.put: source url: {}'.format(source_url))

        path = self.pfn2path(target)
        if not os.path.exists(source_url):
            raise exception.SourceNotFound()
        try:
            cmd = 'rclone copyto %s %s:%s' % (source_url, self.hostname, path)
            self.logger(logging.DEBUG, 'rclone.put: cmd: {}'.format(cmd))
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
        self.logger(logging.DEBUG, 'rclone.delete: pfn: {}'.format(pfn))
        if not self.exists(pfn):
            raise exception.SourceNotFound()
        try:
            path = self.pfn2path(pfn)
            cmd = 'rclone delete %s:%s' % (self.hostname, path)
            self.logger(logging.DEBUG, 'rclone.delete: cmd: {}'.format(cmd))
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
        self.logger(logging.DEBUG, 'rclone.rename: pfn: {}'.format(pfn))
        if not self.exists(pfn):
            raise exception.SourceNotFound()
        try:
            path = self.pfn2path(pfn)
            new_path = self.pfn2path(new_pfn)
            cmd = 'rclone moveto %s:%s %s:%s' % (self.hostname, path, self.hostname, new_path)
            self.logger(logging.DEBUG, 'rclone.stat: rename cmd: {}'.format(cmd))
            status, out, err = execute(cmd)
            if status != 0:
                raise exception.RucioException(err)
        except Exception as e:
            raise exception.ServiceUnavailable(e)
