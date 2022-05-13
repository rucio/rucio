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

import pysftp
from subprocess import call

from rucio.common import exception
from rucio.rse.protocols import protocol


class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using the SFTP protocol."""

    def exists(self, pfn):
        """
            Checks if the requested file is known by the referred RSE.

            :param path: Physical file name

            :returns: True if the file exists, False if it doesn't

            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        status = ''
        try:
            cmd = 'stat ' + self.pfn2path(pfn)
            status = self.__connection.execute(cmd)
        except Exception as e:
            raise exception.ServiceUnavailable(e)
        for s in status:
            if s.endswith('No such file or directory\n'):
                return False

        return True

    def connect(self):
        """
            Establishes the actual connection to the referred RSE.

            :param credentials: needed to establish a connection with the stroage.

            :raises RSEAccessDenied: if no connection could be established.
        """
        try:
            self.rse['credentials']['host'] = self.attributes['hostname']
            self.__connection = pysftp.Connection(**self.rse['credentials'])
        except Exception as e:
            raise exception.RSEAccessDenied(e)

    def close(self):
        """ Closes the connection to RSE."""
        self.__connection.close()

    def get(self, pfn, dest, transfer_timeout=None):
        """
            Provides access to files stored inside connected the RSE.

            :param path: Physical file name of requested file
            :param dest: Name and path of the files when stored at the client
            :param transfer_timeout: Transfer timeout (in seconds) - dummy

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
         """
        try:
            self.__connection.get(self.pfn2path(pfn), dest)
        except IOError as e:
            try:  # To check if the error happend local or remote
                with open(dest, 'wb'):
                    pass
                call(['rm', dest])
            except IOError as e:
                if e.errno == 2:
                    raise exception.DestinationNotAccessible(e)
                else:
                    raise exception.ServiceUnavailable(e)
            if e.errno == 2:
                raise exception.SourceNotFound(e)
            else:
                raise exception.ServiceUnavailable(e)

    def put(self, source, target, source_dir=None, transfer_timeout=None):
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
        if source_dir:
            sf = source_dir + '/' + source
        else:
            sf = source
        try:
            self.__connection.put(sf, self.pfn2path(target))
        except IOError:
            try:
                self.__connection.execute('mkdir -p %s' % '/'.join(self.pfn2path(target).split('/')[0:-1]))
                self.__connection.put(sf, self.pfn2path(target))
            except Exception as e:
                raise exception.DestinationNotAccessible(e)
        except OSError as e:
            if e.errno == 2:
                raise exception.SourceNotFound(e)
            else:
                raise exception.ServiceUnavailable(e)

    def delete(self, pfn):
        """
            Deletes a file from the connected RSE.

            :param path: path to the to be deleted file

            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        status = ''
        cmd = 'rm ' + self.pfn2path(pfn)
        try:
            status = self.__connection.execute(cmd)
        except Exception as e:
            raise exception.ServiceUnavailable(e)
        if len(status):
            if status[0].endswith('No such file or directory\n'):
                raise exception.SourceNotFound(IOError({'errno': 2, 'file': pfn}))

    def rename(self, pfn, new_pfn):
        """ Allows to rename a file stored inside the connected RSE.

            :param path: path to the current file on the storage
            :param new_path: path to the new file on the storage

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        try:
            path = self.pfn2path(pfn)
            new_path = self.pfn2path(new_pfn)
            self.__connection.execute('mkdir -p %s' % '/'.join(new_path.split('/')[0:-1]))
            self.__connection.execute('mv %s %s' % (path, new_path))
        except IOError as e:
            if e.errno == 2:
                if self.exists(path):
                    raise exception.SourceNotFound(e)
                else:
                    raise exception.DestinationNotAccessible(e)
            else:
                raise exception.ServiceUnavailable(e)

    def pfn2path(self, pfn):
        tmp = list(self.parse_pfns(pfn).values())[0]
        return '/'.join([tmp['prefix'], tmp['path'], tmp['name']])

    def stat(self, pfn):
        """ Determines the file size in bytes  of the provided file.

            :param pfn: The PFN the file.

            :returns: a dict containing the key filesize.
        """
        path = self.pfn2path(pfn)
        info = self.__connection.execute('stat %s' % path)
        return {'filesize': int(info[1].split()[1])}
