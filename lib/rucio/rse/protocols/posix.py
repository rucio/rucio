# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012


import os
import shutil
from subprocess import call

from rucio.common import exception
from rucio.rse.protocols import protocol


class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using the local filesystem."""

    def path2pfn(self, path):
        """
            Retruns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.

        """
        return ''.join([self.rse['scheme'], '://', path])

    def exists(self, path):
        """
            Checks if the requested file is known by the referred RSE.

            :param path: Physical file name

            :returns: True if the file exists, False if it doesn't

            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        status = ''
        try:
            status = os.path.exists(path)
        except Exception as e:
            raise exception.ServiceUnavailable(e)
        return status

    def connect(self, credentials):
        """
            Establishes the actual connection to the referred RSE.

            :param: credentials needed to establish a connection with the stroage.

            :raises RSEAccessDenied: if no connection could be established.
        """
        pass

    def close(self):
        """ Closes the connection to RSE."""
        pass

    def get(self, path, dest):
        """ Provides access to files stored inside connected the RSE.

            :param path: Physical file name of requested file
            :param dest: Name and path of the files when stored at the client

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
         """
        try:
            shutil.copy(path, dest)
        except IOError as e:
            try:  # To check if the error happend local or remote
                with open(dest, 'wb'):
                    pass
                call(['rm', '-rf', dest])
            except IOError as e:
                if e.errno == 2:
                    raise exception.DestinationNotAccessible(e)
                else:
                    raise exception.ServiceUnavailable(e)
            if e.errno == 2:
                raise exception.SourceNotFound(e)
            else:
                raise exception.ServiceUnavailable(e)

    def put(self, source, target, source_dir=None):
        """
            Allows to store files inside the referred RSE.

            :param source: path to the source file on the client file system
            :param target: path to the destination file on the storage
            :param source_dir: Path where the to be transferred files are stored in the local file system

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        if source_dir:
            sf = source_dir + '/' + source
        else:
            sf = source
        try:
            dirs = os.path.dirname(target)
            if not os.path.exists(dirs):
                os.makedirs(dirs)
            shutil.copy(sf, target)
        except IOError as e:
            if e.errno == 2:
                raise exception.SourceNotFound(e)
            elif not self.exists(self.rse['prefix']):
                path = ''
                for p in self.rse['prefix'].split('/'):
                    path += p + '/'
                    os.mkdir(path)
                shutil.copy(sf, self.get_path(target))
            else:
                raise exception.DestinationNotAccessible(e)

    def delete(self, path):
        """ Deletes a file from the connected RSE.

            :param path: path to the to be deleted file

            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        try:
            os.remove(path)
        except OSError as e:
            if e.errno == 2:
                raise exception.SourceNotFound(e)

    def rename(self, path, new_path):
        """ Allows to rename a file stored inside the connected RSE.

            :param path: path to the current file on the storage
            :param new_path: path to the new file on the storage

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        try:
            if not os.path.exists(os.path.dirname(new_path)):
                os.makedirs(os.path.dirname(new_path))
            os.rename(path, new_path)
        except IOError as e:
            if e.errno == 2:
                if self.exists(self.get_path(path)):
                    raise exception.SourceNotFound(e)
                else:
                    raise exception.DestinationNotAccessible(e)
            else:
                raise exception.ServiceUnavailable(e)
