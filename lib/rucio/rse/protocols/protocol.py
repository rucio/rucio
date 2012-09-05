# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012


class RSEProtocol(object):
    """ This class is virtual and acts as a base to inherit new protocols from."""

    def __init__(self, props):
        """ Initializes the object with information about the referred RSE.

            :param props Properties derived from the RSE Repository
        """
        raise NotImplemented

    def pfn2uri(self, pfn):
        """ Transforms the physical file name into the local URI in the referred RSE.

            :param pfn Physical file name

            :returns: RSE specific URI of the physical file
        """
        raise NotImplemented

    def exists(self, pfn):
        """ Checks if the requested file is known by the referred RSE.

            :param pfn Physical file name

            :returns: True if the file exists, False if it doesn't

            :raise  ServiceUnavailable
        """
        raise NotImplemented

    def connect(self):
        """ Establishes the actual connection to the referred RSE.

            :param credentials User credentials to establish the connection to the RSE. See documentation of the according protocol for further information.

            :raises RSEAccessDenied
        """
        raise NotImplemented

    def close(self):
        """ Closes the connection to RSE."""
        raise NotImplemented

    def get(self, pfn, dest):
        """ Provides access to files stored inside connected the RSE.

            :param pfn Physical file name of requested file
            :param dest Name and path of the files when stored at the client

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
         """
        raise NotImplemented

    def put(self, source, target, source_dir):
        """ Allows to store files inside the referred RSE.

            :param source Physical file name
            :param target Name of the file on the storage system e.g. with prefixed scope
            :param source_dir Path where the to be transferred files are stored in the local file system

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        raise NotImplemented

    def delete(self, pfn):
        """ Deletes a file from the connected RSE.

            :param pfn Physical file name

            :raises ServiceUnavailable, SourceNotFound
        """
        raise NotImplemented

    def rename(self, lfn, new_lfn):
        """ Allows to rename a file stored inside the connected RSE.

            :param pfn      Current physical file name
            :param new_pfn  New physical file name

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        raise NotImplemented
