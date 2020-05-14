# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Nicolo Magini, <nicolo.magini@cern.ch>, 2018
#
# PY3K COMPATIBLE

from rucio.common import exception
from rucio.rse.protocols import protocol


class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using the local filesystem."""

    def __init__(self, protocol_attr, rse_settings, logger=None):
        """ Initializes the object with information about the referred RSE.

            :param props Properties derived from the RSE Repository
        """
        super(Default, self).__init__(protocol_attr, rse_settings, logger=logger)
        self.attributes.pop('determinism_type', None)
        self.files = []

    def path2pfn(self, path):
        """
            Retruns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.

        """
        return ''.join([self.rse['scheme'], '://%s' % self.rse['hostname'], path])

    def exists(self, pfn):
        """ Checks if the requested file is known by the referred RSE.

            :param pfn Physical file name

            :returns: True if the file exists, False if it doesn't

            :raise  ServiceUnavailable
        """
        return pfn in self.files

    def connect(self):
        """ Establishes the actual connection to the referred RSE.

            :param credentials Provide all necessary information to establish a connection
                to the referred storage system. Some is loaded from the repository inside the
                RSE class and some must be provided specific for the SFTP protocol like
                username, password, private_key, private_key_pass, port.
                For details about possible additional parameters and details about their usage
                see the pysftp.Connection() documentation.
                NOTE: the host parametrer is overwritten with the value provided by the repository

            :raise RSEAccessDenied
        """
        pass

    def close(self):
        """ Closes the connection to RSE."""
        pass

    def get(self, pfn, dest, transfer_timeout=None):
        """ Provides access to files stored inside connected the RSE.

            :param pfn Physical file name of requested file
            :param dest Name and path of the files when stored at the client
            :param transfer_timeout Transfer timeout (in seconds) - dummy

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
         """
        if pfn not in self.files:
            raise exception.SourceNotFound(pfn)

    def put(self, source, target, source_dir=None, transfer_timeout=None):
        """ Allows to store files inside the referred RSE.

            :param source Physical file name
            :param target Name of the file on the storage system e.g. with prefixed scope
            :param source_dir Path where the to be transferred files are stored in the local file system
            :param transfer_timeout Transfer timeout (in seconds) - dummy

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        self.files.append(target)

    def delete(self, pfn):
        """ Deletes a file from the connected RSE.

            :param pfn Physical file name

            :raises ServiceUnavailable, SourceNotFound
        """
        pass

    def rename(self, pfn, new_pfn):
        """ Allows to rename a file stored inside the connected RSE.

            :param pfn      Current physical file name
            :param new_pfn  New physical file name

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        pass
