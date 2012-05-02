# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012


import pysftp

from rucio.rse.protocols import protocol
from rucio.rse.rseexception import RSEException


class Default(protocol.RSEProtocol):
    """ Implementing access to storage systems using the SFTP protocol
        in its standard/default implementation, meaning no storage specific
        customizations are made.
    """

    def __init__(self, rse):
        """ Initializes the object with information about the referred storage system."""
        self.rse = rse

    def __pfn2uri(self, pfn):
        """ Transforms the physical file name into the local URI in the referred storage system.

            :param pfn Physical file name

            :returns: Storage specific URI of the physical file
        """
        return self.rse.static['pfn_prefix'] + pfn

    def __register_file(self, pfn):
        """ Register data in the local catalogue.

            :param pfn Physical file name
        """
        # TODO: Discuss if we need this in RUCIO too?
        pass

    def __unregister_file(self, pfn):
        """ Unregister data in the local catalogue.

            :param pfn Physical file name
        """
        # TODO: Discuss if we need this in RUCIO too?
        pass

    def exists(self, pfn):
        """ Checks if the requested file is known by the referred storage system.

            :param pfn Physical file name

            :returns: True if the file exists, False if it doesn't
        """
        status = ''
        try:
            cmd = 'stat ' + self.__pfn2uri(pfn)
            status = self.__connection.execute(cmd)
        except Exception:
            raise RSEException(500, 'Failed using storage system.', data={'exception': e, 'id': self.rse.static['url'], 'credentials': credentials})
        if status[0].startswith('stat: cannot stat'):
            return False
        return True

    def connect(self, credentials):
        """ Establishes the actual connection to the referred storage system using SFTP as protocol.

            :param credentials Provide all necessary information to establish a connection
                to the referred storage system. Some is loaded from the repository inside the
                RSE class and some must be provided specific for the SFTP protocol like
                username, password, private_key, private_key_pass, port.
                For details about possible additional parameters and details about their usage
                see the pysftp.Connection() documentation.
                NOTE: the host parametrer is overwritten with the value provided by the repository
        """
        try:
            credentials['host'] = self.rse.static['url']
            self.__connection = pysftp.Connection(**credentials)
        except Exception as e:
            raise RSEException(500, 'Failed to log-in into ' + self.rse.static['url'], data={'exception': e, 'id': self.rse.static['url'], 'credentials': credentials})

    def get(self, pfn, dest):
        """ Provides access to files stored inside the storage system.

            :param pfn Physical file name of requested file
            :param dest Name and path of the files when stored at the client
        """

        status = ''
        try:
            status = self.__connection.get(self.__pfn2uri(pfn), dest)
        except IOError as e:
            raise RSEException(404, 'Error while requesting file', data={'exception': e, 'status': str(status)})

    def put(self, pfn, source_path):
        """ Allows to store files inside the referred storage system.

            :param pfn Physical file name
            :param source_path Path where the to be transferred files are storaed in the local file system
        """
        status = ""
        try:
            source = source_path + '/' + pfn if source_path else pfn
            status = self.__connection.put(source, self.__pfn2uri(pfn))
            self.__register_file(pfn)
        except OSError as e:
            raise RSEException(404, 'Error while puting file', data={'exception': e, 'status': str(status)})

    def delete(self, pfn):
        """ Deletes a file from the referred storage system.

            :param pfn Physical file name
        """
        status = ''
        try:
            cmd = 'rm ' + self.__pfn2uri(pfn)
            status = self.__connection.execute(cmd)
            self.__unregister_file(pfn)
        except Exception as e:
            raise RSEException(404, 'Error while deleting file', data={'exception': e, 'status': str(status)})
        if len(status):
            raise RSEException(404, 'Error while deleting file', data={'status': str(status)})

    def close(self):
        """ Closes the current connection to the storage system. """
        self.__connection.close()
