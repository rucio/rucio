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

from rucio.common import exception
from rucio.rse.protocols import protocol


class Default(protocol.RSEProtocol):
    """ Implementing access to storage systems using the SFTP protocol
        in its standard/default implementation, meaning no storage specific
        customizations are made.
    """

    def __init__(self, rse):
        """ Initializes the object with information about the referred storage system."""
        self.rse = rse

    def pfn2uri(self, pfn):
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
            :raise ServiceUnavailable
        """
        status = ''
        try:
            cmd = 'stat ' + self.pfn2uri(pfn)
            status = self.__connection.execute(cmd)
        except Exception as e:
            raise exception.ServiceUnavailable(e)
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
            :raise FailedToLogin
        """
        try:
            credentials['host'] = self.rse.static['url']
            self.__connection = pysftp.Connection(**credentials)
        except Exception as e:
            raise exception.FailedToLogin({'exception': e, 'storageurl': self.rse.static['url'], 'credentials': credentials})

    def get(self, pfn, dest):
        """ Provides access to files stored inside the storage system.

            :param pfn Physical file name of requested file
            :param dest Name and path of the files when stored at the client
            :raises FileNotFound
        """

        try:
            self.__connection.get(self.pfn2uri(pfn), dest)
        except IOError as e:
            raise exception.FileNotFound(str(e))

    def put(self, pfn, source_path):
        """ Allows to store files inside the referred storage system.

            :param pfn Physical file name
            :param source_path Path where the to be transferred files are stored in the local file system
            :raises ServiceUnavailable, FileNotFound
        """
        source = source_path + '/' + pfn if source_path else pfn
        try:
            self.__connection.put(source, self.pfn2uri(pfn))
            self.__register_file(pfn)
        except IOError as e:
            if not self.exists(self.rse.static['pfn_prefix']):
                cmd = 'mkdir '
                for p in self.rse.static['pfn_prefix'].split('/'):
                    cmd += p + '/'
                    self.__connection.execute(cmd)
                self.__connection.put(source, self.pfn2uri(pfn))
            else:
                raise exception.ServiceUnavailable(e)
        except OSError as e:
            raise exception.FileNotFound('Local file %s not found' % source)

    def delete(self, pfn):
        """ Deletes a file from the referred storage system.

            :param pfn Physical file name
            :raise FileNotFound
        """
        status = ''
        try:
            cmd = 'rm ' + self.pfn2uri(pfn)
            status = self.__connection.execute(cmd)
            self.__unregister_file(pfn)
        except Exception as e:
            raise exception.ServiceUnavailable(e)
        if len(status):
            raise exception.ServiceUnavailable(str(status))

    def close(self):
        """ Closes the current connection to the storage system. """
        self.__connection.close()
