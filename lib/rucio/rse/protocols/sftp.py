# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012
# - Yun-Pin Sun, <yun-pin.sun@cern.ch>, 2012


import pysftp
from subprocess import call

from rucio.common import exception
from rucio.rse.protocols import protocol


class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using the SFTP protocol."""

    def __init__(self, props):
        """ Initializes the object with information about the referred RSE."""
        self.rse = props

    def pfn2uri(self, pfn):
        """ Transforms the physical file name into the local URI in the referred RSE.

            :param pfn Physical file name

            :returns: RSE specific URI of the physical file
        """
        return self.rse['protocol']['prefix'] + pfn

    def exists(self, pfn):
        """ Checks if the requested file is known by the referred RSE.

            :param pfn Physical file name

            :returns: True if the file exists, False if it doesn't

            :raise  ServiceUnavailable
        """
        status = ''
        try:
            cmd = 'stat ' + self.pfn2uri(pfn)
            status = self.__connection.execute(cmd)
        except Exception as e:
            raise exception.ServiceUnavailable(e)
        if status[0].endswith('No such file or directory\n'):
            return False
        return True

    def connect(self, credentials):
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
        try:
            credentials['host'] = self.rse['protocol']['hostname']
            self.__connection = pysftp.Connection(**credentials)
        except Exception as e:
            raise exception.RSEAccessDenied(e)

    def close(self):
        """ Closes the connection to RSE."""
        self.__connection.close()

    def get(self, pfn, dest):
        """ Provides access to files stored inside connected the RSE.

            :param pfn Physical file name of requested file
            :param dest Name and path of the files when stored at the client

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
         """
        try:
            self.__connection.get(self.pfn2uri(pfn), dest)
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

    def put(self, source, target, source_dir=None):
        """ Allows to store files inside the referred RSE.

            :param source Physical file name
            :param target Name of the file on the storage system e.g. with prefixed scope
            :param source_dir Path where the to be transferred files are stored in the local file system

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        if source_dir:
            sf = source_dir + '/' + source
        else:
            sf = source
        try:
            self.__connection.put(sf, self.pfn2uri(target))
        except IOError as e:
                try:
                    self.__connection.execute('mkdir -p %s' % '/'.join(self.pfn2uri(target).split('/')[0:-1]))
                    self.__connection.put(sf, self.pfn2uri(target))
                except Exception, e:
                    raise exception.DestinationNotAccessible(e)
        except OSError as e:
            if e.errno == 2:
                raise exception.SourceNotFound(e)
            else:
                raise exception.ServiceUnavailable(e)

    def delete(self, pfn):
        """ Deletes a file from the connected RSE.

            :param pfn Physical file name

            :raises ServiceUnavailable, SourceNotFound
        """
        status = ''
        cmd = 'rm ' + self.pfn2uri(pfn)
        try:
            status = self.__connection.execute(cmd)
        except Exception as e:
            raise exception.ServiceUnavailable(e)
        if len(status):
            if status[0].endswith('No such file or directory\n'):
                raise exception.SourceNotFound(IOError({'errno': 2, 'file': self.pfn2uri(pfn)}))

    def rename(self, pfn, new_pfn):
        """ Allows to rename a file stored inside the connected RSE.

            :param pfn      Current physical file name
            :param new_pfn  New physical file name

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        try:
            self.__connection.execute('mkdir -p %s' % '/'.join(self.pfn2uri(new_pfn).split('/')[0:-1]))
            print 'mkdir -p %s' % '/'.join(self.pfn2uri(new_pfn).split('/')[0:-1])
            self.__connection.execute('mv %s %s' % (self.pfn2uri(pfn), self.pfn2uri(new_pfn)))
            print 'mv %s %s' % (self.pfn2uri(pfn), self.pfn2uri(new_pfn))
        except IOError as e:
            if e.errno == 2:
                if self.exists(self.pfn2uri(pfn)):
                    raise exception.SourceNotFound(e)
                else:
                    raise exception.DestinationNotAccessible(e)
            else:
                raise exception.ServiceUnavailable(e)
