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

    def __init__(self, rse):
        """ Initializes the protocol class with information defined for the referred storage system.

            :param rse Information about the referred storage system.
        """
        raise NotImplemented

    def pfn2uri(self, pfn):
        """ Transforms the physical file name into the local URI in the storage system.

            :param pfn Physical file name

            :returns: Storage specific URI of the physical file
        """
        raise NotImplemented

    def __register_file(self, pfn):
        """ Register data into local catalogue.

            :param pfn Physical file name
        """
        raise NotImplemented

    def __unregister_file(self, pfn):
        """ Unregister data at the local catalogue.

            :param pfn Physical file name
        """
        # TODO: Discuss if this is needed in RUCIO too?
        raise NotImplemented

    def exists(self, pfn):
        """ Checks if the requested file is known by the local storage system

            :param pfn Physical file name
            :returns: True if file exists, False if it doesn't
        """
        raise NotImplemented

    def connect(self):
        """ Establishes the connection to the referred storage system. """
        raise NotImplemented

    def close(self):
        """ Closes the connection to the storage system """
        raise NotImplemented

    def get(self, pfn, dest):
        """ Copies a file from the referred storage system to a specified destination in the local file system.

            :param pfn  Physical file name of the requested file
            :param dest Path where the files will be stored
        """
        raise NotImplemented

    def put(self, pfn, source_path):
        """ Allows to store a file at the referred storage system.

            :param pfn         Physical file name
            :param source_path Path where the to be transferred files are stored on the client
        """
        raise NotImplemented

    def delete(self, pfn):
        """ Deletes a file from the storage system

            :param pfn Physical file name
        """
        raise NotImplemented
