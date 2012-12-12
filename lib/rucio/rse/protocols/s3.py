# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2012


from subprocess import call
# IMPORTANT: If the order of the S3 imports is changed, they fail!
from S3.Exceptions import S3Error, InvalidFileError
from S3.S3 import S3
from S3.Config import Config
from S3.S3Uri import S3Uri

from rucio.common import exception
from rucio.rse.protocols import protocol


class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using the S3 protocol."""

    def __init__(self, props):
        """ Initializes the object with information about the referred RSE.

            :param props Properties derived from the RSE Repository
        """
        self.rse = props

    def pfn2uri(self, pfn):
        """ Transforms the physical file name into the local URI in the referred RSE.

            :param pfn Physical file name

            :returns: RSE specific URI of the physical file
        """
        # On S3 the default naming convention is not supproted
        # It is therefore changed to bucket being either user, group, ... followed by the
        # scope as prefix and the lfn as actual file name
        # IMPORTANT: The prefix defined in the RSE properties are ignored due to system constraints
        tmp = pfn.split('/')
        bucket = tmp[0].split('.')[0].upper()
        scope = tmp[0].split('.')[1]
        lfn = tmp[-1]
        print 'URI %s' % ('s3://%s/%s/%s' % (bucket, scope, lfn))
        return 's3://%s/%s/%s' % (bucket, scope, lfn)

    def exists(self, pfn):
        """ Checks if the requested file is known by the referred RSE.

            :param pfn Physical file name

            :returns: True if the file exists, False if it doesn't

            :raise  ServiceUnavailable
        """
        try:
            self.__s3.object_info(S3Uri(self.pfn2uri(pfn)))
            return True
        except S3Error as e:
            if e.status == 404:
                return False
            else:
                raise exception.ServiceUnavailable(e)

    def connect(self, credentials):
        """ Establishes the actual connection to the referred RSE.

            :param credentials Provides information to establish a connection
                to the referred storage system. For S3 connections these are
                access_key, secretkey, host_base, host_bucket, progress_meter
                and skip_existing.

            :raises RSEAccessDenied
        """
        try:
            cfg = Config()
            for k in credentials:
                cfg.update_option(k.encode('utf-8'), credentials[k].encode('utf-8'))
            self.__s3 = S3(cfg)
        except Exception as e:
            raise exception.RSEAccessDenied(e)

    def close(self):
        """ Closes the connection to RSE."""
        pass

    def get(self, pfn, dest):
        """ Provides access to files stored inside connected the RSE.

            :param pfn Physical file name of requested file
            :param dest Name and path of the files when stored at the client

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
         """
        tf = None
        try:
            tf = open(dest, 'wb')
            self.__s3.object_get(S3Uri(self.pfn2uri(pfn)), tf)
            tf.close()
        except S3Error as e:
            tf.close()
            call(['rm', dest])  # Must be changed if resume will be supported
            if e.status in [404, 403]:
                raise exception.SourceNotFound(e)
            else:
                raise exception.ServiceUnavailable(e)
        except IOError as e:
            if e.errno == 2:
                raise exception.DestinationNotAccessible(e)
            else:
                raise exception.ServiceUnavailable(e)

    def put(self, source, target, source_dir=None):
        """ Allows to store files inside the referred RSE.

            :param source Physical file name
            :param target Name of the file on the storage system e.g. with prefixed scope
            :param source_dir Path where the to be transferred files are stored in the local file system

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        full_name = source_dir + '/' + source if source_dir else source
        try:
            self.__s3.object_put(full_name, S3Uri(self.pfn2uri(target)))
        except S3Error as e:
            if e.info['Code'] in ['NoSuchBucket', "AccessDenied"]:
                raise exception.DestinationNotAccessible(e)
            else:
                raise exception.ServiceUnavailable(e)
        except InvalidFileError as e:
                raise exception.SourceNotFound(e)

    def delete(self, pfn):
        """ Deletes a file from the connected RSE.

            :param pfn Physical file name

            :raises ServiceUnavailable, SourceNotFound
        """
        try:
            self.__s3.object_delete(S3Uri(self.pfn2uri(pfn)))
        except S3Error as e:
            if e.status in [404, 403]:
                raise exception.SourceNotFound(e)
            else:
                raise exception.ServiceUnavailable(e)

    def rename(self, pfn, new_pfn):
        """ Allows to rename a file stored inside the connected RSE.

            :param pfn      Current physical file name
            :param new_pfn  New physical file name

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        try:
            self.__s3.object_move(S3Uri(self.pfn2uri(pfn)), S3Uri(self.pfn2uri(new_pfn)))
        except S3Error as e:
            if e.status in [404, 403]:
                if self.exists(self.pfn2uri(pfn)):
                    raise exception.SourceNotFound(e)
                else:
                    raise exception.DestinationNotAccessible(e)
            else:
                raise exception.ServiceUnavailable(e)
