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
    """ Implementing access to storage systems using the S3 protocol
        in its standard/default implementation, meaning no storage specific
        customizations are made.

        A complete list with all possible Exception can be found here: http://docs.amazonwebservices.com/AmazonS3/2006-03-01/API/ErrorResponses.html
    """

    def __init__(self, rse):
        """ Initializes the object with information about the referred storage system."""
        self.rse = rse

    def pfn2uri(self, pfn):
        """ Transforms the physical file name into the local URI in the referred storage system.

            :param pfn Physical file name
            :returns: Storage specific URI of the physical file
        """
        return 's3://%s/%s' % (self.rse.static['pfn_prefix'], pfn)

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
        try:
            self.__s3.object_info(S3Uri(self.pfn2uri(pfn)))
            return True
        except S3Error:
            return False

    def connect(self, credentials):
        """ Establishes the actual connection to the referred storage system using the S3 protocol.

            :param credentials Provides information to establish a connection
                to the referred storage system. For S3 connections these are
                access_key, secretkey, host_base, host_bucket, progress_meter
                and skip_existing.
            :raises FailedToLogin
        """
        try:
            cfg = Config()
            for k in credentials:
                cfg.update_option(k.encode('utf-8'), credentials[k].encode('utf-8'))
            self.__s3 = S3(cfg)
        except Exception as e:
            raise exception.FailedToLogin({'exception': e, 'storageurl': self.rse.static['url'], 'credentials': credentials})

    def get(self, pfn, dest):
        """ Provides access to files stored inside the storage system.

            :param pfn Physical file name of requested file
            :param dest Name and path of the files when stored at the client
            :raises AccessDenied, ServiceUnavailable, RucioException
        """
        tf = None
        try:
            tf = open(dest, 'wb')
            self.__s3.object_get(S3Uri(self.pfn2uri(pfn)), tf)
            tf.close()
        except S3Error as e:
            tf.close()
            call(['rm', dest])  # Must be changed if resume will be supported
            if e.status == 403:
                raise exception.AccessDenied(e.info)
            elif e.status == 404:
                raise exception.FileNotFound('Remote file %s not found' % (S3Uri(self.pfn2uri(pfn))))
            elif e.info['Code'] == 'ServiceUnavailable':
                raise exception.ServiceUnavailable(e.info)
            else:
                raise exception.RucioException(e.info)

    def put(self, pfn, source_path):
        """ Allows to store files inside the referred storage system.

            :param pfn Physical file name
            :param source_path Path where the to be transferred files are stored in the local file system
            :raises AccessDenied, ServiceUnavailable, RucioException, FileNotFound
        """
        full_name = source_path + '/' + pfn if source_path else pfn
        try:
            self.__s3.object_put(full_name, S3Uri(self.pfn2uri(pfn)))
        except S3Error as e:
            if e.info['Code'] == 'NoSuchBucket':
                try:
                    self.__s3.bucket_create(self.rse.static['pfn_prefix'])
                except Exception as f:
                    raise exception.RucioException(f.info)
                self.__s3.object_put(full_name, S3Uri(self.pfn2uri(pfn)))
            if e.info['Code'] == "AccessDenied":
                raise exception.AccessDenied(e.info)
            elif e.info['Code'] == "ServiceUnavailable":
                raise exception.ServiceUnavailable(e.info)
            else:
                raise exception.RucioException(e.info)
        except InvalidFileError:
            raise exception.FileNotFound('Local file %s not found' % full_name)

    def delete(self, pfn):
        """ Deletes a file from the referred storage system.

            :param pfn Physical file name
            :raises AccessDenied, ServiceUnavailable, RucioException
        """
        try:
            self.__s3.object_delete(S3Uri(self.pfn2uri(pfn)))
        except S3Error as e:
            if e.status == 403:
                raise exception.AccessDenied(e.info)
            elif e.info['Code'] == "ServiceUnavailable":
                raise exception.ServiceUnavailable(e.info)
            elif e.status == 404:
                raise exception.FileNotFound('Remote file %s not found' % (S3Uri(self.pfn2uri(pfn))))
            else:
                raise exception.RucioException(e.info)

    def close(self):
        """ Closes the current connection to the storage system. """
        pass
