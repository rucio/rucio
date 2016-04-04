# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2016

import os
import urlparse

import boto
import boto.s3.connection

from boto.s3.key import Key

from rucio.common import exception
from rucio.common.config import get_rse_credentials

from rucio.rse.protocols import protocol


class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using the S3 protocol."""

    def __init__(self, protocol_attr, rse_settings):
        super(Default, self).__init__(protocol_attr, rse_settings)
        if 'determinism_type' in self.attributes:
            self.attributes['determinism_type'] = 's3'
        self.__conn = None

    def _get_path(self, scope, name):
        """ Transforms the physical file name into the local URI in the referred RSE.
            Suitable for sites implementoing the RUCIO naming convention.

            :param name: filename
            :param scope: scope

            :returns: RSE specific URI of the physical file
        """
        return '%s:%s' % (scope, name)

    def get_bucket_key_name(self, pfn):
        """
            Gets boto key for a pfn

            :param pfn: Physical file name

            :returns: bucket name and key name as string
        """
        try:
            parsed = urlparse.urlparse(pfn)
            hash_path = parsed.path.strip("/")

            pos = hash_path.index("/")
            bucket_name = hash_path[:pos]
            key_name = hash_path[pos + 1:]

            return bucket_name, key_name
        except Exception as e:
            raise exception.RucioException(str(e))

    def get_bucket_key(self, pfn, create=False):
        """
            Gets boto key for a pfn

            :param pfn: Physical file name
            :param create: True if needs to create the key, False if not

            :returns: boto bucket and key object
        """
        try:
            bucket_name, key_name = self.get_bucket_key_name(pfn)

            if create:
                bucket = self.__conn.create_bucket(bucket_name)
                key = Key(bucket, key_name)
            else:
                bucket = self.__conn.get_bucket(bucket_name)
                key = bucket.get_key(key_name)
            return bucket, key
        except boto.exception.S3ResponseError as e:
            if e.status == 404:
                raise exception.SourceNotFound(str(e))
            else:
                raise exception.ServiceUnavailable(e)

    def exists(self, path):
        """
            Checks if the requested file is known by the referred RSE.

            :param path: Physical file name

            :returns: True if the file exists, False if it doesn't

            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        try:
            bucket, key = self.get_bucket_key(path)
            if key:
                return True
            else:
                return False
        except exception.SourceNotFound:
            return False
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def connect(self):
        """
            Establishes the actual connection to the referred RSE.

            :param: credentials needed to establish a connection with the stroage.

            :raises RSEAccessDenied: if no connection could be established.
        """
        try:
            scheme, prefix = self.attributes.get('scheme'), self.attributes.get('prefix')
            netloc, port = self.attributes['hostname'], self.attributes.get('port', 80)
            service_url = '%(scheme)s://%(netloc)s:%(port)s%(prefix)s' % locals()
            credentials = get_rse_credentials()
            self.rse['credentials'] = credentials.get(self.rse['rse'])
            is_secure = self.rse['credentials'].get('is_secure', {}).\
                get(service_url, False)
            self.__conn = boto.connect_s3(host=self.attributes['hostname'],
                                          port=int(port),
                                          aws_access_key_id=self.rse['credentials']['access_key'],
                                          aws_secret_access_key=self.rse['credentials']['secret_key'],
                                          is_secure=is_secure,
                                          calling_format=boto.s3.connection.OrdinaryCallingFormat())
        except Exception as e:
            raise exception.RSEAccessDenied(e)

    def close(self):
        """ Closes the connection to RSE."""
        pass

    def get(self, pfn, dest):
        """
            Provides access to files stored inside connected the RSE.

            :param path: Physical file name of requested file
            :param dest: Name and path of the files when stored at the client

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
         """
        try:
            bucket, key = self.get_bucket_key(pfn)
            if key is None:
                raise exception.SourceNotFound('Cannot get the source key from S3')
            key.get_contents_to_filename(dest)
        except IOError as e:
            if e.errno == 2:
                raise exception.DestinationNotAccessible(e)
            else:
                raise exception.ServiceUnavailable(e)
        except exception.SourceNotFound as e:
            raise exception.SourceNotFound(e)
        except Exception as e:
            if os.path.exists(dest):
                os.remove(dest)
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
        full_name = source_dir + '/' + source if source_dir else source
        try:
            bucket, key = self.get_bucket_key(target, create=True)
            if key is None:
                raise exception.DestinationNotAccessible('Cannot get the destionation key from S3')
            key.set_contents_from_filename(full_name)
        except exception.SourceNotFound as e:
            raise exception.SourceNotFound(e)
        except Exception as e:
            if 'No such file' in str(e):
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
        try:
            bucket, key = self.get_bucket_key(pfn)
            if key is None:
                raise exception.SourceNotFound('Cannot get the key from S3')
            key.delete()
        except exception.SourceNotFound as e:
            raise exception.SourceNotFound(e)
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def rename(self, pfn, new_pfn):
        """ Allows to rename a file stored inside the connected RSE.

            :param path: path to the current file on the storage
            :param new_path: path to the new file on the storage

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        try:
            bucket, key = self.get_bucket_key(pfn)
            if key is None:
                raise exception.SourceNotFound('Cannot get the source key from S3')
            bucket_name, key_name = self.get_bucket_key_name(new_pfn)
            key.copy(bucket_name, key_name)
            key.delete()
        except exception.SourceNotFound as e:
            raise exception.SourceNotFound(e)
        except boto.exception.S3ResponseError as e:
            if e.status in [404, 403]:
                raise exception.DestinationNotAccessible(e)
            else:
                raise exception.ServiceUnavailable(e)
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def stat(self, pfn):
        """ Determines the file size in bytes  of the provided file.

            :param pfn: The PFN the file.

            :returns: a dict containing the key filesize.
        """
        try:
            bucket, key = self.get_bucket_key(pfn)
            if key is None:
                raise exception.SourceNotFound('Cannot get the key from S3')
            return {'filesize': int(key.size)}
        except exception.SourceNotFound as e:
            raise exception.SourceNotFound(e)
        except Exception as e:
            raise exception.ServiceUnavailable(e)
