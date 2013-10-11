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
from urlparse import urlparse
# IMPORTANT: If the order of the S3 imports is changed, they fail!
from S3.Exceptions import S3Error, InvalidFileError
from S3.S3 import S3
from S3.Config import Config
from S3.S3Uri import S3Uri

from rucio.common import exception
from rucio.rse.protocols import protocol


class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using the S3 protocol."""

    def get_path(self, lfn, scope):
        """ Transforms the physical file name into the local URI in the referred RSE.
            Suitable for sites implementoing the RUCIO naming convention.

            :param lfn: filename
            :param scope: scope

            :returns: RSE specific URI of the physical file
        """
        # On S3 the default naming convention is not supproted
        # It is therefore changed to bucket being either user, group, ... followed by the
        # scope as prefix and the lfn as actual file name
        # IMPORTANT: The prefix defined in the RSE properties are ignored due to system constraints
        bucket = scope.split('.')[0].upper()
        scope = scope.split('.')[1]
        return '%s/%s/%s' % (bucket, scope, lfn)

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
        try:
            self.__s3.object_info(S3Uri('://'.join(['s3', path])))
            return True
        except S3Error as e:
            if e.status == 404:
                return False
            else:
                raise exception.ServiceUnavailable(e)

    def connect(self, credentials):
        """
            Establishes the actual connection to the referred RSE.

            :param: credentials needed to establish a connection with the stroage.

            :raises RSEAccessDenied: if no connection could be established.
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

    def get(self, path, dest):
        """
            Provides access to files stored inside connected the RSE.

            :param path: Physical file name of requested file
            :param dest: Name and path of the files when stored at the client

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
         """
        tf = None
        try:
            tf = open(dest, 'wb')
            self.__s3.object_get(S3Uri('://'.join(['s3', path])), tf)
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
            self.__s3.object_put(full_name, S3Uri('://'.join(['s3', target])))
        except S3Error as e:
            if e.info['Code'] in ['NoSuchBucket', "AccessDenied"]:
                raise exception.DestinationNotAccessible(e)
            else:
                raise exception.ServiceUnavailable(e)
        except InvalidFileError as e:
                raise exception.SourceNotFound(e)

    def delete(self, path):
        """
            Deletes a file from the connected RSE.

            :param path: path to the to be deleted file

            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        try:
            self.__s3.object_delete(S3Uri('://'.join(['s3', path])))
        except S3Error as e:
            if e.status in [404, 403]:
                raise exception.SourceNotFound(e)
            else:
                raise exception.ServiceUnavailable(e)

    def rename(self, path, new_path):
        """ Allows to rename a file stored inside the connected RSE.

            :param path: path to the current file on the storage
            :param new_path: path to the new file on the storage

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        try:
            self.__s3.object_move(S3Uri('://'.join(['s3', path])), S3Uri('://'.join(['s3', new_path])))
        except S3Error as e:
            if e.status in [404, 403]:
                if self.exists(path):
                    raise exception.SourceNotFound(e)
                else:
                    raise exception.DestinationNotAccessible(e)
            else:
                raise exception.ServiceUnavailable(e)

    def split_pfn(self, pfn):
        """
            Splits the given PFN into the parts known by the protocol. During parsing the PFN is also checked for
            validity on the given RSE with the given protocol.

            :param pfn: a fully qualified PFN

            :returns: a dict containing all known parts of the PFN for the protocol e.g. scheme, path, filename

            :raises RSEFileNameNotSupported: if the provided PFN doesn't match with the protocol settings
        """
        # s3 URI: s3://[Bucket]/[path]/[name]; Bucket/path = scope/user
        parsed = urlparse(pfn)
        ret = dict()
        ret['scheme'] = parsed.scheme
        ret['hostname'] = None
        ret['port'] = 0
        ret['path'] = ''.join([parsed.netloc, parsed.path])
        ret['name'] = ret['path'].split('/')[-1]
        ret['path'] = ret['path'].partition(ret['name'])[0]
        return ret
