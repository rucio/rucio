# Copyright 2018 CERN for the benefit of the ATLAS collaboration.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2016-2017
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2017
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Nicolo Magini, <nicolo.magini@cern.ch>, 2018
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2019
#
# PY3K COMPATIBLE

from __future__ import print_function, division

import os
import requests

from progressbar import ProgressBar
from sys import stdout

from rucio.client.objectstoreclient import ObjectStoreClient
from rucio.common import exception
from rucio.rse.protocols import protocol


class UploadInChunks(object):
    '''
    Class to upload by chunks.
    '''

    def __init__(self, filename, chunksize, progressbar=False):
        self.__totalsize = os.path.getsize(filename)
        self.__readsofar = 0
        self.__filename = filename
        self.__chunksize = chunksize
        self.__progressbar = progressbar

    def __iter__(self):
        try:
            with open(self.__filename, 'rb') as file_in:
                while True:
                    data = file_in.read(self.__chunksize)
                    if not data:
                        if self.__progressbar:
                            stdout.write("\n")
                        break
                    self.__readsofar += len(data)
                    if self.__progressbar:
                        percent = self.__readsofar * 100 / self.__totalsize
                        stdout.write("\r{percent:3.0f}%".format(percent=percent))
                    yield data
        except OSError as error:
            raise exception.SourceNotFound(error)

    def __len__(self):
        return self.__totalsize


class IterableToFileAdapter(object):
    '''
    Class IterableToFileAdapter
    '''
    def __init__(self, iterable):
        self.iterator = iter(iterable)
        self.length = len(iterable)

    def read(self, size=-1):   # TBD: add buffer for `len(data) > size` case
        return next(self.iterator, b'')

    def __len__(self):
        return self.length


class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using the S3 protocol."""

    def __init__(self, protocol_attr, rse_settings):
        super(Default, self).__init__(protocol_attr, rse_settings)
        self.session = requests.session()
        self.timeout = 300
        self.cert = None
        self.renaming = False
        self.overwrite = True

    def path2pfn(self, path):
        """
            Returns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.

        """
        if path.startswith("s3:") or path.startswith("http"):
            return path

        prefix = self.attributes['prefix']

        if not prefix.startswith('/'):
            prefix = ''.join(['/', prefix])
        if not prefix.endswith('/'):
            prefix = ''.join([prefix, '/'])

        return ''.join([self.attributes['scheme'], '://', self.attributes['hostname'], ':', str(self.attributes['port']), prefix, path])

    def _connect(self):
        url = self.path2pfn('')
        client = ObjectStoreClient()
        return client.connect(self.rse['rse'], url)

    def _get_signed_urls(self, urls, operation='read'):
        client = ObjectStoreClient()
        return client.get_signed_urls(urls, rse=self.rse['rse'], operation=operation)

    def _get_signed_url(self, url, operation='read'):
        client = ObjectStoreClient()
        return client.get_signed_url(url, rse=self.rse['rse'], operation=operation)

    def _get_metadata(self, urls):
        client = ObjectStoreClient()
        return client.get_metadata(urls, rse=self.rse['rse'])

    def _rename(self, url, new_url):
        client = ObjectStoreClient()
        return client.rename(url, new_url, rse=self.rse['rse'])

    def connect(self):
        """
            Establishes the actual connection to the referred RSE.

            :param: credentials needed to establish a connection with the stroage.

            :raises RSEAccessDenied: if no connection could be established.
        """
        pass

    def close(self):
        """ Closes the connection to RSE."""
        pass

    def get(self, path, dest, transfer_timeout=None):
        """
            Provides access to files stored inside connected the RSE.

            :param path: Physical file name of requested file
            :param dest: Name and path of the files when stored at the client
            :param transfer_timeout: Transfer timeout (in seconds) - dummy

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
         """
        path = self._get_signed_url(path, 'read')
        if isinstance(path, Exception):
            raise path

        chunksize = 1024
        try:
            result = self.session.get(path, verify=False, stream=True, timeout=self.timeout)
            if result and result.status_code in [200, ]:
                length = None
                if 'content-length' in result.headers:
                    length = int(result.headers['content-length'])
                    totnchunk = int(length / chunksize) + 1
                with open(dest, 'wb') as f:
                    nchunk = 0
                    try:
                        if length:
                            pbar = ProgressBar(maxval=totnchunk).start()
                        else:
                            print('Malformed HTTP response (missing content-length header). Cannot show progress bar.')
                        for chunk in result.iter_content(chunksize):
                            f.write(chunk)
                            if length:
                                nchunk += 1
                                pbar.update(nchunk)
                    finally:
                        if length:
                            pbar.finish()

            elif result.status_code in [404, ]:
                raise exception.SourceNotFound()
            elif result.status_code in [401, 403]:
                raise exception.RSEAccessDenied()
            else:
                # catchall exception
                raise exception.RucioException(result.status_code, result.text)
        except requests.exceptions.ConnectionError as error:
            raise exception.ServiceUnavailable(error)

    def put(self, source, target, source_dir=None, transfer_timeout=None):
        """
            Allows to store files inside the referred RSE.

            :param source: path to the source file on the client file system
            :param target: path to the destination file on the storage
            :param source_dir: Path where the to be transferred files are stored in the local file system
            :param transfer_timeout: Transfer timeout (in seconds) - dummy

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        full_name = source_dir + '/' + source if source_dir else source
        path = self._get_signed_url(target, operation='write')
        full_name = source_dir + '/' + source if source_dir else source
        try:
            if not os.path.exists(full_name):
                raise exception.SourceNotFound()
            it = UploadInChunks(full_name, 10000000, progressbar=False)
            result = self.session.put(path, data=IterableToFileAdapter(it), verify=False, allow_redirects=True, timeout=self.timeout, cert=self.cert)
            if result.status_code in [200, 201]:
                return
            if result.status_code in [409, ]:
                raise exception.FileReplicaAlreadyExists()
            else:
                try:
                    if not os.path.exists(full_name):
                        raise exception.SourceNotFound()
                    it = UploadInChunks(full_name, 10000000, progressbar=False)
                    result = self.session.put(path, data=IterableToFileAdapter(it), verify=False, allow_redirects=True, timeout=self.timeout, cert=self.cert)
                    if result.status_code in [200, 201]:
                        return
                    if result.status_code in [409, ]:
                        raise exception.FileReplicaAlreadyExists()
                    elif result.status_code in [401, ]:
                        raise exception.RSEAccessDenied()
                    else:
                        # catchall exception
                        raise exception.RucioException(result.status_code, result.text)
                except requests.exceptions.ConnectionError as error:
                    raise exception.ServiceUnavailable(error)
                except IOError as error:
                    raise exception.SourceNotFound(error)
        except requests.exceptions.ConnectionError as error:
            raise exception.ServiceUnavailable(error)
        except IOError as error:
            raise exception.SourceNotFound(error)

    def stat(self, pfn):
        """ Determines the file size in bytes  of the provided file.

            :param pfn: The PFN the file.

            :returns: a dict containing the key filesize.
        """
        try:
            metadata = self._get_metadata([pfn])
            if pfn in metadata and metadata[pfn]:
                if isinstance(metadata[pfn], Exception):
                    raise metadata[pfn]
                else:
                    return metadata[pfn]
            else:
                raise exception.RucioException('Failed to check file state: %s' % metadata)
        except exception.SourceNotFound as e:
            raise exception.SourceNotFound(e)
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def exists(self, pfn):
        """
            Checks if the requested file is known by the referred RSE.

            :param path: Physical file name

            :returns: True if the file exists, False if it doesn't

            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        try:
            metadata = self._get_metadata([pfn])
            if pfn in metadata and metadata[pfn]:
                if isinstance(metadata[pfn], Exception):
                    raise metadata[pfn]
                else:
                    return True
            else:
                raise exception.RucioException('Failed to check file %s state: %s' % (pfn, metadata))
        except exception.SourceNotFound:
            return False
        except Exception as e:
            raise exception.RucioException(e)

    def rename(self, pfn, new_pfn):
        """ Allows to rename a file stored inside the connected RSE.

            :param path: path to the current file on the storage
            :param new_path: path to the new file on the storage

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        try:
            self._rename(pfn, new_pfn)
        except exception.SourceNotFound as e:
            raise exception.SourceNotFound(e)
        except Exception as e:
            raise exception.ServiceUnavailable(e)
