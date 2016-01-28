# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2014

import os
import requests
import urlparse

from progressbar import ProgressBar
from sys import stdout

from rucio.common import exception
from rucio.rse.protocols import protocol
from rucio.rse import rsemanager

if rsemanager.CLIENT_MODE:
    from rucio.client.objectstoreclient import ObjectStoreClient
if rsemanager.SERVER_MODE:
    from rucio.common import objectstore


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

    REDIRECT_URL = 'https://pcuwvirt5.cern.ch:8443/objectstore'

    def __init__(self, protocol_attr, rse_settings):
        super(Default, self).__init__(protocol_attr, rse_settings)
        self.session = requests.session()
        self.timeout = 300
        self.cert = None

    def lfns2pfns(self, lfns, operation='read'):
        """
            Retruns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.
        """
        pfns = {}
        prefix = self.attributes['prefix']

        if not prefix.startswith('/'):
            prefix = ''.join(['/', prefix])
        if not prefix.endswith('/'):
            prefix = ''.join([prefix, '/'])

        lfns = [lfns] if type(lfns) == dict else lfns
        for lfn in lfns:
            scope, name = lfn['scope'], lfn['name']
            if 'prefix' in lfn and lfn['prefix'] is not None:
                pfn = ''.join([self.attributes['scheme'],
                               '://',
                               self.attributes['hostname'],
                               ':',
                               str(self.attributes['port']),
                               prefix,
                               os.path.join(lfn['prefix'], name)
                               ])
            else:
                pfn = ''.join([self.attributes['scheme'],
                               '://',
                               self.attributes['hostname'],
                               ':',
                               str(self.attributes['port']),
                               prefix,
                               name
                               ])
            if rsemanager.SERVER_MODE:
                pfns['%s:%s' % (scope, name)] = pfn
            else:
                pfns['%s:%s' % (scope, name)] = '/'.join([self.REDIRECT_URL, operation, pfn])
        return pfns

    def _get_unredirector_pfn(self, pfn):
        """
            Parse redirected PFN to get the original PFN.

            :param pfn: a redirected PFN.

            :returns: a original PFN.
        """
        if pfn.startswith(self.REDIRECT_URL):
            pfn = pfn.replace(self.REDIRECT_URL, '')
            pfn = pfn[1:]
            pos = pfn.index('/')
            pfn = pfn[pos+1:]
        return pfn

    def parse_pfns(self, pfns):
        """
            Splits the given PFN into the parts known by the protocol. It is also checked if the provided protocol supportes the given PFNs.

            :param pfns: a list of a fully qualified PFNs

            :returns: dic with PFN as key and a dict with path and name as value

            :raises RSEFileNameNotSupported: if the provided PFN doesn't match with the protocol settings
        """
        ret = dict()
        pfns = [pfns] if ((type(pfns) == str) or (type(pfns) == unicode)) else pfns

        for redirect_pfn in pfns:
            pfn = self._get_unredirector_pfn(redirect_pfn)

            parsed = urlparse(pfn)
            scheme = parsed.scheme
            hostname = parsed.netloc.partition(':')[0]
            port = int(parsed.netloc.partition(':')[2]) if parsed.netloc.partition(':')[2] != '' else 0
            while '//' in parsed.path:
                parsed = parsed._replace(path=parsed.path.replace('//', '/'))
            path = parsed.path

            # Protect against 'lazy' defined prefixes for RSEs in the repository
            if not self.attributes['prefix'].startswith('/'):
                self.attributes['prefix'] = '/' + self.attributes['prefix']
            if not self.attributes['prefix'].endswith('/'):
                self.attributes['prefix'] += '/'

            if self.attributes['hostname'] != hostname:
                if self.attributes['hostname'] != 'localhost':  # In the database empty hostnames are replaced with localhost but for some URIs (e.g. file) a hostname is not included
                    raise exception.RSEFileNameNotSupported('Invalid hostname: provided \'%s\', expected \'%s\'' % (hostname, self.attributes['hostname']))

            if self.attributes['port'] != port:
                raise exception.RSEFileNameNotSupported('Invalid port: provided \'%s\', expected \'%s\'' % (port, self.attributes['port']))

            if not path.startswith(self.attributes['prefix']):
                raise exception.RSEFileNameNotSupported('Invalid prefix: provided \'%s\', expected \'%s\'' % ('/'.join(path.split('/')[0:len(self.attributes['prefix'].split('/')) - 1]),
                                                                                                              self.attributes['prefix']))  # len(...)-1 due to the leading '/

            # Spliting parsed.path into prefix, path, filename
            prefix = self.attributes['prefix']
            path = path.partition(self.attributes['prefix'])[2]
            name = path.split('/')[-1]
            path = path.partition(name)[0]
            ret[pfn] = {'path': path, 'name': name, 'scheme': scheme, 'prefix': prefix, 'port': port, 'hostname': hostname, }

        return ret

    def _get_signed_urls(self, urls, operation='read'):
        urls = [self._get_unredirector_pfn(url) for url in urls]
        if rsemanager.CLIENT_MODE:
            client = ObjectStoreClient()
            return client.get_signed_urls(urls, operation=operation)
        if rsemanager.SERVER_MODE:
            return objectstore.get_signed_urls(urls, operation=operation)

    def _get_signed_url(self, url, operation='read'):
        url = self._get_unredirector_pfn(url)
        if rsemanager.CLIENT_MODE:
            client = ObjectStoreClient()
            return client.get_signed_url(url, operation=operation)
        if rsemanager.SERVER_MODE:
            return objectstore.get_signed_urls([url], operation=operation)[url]

    def _get_metadata(self, urls):
        urls = [self._get_unredirector_pfn(url) for url in urls]
        if rsemanager.CLIENT_MODE:
            client = ObjectStoreClient()
            return client.get_metadata(urls)
        if rsemanager.SERVER_MODE:
            return objectstore.get_metadata(urls)

    def _delete(self, urls):
        urls = [self._get_unredirector_pfn(url) for url in urls]
        if rsemanager.CLIENT_MODE:
            raise exception.NotImplementedError
        if rsemanager.SERVER_MODE:
            return objectstore.delete(urls)

    def _delete_dir(self, url):
        url = self._get_unredirector_pfn(url)
        if rsemanager.CLIENT_MODE:
            raise exception.NotImplementedError
        if rsemanager.SERVER_MODE:
            return objectstore.delete_dir(url)

    def _rename(self, url, new_url):
        url = self._get_unredirector_pfn(url)
        new_url = self._get_unredirector_pfn(new_url)
        if rsemanager.CLIENT_MODE:
            client = ObjectStoreClient()
            return client.rename(url, new_url)
        if rsemanager.SERVER_MODE:
            return objectstore.rename(url, new_url)

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
                raise exception.RucioException('Failed to check file state: %s' % metadata)
        except exception.SourceNotFound:
            return False
        except Exception as e:
            raise exception.RucioException(e)

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

    def get(self, path, dest):
        """
            Provides access to files stored inside connected the RSE.

            :param path: Physical file name of requested file
            :param dest: Name and path of the files when stored at the client

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
         """
        print path
        path = self._get_signed_url(path, 'read')
        print path
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
                            print 'Malformed HTTP response (missing content-length header). Cannot show progress bar.'
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
        print source
        print target
        path = self._get_signed_url(target, operation='write')
        print path
        full_name = source_dir + '/' + source if source_dir else source
        directories = path.split('/')
        # Try the upload without testing the existence of the destination directory
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
                # Create the directories before issuing the PUT
                for directory_level in reversed(xrange(1, 4)):
                    upper_directory = "/".join(directories[:-directory_level])
                    self.mkdir(upper_directory)
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

    def delete(self, pfn):
        """
            Deletes a file from the connected RSE.

            :param path: path to the to be deleted file

            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        try:
            self._delete([pfn])
        except exception.SourceNotFound, e:
            raise exception.SourceNotFound(e)
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
            print pfn
            print new_pfn
            self._rename(pfn, new_pfn)
        except exception.SourceNotFound as e:
            raise exception.SourceNotFound(e)
        except Exception as e:
            raise exception.ServiceUnavailable(e)

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
