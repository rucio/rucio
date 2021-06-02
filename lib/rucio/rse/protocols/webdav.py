# Copyright 2012-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2012-2017
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013
# - Vincent Garonne <vincent.garonne@cern.ch>, 2013-2017
# - David Cameron <david.cameron@cern.ch>, 2014
# - Sylvain Blunier <sylvain.blunier@cern.ch>, 2016
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Nicolo Magini <nicolo.magini@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Eric Vaandering <ericvaandering@gmail.com>, 2019
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
#
# PY3K COMPATIBLE

from __future__ import print_function, division
import os
import ssl
import sys

import xml.etree.ElementTree as ET
from xml.parsers import expat

import requests
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

from rucio.common import exception
from rucio.rse.protocols import protocol


class TLSv1HttpAdapter(HTTPAdapter):
    '''
    Class to force the SSL protocol to TLSv1
    '''
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_TLSv1)


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
                            sys.stdout.write("\n")
                        break
                    self.__readsofar += len(data)
                    if self.__progressbar:
                        percent = self.__readsofar * 100 / self.__totalsize
                        sys.stdout.write("\r{percent:3.0f}%".format(percent=percent))
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
        nextvar = next(self.iterator, b'')
        return nextvar

    def __len__(self):
        return self.length


class Parser:

    """ Parser to parse XML output for PROPFIND ."""

    def __init__(self):
        """ Initializes the object"""
        self._parser = expat.ParserCreate()
        self._parser.StartElementHandler = self.start
        self._parser.EndElementHandler = self.end
        self._parser.CharacterDataHandler = self.data
        self.hrefflag = 0
        self.href = ''
        self.status = 0
        self.size = 0
        self.dict = {}
        self.sizes = {}
        self.list = []

    def feed(self, data):
        """ Feed the parser with data"""
        self._parser.Parse(data, 0)

    def close(self):
        self._parser.Parse("", 1)
        del self._parser

    def start(self, tag, attrs):
        if tag == 'D:href' or tag == 'd:href':
            self.hrefflag = 1
        if tag == 'D:status' or tag == 'd:status':
            self.status = 1
        if tag == 'D:getcontentlength' or tag == 'd:getcontentlength':
            self.size = 1

    def end(self, tag):
        if tag == 'D:href' or tag == 'd:href':
            self.hrefflag = 0
        if tag == 'D:status' or tag == 'd:status':
            self.status = 0
        if tag == 'D:getcontentlength' or tag == 'd:getcontentlength':
            self.size = 0

    def data(self, data):
        if self.hrefflag:
            self.href = str(data)
            self.list.append(self.href)
        if self.status:
            self.dict[self.href] = data
        if self.size:
            self.sizes[self.href] = data


class Default(protocol.RSEProtocol):

    """ Implementing access to RSEs using the webDAV protocol."""

    def connect(self, credentials={}):
        """ Establishes the actual connection to the referred RSE.

            :param credentials Provides information to establish a connection
                to the referred storage system. For WebDAV connections these are
                ca_cert, cert, auth_type, timeout

            :raises RSEAccessDenied
        """
        try:
            self.server = self.path2pfn('')
        except KeyError:
            raise exception.RSEAccessDenied('No specified Server')

        try:
            self.ca_cert = credentials['ca_cert']
        except KeyError:
            self.ca_cert = None

        try:
            self.auth_type = credentials['auth_type']
        except KeyError:
            self.auth_type = 'cert'

        try:
            self.cert = credentials['cert']
        except KeyError:
            x509 = os.getenv('X509_USER_PROXY')
            if not x509:
                # Trying to get the proxy from the default location
                proxy_path = '/tmp/x509up_u%s' % os.geteuid()
                if os.path.isfile(proxy_path):
                    x509 = proxy_path
                elif self.auth_token:
                    pass
                else:
                    raise exception.RSEAccessDenied('X509_USER_PROXY is not set')
            self.cert = (x509, x509)

        try:
            self.timeout = credentials['timeout']
        except KeyError:
            self.timeout = 300
        self.session = requests.Session()
        self.session.mount('https://', TLSv1HttpAdapter())
        if self.auth_token:
            self.session.headers.update({'Authorization': 'Bearer ' + self.auth_token})
        # "ping" to see if the server is available
        try:
            res = self.session.request('HEAD', self.path2pfn(''), verify=False, timeout=self.timeout, cert=self.cert)
            if res.status_code != 200:
                raise exception.ServiceUnavailable('Problem to connect %s : %s' % (self.path2pfn(''), res.text))
        except requests.exceptions.ConnectionError as error:
            raise exception.ServiceUnavailable('Problem to connect %s : %s' % (self.path2pfn(''), error))
        except requests.exceptions.ReadTimeout as error:
            raise exception.ServiceUnavailable(error)

    def close(self):
        self.session.close()

    def path2pfn(self, path):
        """
            Returns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.

        """
        if not path.startswith('https'):
            return '%s://%s:%s%s%s' % (self.attributes['scheme'], self.attributes['hostname'], str(self.attributes['port']), self.attributes['prefix'], path)
        else:
            return path

    def exists(self, pfn):
        """ Checks if the requested file is known by the referred RSE.

            :param pfn Physical file name

            :returns: True if the file exists, False if it doesn't

            :raise  ServiceUnavailable, RSEAccessDenied
        """
        path = self.path2pfn(pfn)
        try:
            result = self.session.request('HEAD', path, verify=False, timeout=self.timeout, cert=self.cert)
            if result.status_code == 200:
                return True
            elif result.status_code in [401, ]:
                raise exception.RSEAccessDenied()
            elif result.status_code in [404, ]:
                return False
            else:
                # catchall exception
                raise exception.RucioException(result.status_code, result.text)
        except requests.exceptions.ConnectionError as error:
            raise exception.ServiceUnavailable(error)

    def get(self, pfn, dest='.', transfer_timeout=None):
        """ Provides access to files stored inside connected the RSE.

            :param pfn Physical file name of requested file
            :param dest Name and path of the files when stored at the client
            :param transfer_timeout: Transfer timeout (in seconds) - dummy

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound, RSEAccessDenied
        """
        path = self.path2pfn(pfn)
        chunksize = 1024
        try:
            result = self.session.get(path, verify=False, stream=True, timeout=self.timeout, cert=self.cert)
            if result and result.status_code in [200, ]:
                length = None
                if 'content-length' in result.headers:
                    length = int(result.headers['content-length'])
                with open(dest, 'wb') as file_out:
                    nchunk = 0
                    if not length:
                        print('Malformed HTTP response (missing content-length header).')
                    for chunk in result.iter_content(chunksize):
                        file_out.write(chunk)
                        if length:
                            nchunk += 1
            elif result.status_code in [404, ]:
                raise exception.SourceNotFound()
            elif result.status_code in [401, 403]:
                raise exception.RSEAccessDenied()
            else:
                # catchall exception
                raise exception.RucioException(result.status_code, result.text)
        except requests.exceptions.ConnectionError as error:
            raise exception.ServiceUnavailable(error)
        except requests.exceptions.ReadTimeout as error:
            raise exception.ServiceUnavailable(error)

    def put(self, source, target, source_dir=None, transfer_timeout=None, progressbar=False):
        """ Allows to store files inside the referred RSE.

            :param source Physical file name
            :param target Name of the file on the storage system e.g. with prefixed scope
            :param source_dir Path where the to be transferred files are stored in the local file system
            :param transfer_timeout Transfer timeout (in seconds) - dummy

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound, RSEAccessDenied
        """
        path = self.path2pfn(target)
        full_name = source_dir + '/' + source if source_dir else source
        directories = path.split('/')
        # Try the upload without testing the existence of the destination directory
        try:
            if not os.path.exists(full_name):
                raise exception.SourceNotFound()
            it = UploadInChunks(full_name, 10000000, progressbar)
            result = self.session.put(path, data=IterableToFileAdapter(it), verify=False, allow_redirects=True, timeout=self.timeout, cert=self.cert)
            if result.status_code in [200, 201]:
                return
            if result.status_code in [409, ]:
                raise exception.FileReplicaAlreadyExists()
            else:
                # Create the directories before issuing the PUT
                for directory_level in reversed(list(range(1, 4))):
                    upper_directory = "/".join(directories[:-directory_level])
                    self.mkdir(upper_directory)
                try:
                    if not os.path.exists(full_name):
                        raise exception.SourceNotFound()
                    it = UploadInChunks(full_name, 10000000, progressbar)
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
        except requests.exceptions.ReadTimeout as error:
            raise exception.ServiceUnavailable(error)
        except IOError as error:
            raise exception.SourceNotFound(error)

    def rename(self, pfn, new_pfn):
        """ Allows to rename a file stored inside the connected RSE.

            :param pfn      Current physical file name
            :param new_pfn  New physical file name

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound, RSEAccessDenied
        """
        path = self.path2pfn(pfn)
        new_path = self.path2pfn(new_pfn)
        directories = new_path.split('/')

        headers = {'Destination': new_path}
        # Try the rename without testing the existence of the destination directory
        try:
            result = self.session.request('MOVE', path, verify=False, headers=headers, timeout=self.timeout, cert=self.cert)
            if result.status_code == 201:
                return
            elif result.status_code in [404, ]:
                raise exception.SourceNotFound()
            else:
                # Create the directories before issuing the MOVE
                for directory_level in reversed(list(range(1, 4))):
                    upper_directory = "/".join(directories[:-directory_level])
                    self.mkdir(upper_directory)
                try:
                    result = self.session.request('MOVE', path, verify=False, headers=headers, timeout=self.timeout, cert=self.cert)
                    if result.status_code == 201:
                        return
                    elif result.status_code in [404, ]:
                        raise exception.SourceNotFound()
                    elif result.status_code in [401, ]:
                        raise exception.RSEAccessDenied()
                    else:
                        # catchall exception
                        raise exception.RucioException(result.status_code, result.text)
                except requests.exceptions.ConnectionError as error:
                    raise exception.ServiceUnavailable(error)
        except requests.exceptions.ConnectionError as error:
            raise exception.ServiceUnavailable(error)
        except requests.exceptions.ReadTimeout as error:
            raise exception.ServiceUnavailable(error)

    def delete(self, pfn):
        """ Deletes a file from the connected RSE.

            :param pfn Physical file name

            :raises ServiceUnavailable, SourceNotFound, RSEAccessDenied, ResourceTemporaryUnavailable
        """
        path = self.path2pfn(pfn)
        try:
            result = self.session.delete(path, verify=False, timeout=self.timeout, cert=self.cert)
            if result.status_code in [204, ]:
                return
            elif result.status_code in [404, ]:
                raise exception.SourceNotFound()
            elif result.status_code in [401, 403]:
                raise exception.RSEAccessDenied()
            elif result.status_code in [500, 503]:
                raise exception.ResourceTemporaryUnavailable()
            else:
                # catchall exception
                raise exception.RucioException(result.status_code, result.text)
        except requests.exceptions.ConnectionError as error:
            raise exception.ServiceUnavailable(error)
        except requests.exceptions.ReadTimeout as error:
            raise exception.ServiceUnavailable(error)

    def mkdir(self, directory):
        """ Internal method to create directories

            :param directory Name of the directory that needs to be created

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound, RSEAccessDenied
        """
        path = self.path2pfn(directory)
        try:
            result = self.session.request('MKCOL', path, verify=False, timeout=self.timeout, cert=self.cert)
            if result.status_code in [201, 405]:  # Success or directory already exists
                return
            elif result.status_code in [404, ]:
                raise exception.SourceNotFound()
            elif result.status_code in [401, ]:
                raise exception.RSEAccessDenied()
            else:
                # catchall exception
                raise exception.RucioException(result.status_code, result.text)
        except requests.exceptions.ConnectionError as error:
            raise exception.ServiceUnavailable(error)
        except requests.exceptions.ReadTimeout as error:
            raise exception.ServiceUnavailable(error)

    def ls(self, filename):
        """ Internal method to list files/directories

            :param filename Name of the directory that needs to be created

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound, RSEAccessDenied
        """
        path = self.path2pfn(filename)
        headers = {'Depth': '1'}
        self.exists(filename)
        try:
            result = self.session.request('PROPFIND', path, verify=False, headers=headers, timeout=self.timeout, cert=self.cert)
            if result.status_code in [404, ]:
                raise exception.SourceNotFound()
            elif result.status_code in [401, ]:
                raise exception.RSEAccessDenied()
            parser = Parser()
            parser.feed(result.text)
            list_files = [self.server + p_file for p_file in parser.list]
            try:
                list_files.remove(filename + '/')
            except ValueError:
                pass
            try:
                list_files.remove(filename)
            except ValueError:
                pass
            parser.close()
            return list_files
        except requests.exceptions.ConnectionError as error:
            raise exception.ServiceUnavailable(error)
        except requests.exceptions.ReadTimeout as error:
            raise exception.ServiceUnavailable(error)

    def stat(self, path):
        """
            Returns the stats of a file.

            :param path: path to file

            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
            :raises RSEAccessDenied: in case of permission issue.

            :returns: a dict with two keys, filesize and adler32 of the file provided in path.
        """
        raise NotImplementedError
        headers = {'Depth': '1'}
        dict = {}
        try:
            result = self.session.request('PROPFIND', path, verify=False, headers=headers, timeout=self.timeout, cert=self.cert)
            if result.status_code in [404, ]:
                raise exception.SourceNotFound()
            elif result.status_code in [401, ]:
                raise exception.RSEAccessDenied()
            if result.status_code in [400, ]:
                raise NotImplementedError
            parser = Parser()
            parser.feed(result.text)
            for file_name in parser.sizes:
                if '%s%s' % (self.server, file_name) == path:
                    dict['size'] = parser.sizes[file_name]
            parser.close()
            return dict
        except requests.exceptions.ConnectionError as error:
            raise exception.ServiceUnavailable(error)
        except requests.exceptions.ReadTimeout as error:
            raise exception.ServiceUnavailable(error)

    def get_space_usage(self):
        """
        Get RSE space usage information.

        :returns: a list with dict containing 'totalsize' and 'unusedsize'

        :raises ServiceUnavailable: if some generic error occured in the library.
        """
        endpoint_basepath = self.path2pfn('')
        headers = {'Depth': '0'}

        try:
            root = ET.fromstring(self.session.request('PROPFIND', endpoint_basepath, verify=False, headers=headers, cert=self.session.cert).text)
            usedsize = root[0][1][0].find('{DAV:}quota-used-bytes').text
            try:
                unusedsize = root[0][1][0].find('{DAV:}quota-available-bytes').text
            except Exception:
                print('No free space given, return -999')
                unusedsize = -999
            totalsize = int(usedsize) + int(unusedsize)
            return totalsize, unusedsize
        except Exception as error:
            raise exception.ServiceUnavailable(error)
