# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Cedric Serfon <cedric.serfon@cern.ch>, 2012

import os
import requests
from sys import stdout
from xml.parsers import expat

from rucio.common import exception
from rucio.rse.protocols import protocol


class uploadInChunks(object):
    def __init__(self, filename, chunksize):
        self.__totalsize = os.path.getsize(filename)
        self.__readsofar = 0
        self.__filename = filename
        self.__chunksize = chunksize

    def __iter__(self):
        try:
            with open(self.__filename, 'rb') as file:
                while True:
                    data = file.read(self.__chunksize)
                    if not data:
                        stdout.write("\n")
                        break
                    self.__readsofar += len(data)
                    percent = self.__readsofar * 100 / self.__totalsize
                    stdout.write("\r{percent:3.0f}%".format(percent=percent))
                    yield data
        except OSError, e:
            raise exception.SourceNotFound(e)

    def __len__(self):
        return self.__totalsize


class IterableToFileAdapter(object):
    def __init__(self, iterable):
        self.iterator = iter(iterable)
        self.length = len(iterable)

    def read(self, size=-1):   # TBD: add buffer for `len(data) > size` case
        return next(self.iterator, b'')

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
        self.dict = {}
        self.list = []

    def feed(self, data):
        """ Feed the parser with data"""
        self._parser.Parse(data, 0)

    def close(self):
        self._parser.Parse("", 1)
        del self._parser

    def start(self, tag, attrs):
        if (tag == 'D:href'):
            self.hrefflag = 1
        if (tag == 'D:status'):
            self.status = 1

    def end(self, tag):
        if (tag == 'D:href'):
            self.hrefflag = 0
        if (tag == 'D:status'):
            self.status = 0

    def data(self, data):
        if self.hrefflag:
            self.href = str(data)
            self.list.append(self.href)
        if self.status:
            self.dict[self.href] = data


class Default(protocol.RSEProtocol):

    """ Implementing access to RSEs using the webDAV protocol."""

    def __init__(self, props):
        """ Initializes the object with information about the referred RSE.

            :param props Properties derived from the RSE Repository
        """
        self.rse = props

    def connect(self, credentials):
        """ Establishes the actual connection to the referred RSE.

            :param credentials Provides information to establish a connection
                to the referred storage system. For WebDAV connections these are
                ca_cert, cert, auth_type, timeout

            :raises RSEAccessDenied
        """

        try:
            self.server = self.rse['protocol']['host']
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
            self.cert = (x509, x509)

        try:
            self.timeout = credentials['timeout']
        except KeyError:
            self.timeout = 300
        #self.session=requests.session(auth_type=self.auth_type, timeout=self.timeout, cert=self.cert)
        self.session = requests.session(timeout=self.timeout, cert=self.cert)

        # "ping" to see if the server is available
        try:
            self.session.request('HEAD', self.server, verify=False)
        except requests.exceptions.ConnectionError, e:
            raise exception.ServiceUnavailable(e)

    def close(self):
        self.session.close()

    def pfn2uri(self, pfn):
        """ Transforms the physical file name into the local URI in the referred RSE.

            :param pfn Physical file name

            :returns: RSE specific URI of the physical file
        """
        if not pfn.startswith('https'):
            return '%s%s/%s' % (self.rse['protocol']['host'].rstrip('/'), self.rse['protocol']['prefix'].rstrip('/'), pfn)
        else:
            return pfn

    def exists(self, pfn):
        """ Checks if the requested file is known by the referred RSE.

            :param pfn Physical file name

            :returns: True if the file exists, False if it doesn't

            :raise  ServiceUnavailable
        """
        path = self.pfn2uri(pfn)
        #print 'Checking existence of '+path
        try:
            result = self.session.request('HEAD', path, verify=False)
            if (result.status_code == 200):
                return True
            elif result.status_code in [404, ]:
                return False
            else:
                # catchall exception
                raise exception.RucioException(result.status_code, result.text)
        except requests.exceptions.ConnectionError, e:
            raise exception.ServiceUnavailable(e)

    def get(self, pfn, dest='.'):
        """ Provides access to files stored inside connected the RSE.

            :param pfn Physical file name of requested file
            :param dest Name and path of the files when stored at the client

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        path = self.pfn2uri(pfn)
        chunksize = 1024
        #print 'Will get %s' %(path)
        try:
            result = self.session.get(path, verify=False, prefetch=False)
            if result and result.status_code in [200, ]:
                length = int(result.headers['content-length'])
                totnchunk = int(length / chunksize) + 1
                progressbar_width = 100
                stdout.write("[%s]\t  0/100" % (" " * progressbar_width))
                nchunk = 0
                f = open(dest, 'wb')
                for chunk in result.iter_content(chunksize):
                    nchunk += 1
                    f.write(chunk)
                    percent = int(100 * nchunk / (float(totnchunk)))
                    stdout.write("\r[%s%s]\t  %s/100" % ("+" * percent, "-" * (100 - percent), percent))
                    stdout.flush()
                stdout.write('\n')
                f.close()
            elif result.status_code in [404, 403]:
                raise exception.SourceNotFound()
            else:
                # catchall exception
                raise exception.RucioException(result.status_code, result.text)
        except requests.exceptions.ConnectionError, e:
            raise exception.ServiceUnavailable(e)

    def put(self, source, target, source_dir=None):
        """ Allows to store files inside the referred RSE.

            :param source Physical file name
            :param target Name of the file on the storage system e.g. with prefixed scope
            :param source_dir Path where the to be transferred files are stored in the local file system

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        path = self.pfn2uri(target)
        full_name = source_dir + '/' + source if source_dir else source
        #print 'Will copy %s to %s' %(full_name,path)
        directories = path.split('/')
        for directory_level in reversed(xrange(1, 4)):
            upper_directory = "/".join(directories[:-directory_level])
            if not self.exists(upper_directory):
                self.mkdir(upper_directory)
        try:
            if not os.path.exists(full_name):
                raise exception.SourceNotFound()
            it = uploadInChunks(full_name, 10000000)
            result = self.session.put(path, data=IterableToFileAdapter(it), verify=False, allow_redirects=True)
            if result.status_code in [201, ]:
                return
            if result.status_code in [409, ]:
                raise exception.FileReplicaAlreadyExists()
            else:
                # catchall exception
                raise exception.RucioException(result.status_code, result.text)
        except requests.exceptions.ConnectionError, e:
            raise exception.ServiceUnavailable(e)
        except IOError, e:
            raise exception.SourceNotFound(e)

    def rename(self, pfn, new_pfn):
        """ Allows to rename a file stored inside the connected RSE.

            :param pfn      Current physical file name
            :param new_pfn  New physical file name

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        path = self.pfn2uri(pfn)
        new_path = self.pfn2uri(new_pfn)
        #print 'Moving %s to %s' % (path, new_path)
        directories = new_path.split('/')

        directoriesToCreate = []
        for directory_level in xrange(1, 6):
            upper_directory = "/".join(directories[:-directory_level])
            if not self.exists(upper_directory):
                directoriesToCreate.append(upper_directory)
            else:
                break

        for dir in reversed(directoriesToCreate):
            self.mkdir(dir)

        headers = {'Destination': new_path}
        try:
            result = self.session.request('MOVE', path, verify=False, headers=headers)
            if result.status_code == 201:
                return
            elif result.status_code in [404, ]:
                raise exception.SourceNotFound()
            else:
                # catchall exception
                raise exception.RucioException(result.status_code, result.text)
        except requests.exceptions.ConnectionError, e:
            raise exception.ServiceUnavailable(e)

    def delete(self, pfn):
        """ Deletes a file from the connected RSE.

            :param pfn Physical file name

            :raises ServiceUnavailable, SourceNotFound
        """
        path = self.pfn2uri(pfn)
        #print 'Will delete %s' % (path)
        listfiles = self.ls(path)
        if (listfiles == []):
            try:
                result = self.session.delete(path, verify=False)
                if result.status_code in [204, ]:
                    return
                elif result.status_code in [404, ]:
                    raise exception.SourceNotFound()
                else:
                    # catchall exception
                    raise exception.RucioException(result.status_code, result.text)
            except requests.exceptions.ConnectionError, e:
                raise exception.ServiceUnavailable(e)
        else:
            print listfiles

    def mkdir(self, directory):
        """ Internal method to create directories

            :param directory Name of the directory that needs to be created

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        path = self.pfn2uri(directory)
        #print 'Will create %s' % (path)
        try:
            result = self.session.request('MKCOL', path, verify=False)
            if result.status_code in [201, ]:
                return
            elif result.status_code in [404, ]:
                raise exception.SourceNotFound()
            else:
                # catchall exception
                raise exception.RucioException(result.status_code, result.text)
        except requests.exceptions.ConnectionError, e:
            raise exception.ServiceUnavailable(e)

    def ls(self, filename):
        """ Internal method to list files/directories

            :param filename Name of the directory that needs to be created

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        path = self.pfn2uri(filename)
        print 'Checking files in %s' % (path)
        headers = {'Depth': '1'}
        self.exists(filename)
        try:
            result = self.session.request('PROPFIND', path, verify=False, headers=headers)
            if result.status_code in [404, ]:
                raise exception.SourceNotFound()
            p = Parser()
            p.feed(result.text)
            list = [self.server + file for file in p.list]
            try:
                list.remove(filename + '/')
            except ValueError:
                pass
            try:
                list.remove(filename)
            except ValueError:
                pass
            p.close()
            return list
        except requests.exceptions.ConnectionError, e:
            raise exception.ServiceUnavailable(e)


#    def stat(self,basepath,file):
#        path=self.server+basepath+file
#        print 'Checking existence of '+path
#        headers={'Depth':'1'}
#        self.exists(basepath,file)
#        try:
#            result=self.session.request('PROPFIND',path,verify=False,headers=headers)
#            p = Parser()
#            p.feed(result.text)
#            #print p.dict
#            #if p.dict.has_key(basepath+file):
#            #    print p.dict[basepath+file]
#            list=p.list
#            print basepath+file
#            list.remove(basepath+file+'/')
#            p.close()
#            return list
#        except requests.exceptions.ConnectionError,e:
#            raise exception.ServiceUnavailable(e)
