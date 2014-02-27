# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2014

import commands
import os
import re
import subprocess
import signal
import sys
import time
import urlparse

from rucio.common import exception
from rucio.rse.protocols import protocol


class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using the srm protocol."""

    def lfns2pfns(self, lfns):
        """
            Returns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.
        """
        pfns = {}
        prefix = self.attributes['prefix']
        web_service_path = self.attributes['extended_attributes']['web_service_path']

        if not prefix.startswith('/'):
            prefix = ''.join(['/', prefix])
        if not prefix.endswith('/'):
            prefix = ''.join([prefix, '/'])

        lfns = [lfns] if type(lfns) == dict else lfns
        for lfn in lfns:
            scope, name = lfn['scope'], lfn['name']
            pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'], '://', self.attributes['hostname'], ':', str(self.attributes['port']), web_service_path, prefix, self._get_path(scope=scope, name=name)])
        return pfns

    def parse_pfns(self, pfns):
        """
            Splits the given PFN into the parts known by the protocol. During parsing the PFN is also checked for
            validity on the given RSE with the given protocol.

            :param pfn: a fully qualified PFN

            :returns: a dict containing all known parts of the PFN for the protocol e.g. scheme, path, filename

            :raises RSEFileNameNotSupported: if the provided PFN doesn't match with the protocol settings
        """
        ret = dict()
        pfns = [pfns] if ((type(pfns) == str) or (type(pfns) == unicode)) else pfns
        for pfn in pfns:
            parsed = urlparse.urlparse(pfn)
            if parsed.path.startswith('/srm/managerv2') or parsed.path.startswith('/srm/managerv1') or parsed.path.startswith('/srm/v2/server'):
                scheme, hostname, port, service_path, path = re.findall(r"([^:]+)://([^:/]+):?(\d+)?([^:]+=)?([^:]+)", pfn)[0]
            else:
                scheme = parsed.scheme
                hostname = parsed.netloc.partition(':')[0]
                port = parsed.netloc.partition(':')[2]
                path = parsed.path

            if self.attributes['hostname'] != hostname:
                raise exception.RSEFileNameNotSupported('Invalid hostname: provided \'%s\', expected \'%s\'' % (hostname, self.attributes['hostname']))

            if port != '' and str(self.attributes['port']) != str(port):
                raise exception.RSEFileNameNotSupported('Invalid port: provided \'%s\', expected \'%s\'' % (port, self.attributes['port']))
            elif port == '':
                port = self.attributes['port']

            if not path.startswith(self.attributes['prefix']):
                raise exception.RSEFileNameNotSupported('Invalid prefix: provided \'%s\', expected \'%s\'' % ('/'.join(path.split('/')[0:len(self.attributes['prefix'].split('/')) - 1]),
                                                                                                              self.attributes['prefix']))  # len(...)-1 due to the leading '/
            # Spliting path into prefix, path, filename
            prefix = self.attributes['prefix']
            path = path.partition(self.attributes['prefix'])[2]
            name = path.split('/')[-1]
            path = path.partition(name)[0]
            ret[pfn] = {'scheme': scheme, 'port': port, 'hostname': hostname, 'path': path, 'name': name, 'prefix': prefix}

        return ret

    def connect(self):
        """
            Establishes the actual connection to the referred RSE.
            As a quick and dirty impelementation we just use this method to check if the lcg tools are available.
            If we decide to use gfal, init should be done here.

            :raises RSEAccessDenied
        """
        status, lcglscommand = commands.getstatusoutput('which lcg-ls')
        if status != 0:
            raise exception.RSEAccessDenied('Cannot find lcg tools')
        endpoint_basepath = ''.join([self.attributes['scheme'], '://', self.attributes['hostname'], ':', str(self.attributes['port']), self.attributes['extended_attributes']['web_service_path'], self.attributes['prefix']])
        status, result = commands.getstatusoutput('%s -l -b --setype srmv2 %s' % (lcglscommand, endpoint_basepath))
        if status != 0:
            print result
            raise exception.RSEAccessDenied('Endpoint not reachable')

    def get(self, path, dest):
        """
            Provides access to files stored inside connected the RSE.

            :param path: Physical file name of requested file
            :param dest: Name and path of the files when stored at the client

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
         """
        alive = True
        timeout = 3600
        timeoutCounter = 0
        proc = subprocess.Popen('lcg-cp -v -b --srcsetype srmv2 %s file:%s' % (path, dest), shell=True)
        # This part is taken from dq2-get
        try:
            while(alive):
                if timeoutCounter > timeout:
                    os.kill(proc.pid, signal.SIGKILL)
                    break
                else:
                    #None means still running
                    if proc.poll() is None:
                        time.sleep(1)
                    else:
                        alive = False
        except:
            excType, excValue, excStack = sys.exc_info()
            print excValue

    def put(self, source, target, source_dir):
        """
            Allows to store files inside the referred RSE.

            :param source: path to the source file on the client file system
            :param target: path to the destination file on the storage
            :param source_dir: Path where the to be transferred files are stored in the local file system

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        raise NotImplementedError

    def delete(self, path):
        """
            Deletes a file from the connected RSE.

            :param path: path to the to be deleted file

            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        raise NotImplementedError

    def close(self):
        """ Closes the connection to RSE."""
        pass
