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
# - Wen Guan, <wguan@cern.ch>, 2014

import commands
import os
import re
import urlparse

from rucio.common import exception
from rucio.rse.protocols import protocol
from rucio.common.utils import execute


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
        if self.attributes['extended_attributes'] is not None and 'web_service_path' in self.attributes['extended_attributes'].keys():
            web_service_path = self.attributes['extended_attributes']['web_service_path']
        else:
            web_service_path = ''

        if not prefix.startswith('/'):
            prefix = ''.join(['/', prefix])
        if not prefix.endswith('/'):
            prefix = ''.join([prefix, '/'])

        hostname = self.attributes['hostname']
        if hostname.count("://"):
            hostname = hostname.split("://")[1]

        lfns = [lfns] if type(lfns) == dict else lfns
        if self.attributes['port'] == 0:
            for lfn in lfns:
                scope, name = lfn['scope'], lfn['name']
                pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'], '://', hostname, web_service_path, prefix, self._get_path(scope=scope, name=name)])
        else:
            for lfn in lfns:
                scope, name = lfn['scope'], lfn['name']
                pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'], '://', hostname, ':', str(self.attributes['port']), web_service_path, prefix, self._get_path(scope=scope, name=name)])

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
                service_path = ''

            if self.attributes['hostname'] != hostname and self.attributes['hostname'] != scheme + "://" + hostname:
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
            ret[pfn] = {'scheme': scheme, 'port': port, 'hostname': hostname, 'path': path, 'name': name, 'prefix': prefix, 'web_service_path': service_path}

        return ret

    def path2pfn(self, path):
        """
            Returns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.
        """
        if path.startswith("srm://"):
            return path

        hostname = self.attributes['hostname']
        if hostname.count("://"):
            hostname = hostname.split("://")[1]

        if 'extended_attributes' in self.attributes.keys() and self.attributes['extended_attributes'] is not None and 'web_service_path' in self.attributes['extended_attributes'].keys():
            web_service_path = self.attributes['extended_attributes']['web_service_path']
        else:
            web_service_path = ''

        if not path.startswith('srm'):
            if self.attributes['port'] > 0:
                return ''.join([self.attributes['scheme'], '://', hostname, ':', str(self.attributes['port']), web_service_path, path])
            else:
                return ''.join([self.attributes['scheme'], '://', hostname, web_service_path, path])
        else:
            return path

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
        endpoint_basepath = self.path2pfn(self.attributes['prefix'])
        status, result = commands.getstatusoutput('%s -l  --srm-timeout 60 --defaultsetype srmv2 %s' % (lcglscommand, endpoint_basepath))
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
        space_token = ''
        if self.attributes['extended_attributes'] is not None and 'space_token' in self.attributes['extended_attributes'].keys():
            space_token = '--sst ' + self.attributes['extended_attributes']['space_token']

        try:
            cmd = 'lcg-cp -v  --srm-timeout 3600  --defaultsetype srmv2 %s  %s file:%s' % (space_token, path, dest)
            status, out, err = execute(cmd)
            if not status == 0:
                if self.__parse_srm_error__("SRM_INVALID_PATH", out, err):
                    raise exception.SourceNotFound(err)
                raise exception.RucioException(err)
        except exception.SourceNotFound as e:
            raise exception.SourceNotFound(str(e))
        except Exception as e:
            raise exception.ServiceUnavailable(e)

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
        source_url = '%s/%s' % (source_dir, source) if source_dir else source

        if not os.path.exists(source_url):
            raise exception.SourceNotFound()

        space_token = ''
        if self.attributes['extended_attributes'] is not None and 'space_token' in self.attributes['extended_attributes'].keys():
            space_token = '--dst ' + self.attributes['extended_attributes']['space_token']

        try:
            cmd = 'lcg-cp -v  --srm-timeout 3600 --defaultsetype srmv2 %s file:%s %s' % (space_token, source_url, target)
            status, out, err = execute(cmd)
            if not status == 0:
                raise exception.RucioException(err)
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def delete(self, path):
        """
            Deletes a file from the connected RSE.

            :param path: path to the to be deleted file

            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        pfns = [path] if ((type(path) == str) or (type(path) == unicode)) else path

        #if not self.exists(path):
        #    raise exception.SourceNotFound()

        try:
            pfn_chunks = [pfns[i:i + 20] for i in range(0, len(pfns), 20)]
            for pfn_chunk in pfn_chunks:
                cmd = 'lcg-del -v --nolfc --srm-timeout 600 --defaultsetype srmv2'
                for pfn in pfn_chunk:
                    cmd += ' ' + pfn
                status, out, err = execute(cmd)
                if not status == 0:
                    if self.__parse_srm_error__("SRM_INVALID_PATH", out, err):
                        raise exception.SourceNotFound(err)
                    raise exception.RucioException(err)
        except exception.SourceNotFound as e:
            raise exception.SourceNotFound(str(e))
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def rename(self, path, new_path):
        """
            Allows to rename a file stored inside the connected RSE.

            :param path: path to the current file on the storage
            :param new_path: path to the new file on the storage

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """

        try:
            #self.create_dest_dir(os.path.dirname(new_path))
            cmd = 'lcg-cp -v  --srm-timeout 3600 --defaultsetype srmv2 %s %s' % (path, new_path)
            status, out, err = execute(cmd)
            if not status == 0:
                raise exception.RucioException(err)

            cmd = 'lcg-del -v --nolfc --srm-timeout 600 --defaultsetype srmv2 %s' % (path)
            status, out, err = execute(cmd)
            if not status == 0:
                raise exception.RucioException(err)
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def exists(self, path):
        """
            Checks if the requested file is known by the referred RSE.

            :param path: Physical file name

            :returns: True if the file exists, False if it doesn't

            :raises SourceNotFound: if the source file was not found on the referred storage.
        """

        try:
            cmd = 'lcg-ls -v  --srm-timeout 60 --defaultsetype srmv2  %s' % (path)
            status, out, err = execute(cmd)
            if not status == 0:
                return False
            return True
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def __parse_srm_error__(self, err_code, out, err):
        """Parse the error message to return error code."""
        if out is not None and len(out) > 0:
            if out.count(err_code) > 0:
                return True
        if err is not None and len(err) > 0:
            if err.count(err_code) > 0:
                return True
        return False

    def close(self):
        """
            Closes the connection to RSE.
        """
        pass
