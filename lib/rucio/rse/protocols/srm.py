# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2015
# - Wen Guan, <wguan@cern.ch>, 2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014, 2017
# - Nicolo Magini, <nicolo.magini@cern.ch>, 2018
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2019
#
# PY3K COMPATIBLE

import os
import re
try:
    # PY2
    import urlparse
except ImportError:
    # PY3
    import urllib.parse as urlparse

try:
    # PY2
    from commands import getstatusoutput
except ImportError:
    # PY3
    from subprocess import getstatusoutput
from six import string_types

from rucio.common import exception
from rucio.common.utils import execute
from rucio.rse.protocols import protocol


class Default(protocol.RSEProtocol):
    """ Implementing access to RSEs using the SRM protocol. """

    def lfns2pfns(self, lfns):
        """
        Returns a fully qualified PFN for the file referred by path.

        :param path: The path to the file.
        :returns: Fully qualified PFN.
        """

        pfns = {}
        prefix = self.attributes['prefix']
        if self.attributes['extended_attributes'] is not None and\
           'web_service_path' in list(self.attributes['extended_attributes'].keys()):
            web_service_path = self.attributes['extended_attributes']['web_service_path']
        else:
            web_service_path = ''

        if not prefix.startswith('/'):
            prefix = ''.join(['/', prefix])
        if not prefix.endswith('/'):
            prefix = ''.join([prefix, '/'])

        hostname = self.attributes['hostname']
        if '://' in hostname:
            hostname = hostname.split("://")[1]

        lfns = [lfns] if type(lfns) == dict else lfns
        if not self.attributes['port']:
            for lfn in lfns:
                scope, name, path = lfn['scope'], lfn['name'], lfn.get('path')
                if not path:
                    path = self._get_path(scope=scope, name=name)
                if path.startswith('/'):
                    path = path[1:]
                pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'], '://',
                                                         hostname, web_service_path, prefix, path])
        else:
            for lfn in lfns:
                scope, name, path = lfn['scope'], lfn['name'], lfn.get('path')
                if not path:
                    path = self._get_path(scope=scope, name=name)
                if path.startswith('/'):
                    path = path[1:]
                pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'], '://',
                                                         hostname, ':', str(self.attributes['port']),
                                                         web_service_path, prefix, path])

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
        pfns = [pfns] if isinstance(pfns, string_types) else pfns
        for pfn in pfns:
            parsed = urlparse.urlparse(pfn)
            if parsed.path.startswith('/srm/managerv2') or\
               parsed.path.startswith('/srm/managerv1') or\
               parsed.path.startswith('/srm/v2/server'):
                scheme, hostname, port, service_path, path = re.findall(r"([^:]+)://([^:/]+):?(\d+)?([^:]+=)?([^:]+)", pfn)[0]
            else:
                scheme = parsed.scheme
                hostname = parsed.netloc.partition(':')[0]
                port = parsed.netloc.partition(':')[2]
                path = parsed.path
                service_path = ''

            # force type conversion
            try:
                port = int(port)
            except:
                port = ''

            if self.attributes['hostname'] != hostname and\
               self.attributes['hostname'] != scheme + "://" + hostname:
                raise exception.RSEFileNameNotSupported('Invalid hostname: provided \'%s\', expected \'%s\'' % (hostname,
                                                                                                                self.attributes['hostname']))

            if port != '' and str(self.attributes['port']) != str(port):
                raise exception.RSEFileNameNotSupported('Invalid port: provided \'%s\', expected \'%s\'' % (port,
                                                                                                            self.attributes['port']))
            elif port == '':
                port = self.attributes['port']

            if not path.startswith(self.attributes['prefix']):
                raise exception.RSEFileNameNotSupported('Invalid prefix: provided \'%s\', expected \'%s\'' % ('/'.join(path.split('/')[0:len(self.attributes['prefix'].split('/')) - 1]),
                                                                                                              self.attributes['prefix']))  # len(...)-1 due to the leading '/

            # Spliting path into prefix, path, filename
            prefix = self.attributes['prefix']
            path = path.partition(self.attributes['prefix'])[2]
            name = path.split('/')[-1]
            path = '/' + '/'.join(path.split('/')[:-1]) if not self.rse['staging_area'] else None

            if path != '/' and path[:-1] != '/':
                path += '/'

            ret[pfn] = {'scheme': scheme, 'port': port, 'hostname': hostname,
                        'path': path, 'name': name, 'prefix': prefix,
                        'web_service_path': service_path}

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
        if '://' in hostname:
            hostname = hostname.split("://")[1]

        if 'extended_attributes' in list(self.attributes.keys()) and\
           self.attributes['extended_attributes'] is not None and\
           'web_service_path' in list(self.attributes['extended_attributes'].keys()):
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

        :raises RSEAccessDenied: Cannot connect.
        """

        status, lcglscommand = getstatusoutput('which lcg-ls')
        if status:
            raise exception.RSEAccessDenied('Cannot find lcg tools')
        endpoint_basepath = self.path2pfn(self.attributes['prefix'])
        status, result = getstatusoutput('%s -vv $LCGVO -b --srm-timeout 60 -D srmv2 -l %s' % (lcglscommand, endpoint_basepath))
        if status:
            if result == '':
                raise exception.RSEAccessDenied('Endpoint not reachable. lcg-ls failed with status code %s but no further details.' % (str(status)))
            else:
                raise exception.RSEAccessDenied('Endpoint not reachable : %s' % str(result))

    def get(self, path, dest, transfer_timeout=None):
        """
        Provides access to files stored inside connected the RSE.

        :param path: Physical file name of requested file
        :param dest: Name and path of the files when stored at the client
        :param transfer_timeout: Transfer timeout (in seconds)

        :raises DestinationNotAccessible: if the destination storage was not accessible.
        :raises ServiceUnavailable: if some generic error occured in the library.
        :raises SourceNotFound: if the source file was not found on the referred storage.
        """

        timeout_option = ''
        if transfer_timeout:
            timeout_option = '--sendreceive-timeout %s' % transfer_timeout

        try:
            cmd = 'lcg-cp $LCGVO -v -b --srm-timeout 3600 %s -D srmv2 %s file:%s' % (timeout_option, path, dest)
            status, out, err = execute(cmd)
            if status:
                if self.__parse_srm_error__("SRM_INVALID_PATH", out, err):
                    raise exception.SourceNotFound(err)
                raise exception.RucioException(err)
        except exception.SourceNotFound as error:
            raise exception.SourceNotFound(str(error))
        except Exception as error:
            raise exception.ServiceUnavailable(error)

    def put(self, source, target, source_dir, transfer_timeout=None):
        """
        Allows to store files inside the referred RSE.

        :param source: path to the source file on the client file system
        :param target: path to the destination file on the storage
        :param source_dir: Path where the to be transferred files are stored in the local file system
        :param transfer_timeout: Transfer timeout (in seconds)

        :raises DestinationNotAccessible: if the destination storage was not accessible.
        :raises ServiceUnavailable: if some generic error occured in the library.
        :raises SourceNotFound: if the source file was not found on the referred storage.
        """

        source_url = '%s/%s' % (source_dir, source) if source_dir else source

        if not os.path.exists(source_url):
            raise exception.SourceNotFound()

        space_token = ''
        if self.attributes['extended_attributes'] is not None and 'space_token' in list(self.attributes['extended_attributes'].keys()):
            space_token = '--dst %s' % self.attributes['extended_attributes']['space_token']

        timeout_option = ''
        if transfer_timeout:
            timeout_option = '--sendreceive-timeout %s' % transfer_timeout

        try:
            cmd = 'lcg-cp $LCGVO -v -b --srm-timeout 3600 %s -D srmv2 %s file:%s %s' % (timeout_option, space_token, source_url, target)
            status, out, err = execute(cmd)
            if status:
                raise exception.RucioException(err)
        except Exception as error:
            raise exception.ServiceUnavailable(error)

    def delete(self, path):
        """
        Deletes a file from the connected RSE.

        :param path: path to the to be deleted file
        :raises ServiceUnavailable: if some generic error occured in the library.
        :raises SourceNotFound: if the source file was not found on the referred storage.
        """

        pfns = [path] if isinstance(path, string_types) else path

        try:
            pfn_chunks = [pfns[i:i + 20] for i in range(0, len(pfns), 20)]
            for pfn_chunk in pfn_chunks:
                cmd = 'lcg-del $LCGVO -v -b -l --srm-timeout 600 -D srmv2'
                for pfn in pfn_chunk:
                    cmd += ' ' + pfn
                status, out, err = execute(cmd)
                if status:
                    if self.__parse_srm_error__("SRM_INVALID_PATH", out, err):
                        raise exception.SourceNotFound(err)
                    raise exception.RucioException(err)
        except exception.SourceNotFound as error:
            raise exception.SourceNotFound(str(error))
        except Exception as error:
            raise exception.ServiceUnavailable(error)

    def rename(self, path, new_path):
        """
        Allows to rename a file stored inside the connected RSE.

        :param path: path to the current file on the storage
        :param new_path: path to the new file on the storage
        :raises DestinationNotAccessible: if the destination storage was not accessible.
        :raises ServiceUnavailable: if some generic error occured in the library.
        :raises SourceNotFound: if the source file was not found on the referred storage.
        """

        space_token = ''
        if self.attributes['extended_attributes'] is not None and 'space_token' in list(self.attributes['extended_attributes'].keys()):
            space_token = '--dst %s' % self.attributes['extended_attributes']['space_token']

        try:
            cmd = 'lcg-cp $LCGVO -v -b --srm-timeout 3600 -D srmv2 %s %s %s' % (space_token, path, new_path)
            status, out, err = execute(cmd)
            if status:
                raise exception.RucioException(err)

            cmd = 'lcg-del $LCGVO -v -b -l --srm-timeout 600 -D srmv2 %s' % (path)
            status, out, err = execute(cmd)
            if status:
                raise exception.RucioException(err)
        except Exception as error:
            raise exception.ServiceUnavailable(error)

    def exists(self, path):
        """
        Checks if the requested file is known by the referred RSE.

        :param path: Physical file name
        :returns: True if the file exists, False if it doesn't
        :raises SourceNotFound: if the source file was not found on the referred storage.
        """

        try:
            cmd = 'lcg-ls $LCGVO -v -b --srm-timeout 60 -D srmv2  %s' % (path)
            status, out, err = execute(cmd)
            if status:
                return False
            return True
        except Exception as error:
            raise exception.ServiceUnavailable(error)

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
