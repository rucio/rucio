# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

import logging

from urllib.parse import urlparse

from rucio.common import exception
from rucio.common.extra import import_extras
from rucio.core.rse import get_rse_attribute
from rucio.rse.protocols.protocol import RSEProtocol
from rucio.transfertool.globus_library import get_transfer_client, send_delete_task, send_bulk_delete_task

EXTRA_MODULES = import_extras(['globus_sdk'])

if EXTRA_MODULES['globus_sdk']:
    from globus_sdk import TransferAPIError  # pylint: disable=import-error


class GlobusRSEProtocol(RSEProtocol):
    """ Implementing access to RSEs using the Globus service as a Rucio RSE protocol. """

    def __init__(self, protocol_attr, rse_settings, logger=logging.log):
        """ Initializes the object with information about the referred RSE.

            :param props: Properties of the requested protocol
        """
        super(GlobusRSEProtocol, self).__init__(protocol_attr, rse_settings, logger=logger)
        self.globus_endpoint_id = get_rse_attribute(self.rse.get('id'), 'globus_endpoint_id')
        self.logger = logger

    def lfns2pfns(self, lfns):
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

        lfns = [lfns] if isinstance(lfns, dict) else lfns
        for lfn in lfns:
            scope, name = lfn['scope'], lfn['name']

            if 'path' in lfn and lfn['path'] is not None:
                pfns['%s:%s' % (scope, name)] = ''.join([prefix, lfn['path'] if not lfn['path'].startswith('/') else lfn['path'][1:]])
            else:
                pfns['%s:%s' % (scope, name)] = ''.join([prefix, self._get_path(scope=scope, name=name)])
        return pfns

    def _get_path(self, scope, name):
        """ Transforms the logical file name into a PFN.
            Suitable for sites implementing the RUCIO naming convention.
            This implementation is only invoked if the RSE is deterministic.

            :param scope: scope
            :param name: filename

            :returns: RSE specific URI of the physical file
        """
        return self.translator.path(scope, name)

    def parse_pfns(self, pfns):
        """
            Splits the given PFN into the parts known by the protocol. It is also checked if the provided protocol supportes the given PFNs.

            :param pfns: a list of a fully qualified PFNs

            :returns: dic with PFN as key and a dict with path and name as value

            :raises RSEFileNameNotSupported: if the provided PFN doesn't match with the protocol settings
        """
        ret = dict()
        pfns = [pfns] if isinstance(pfns, str) else pfns

        for pfn in pfns:
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
            path = '/'.join(path.split('/')[:-1])
            if not path.startswith('/'):
                path = '/' + path
            if path != '/' and not path.endswith('/'):
                path = path + '/'
            ret[pfn] = {'path': path, 'name': name, 'scheme': scheme, 'prefix': prefix, 'port': port, 'hostname': hostname, }

        return ret

    def exists(self, path):
        """
            Checks if the requested file is known by the referred RSE.

            :param path: Physical file name

            :returns: True if the file exists, False if it doesn't

            :raises SourceNotFound: if the source file was not found on the referred storage.

        """

        filepath = '/'.join(path.split('/')[0:-1]) + '/'
        filename = path.split('/')[-1]

        transfer_client = get_transfer_client()
        exists = False

        if self.globus_endpoint_id:
            try:
                resp = transfer_client.operation_ls(endpoint_id=self.globus_endpoint_id, path=filepath)
                exists = len([r for r in resp if r['name'] == filename]) > 0
            except TransferAPIError as err:
                print(err)
        else:
            print('No rse attribute found for globus endpoint id.')

        return exists

    def list(self, path):
        """

            Checks if the requested path is known by the referred RSE and returns a list of items

            :param path: Physical file name

            :returns: List of items

        """

        transfer_client = get_transfer_client()
        items = []

        if self.globus_endpoint_id:
            try:
                resp = transfer_client.operation_ls(endpoint_id=self.globus_endpoint_id, path=path)
                items = resp['DATA']
            except TransferAPIError as err:
                print(err)
        else:
            print('No rse attribute found for globus endpoint id.')

        return items

    def delete(self, path):
        """
            Deletes a file from the connected RSE.

            :param path: path to the to be deleted file

            :raises ServiceUnavailable: if some generic error occured in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        if self.globus_endpoint_id:
            try:
                delete_response = send_delete_task(endpoint_id=self.globus_endpoint_id, path=path, logger=self.logger)
            except TransferAPIError as err:
                print(err)
        else:
            print('No rse attribute found for globus endpoint id.')

        if delete_response['code'] != 'Accepted':
            print('delete_task not accepted by Globus')
            print('delete_response: %s' % delete_response)

    def bulk_delete(self, pfns):
        """
            Submits an async task to bulk delete files on globus endpoint.

            :param pfns: list of pfns to delete

            :raises TransferAPIError: if unexpected response from the service.
        """
        if self.globus_endpoint_id:
            try:
                bulk_delete_response = send_bulk_delete_task(endpoint_id=self.globus_endpoint_id, pfns=pfns, logger=self.logger)
            except TransferAPIError as err:
                self.logger(logging.WARNING, str(err))
        else:
            self.logger(logging.WARNING, 'No rse attribute found for globus endpoint id.')

        if bulk_delete_response['code'] != 'Accepted':
            self.logger(logging.WARNING, 'delete_task not accepted by Globus')
            self.logger(logging.WARNING, 'delete_response: %s' % bulk_delete_response)

    def connect(self):
        """
            Establishes the actual connection to the referred RSE.

            reaper2 daemon requires implementation of protocol.connect
        """
        pass

    def close(self):
        """
            Closes the connection to RSE.

            reaper2 daemon requires implementation of protocol.close
        """
        pass
