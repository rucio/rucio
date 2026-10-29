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
from typing import TYPE_CHECKING, Optional, Union
from urllib.parse import urlparse

from rucio.common import exception
from rucio.common.constants import RseAttr
from rucio.common.extra import import_extras
from rucio.core.rse import get_rse_attribute
from rucio.rse.protocols.protocol import RSEProtocol
from rucio.transfertool.globus_library import GlobusTools

EXTRA_MODULES = import_extras(['globus_sdk'])

if EXTRA_MODULES['globus_sdk']:
    from globus_sdk import TransferAPIError  # pylint: disable=import-error

if TYPE_CHECKING:
    from collections.abc import Iterable


class Default(RSEProtocol):
    """ Implementing access to RSEs using the Globus service as a Rucio RSE protocol. """

    def __init__(self, protocol_attr, rse_settings, logger=logging.log):
        """ Initializes the object with information about the referred RSE.

            :param props: Properties of the requested protocol
        """
        super(Default, self).__init__(protocol_attr, rse_settings, logger=logger)
        self.globus_endpoint_id = get_rse_attribute(self.rse.get('id'), RseAttr.GLOBUS_ENDPOINT_ID)
        self.globus_collection_id = get_rse_attribute(self.rse.get('id'), RseAttr.GLOBUS_COLLECTION_ID)

        self.logger = logger
        self.tools = GlobusTools()

    def lfns2pfns(self, lfns) -> dict[str, str]:
        """
            Returns a fully qualified PFN for the file referred by path.

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

    def parse_pfns(self, pfns: Union[str, "Iterable"]) -> dict[str, dict[str, str]]:
        """
            Splits the given PFN into the parts known by the protocol. It is also checked if the provided protocol supports the given PFNs.

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

            if not path.startswith(self.attributes['prefix']):
                provided_path = '/'.join(path.split('/')[0:len(self.attributes['prefix'].split('/')) - 1])
                msg = f"Invalid prefix: provided {provided_path}, expected {self.attributes['prefix']}"
                raise exception.RSEFileNameNotSupported(msg)

            # Splitting parsed.path into prefix, path, filename
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

    def exists(self, path: str) -> bool:
        """
            Checks if the requested file is known by the referred RSE.

            :param path: Physical file name

            :returns: True if the file exists, False if it doesn't

            :raises SourceNotFound: if the source file was not found on the referred storage.

        """

        file_info = self.parse_pfns(path)[path]
        filepath = file_info['path']
        filename = file_info['name']
        exists = False

        if self.globus_collection_id:
            try:
                with self.tools.transfer_client() as tc:
                    resp = tc.operation_ls(endpoint_id=self.globus_collection_id, path=file_info['prefix'].rstrip('/') + filepath, filter={'name': filename})
                    exists = len(resp['DATA']) != 0
            except TransferAPIError as err:
                raise exception.ServiceUnavailable(err)
        else:
            raise exception.ServiceUnavailable('No rse attribute found for globus collection id.')

        return exists

    def list(self, path: str) -> list[str]:
        """

            Checks if the requested path is known by the referred RSE and returns a list of items

            :param path: Physical file name

            :returns: List of items

        """

        items = []

        if self.globus_collection_id:
            try:
                with self.tools.transfer_client() as tc:
                    resp = tc.operation_ls(endpoint_id=self.globus_collection_id, path=path)
                    items = resp['DATA']
            except TransferAPIError as err:
                self.logger(logging.DEBUG, err)
                raise exception.ServiceUnavailable()
        else:
            raise exception.ServiceUnavailable('No rse attribute found for globus collection id.')

        return items

    def delete(self, path: str) -> None:
        """
            Deletes a file from the connected RSE.

            :param path: path to the to be deleted file

            :raises ServiceUnavailable: if some generic error occurred in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """

        if not self.exists(path):
            raise exception.SourceNotFound()

        if self.globus_collection_id:
            try:
                ddata = self.tools.build_delete_data(delete_items=[path], endpoint_id=self.globus_collection_id)
                delete_response = self.tools.submit_deletion(ddata)
            except TransferAPIError as err:
                self.logger(logging.WARNING, str(err))
                raise exception.ServiceUnavailable(err)
        else:
            raise exception.ServiceUnavailable('No rse attribute found for globus collection id.')

        if delete_response['code'] != 'Accepted':
            self.logger(logging.DEBUG, 'delete_response: %s' % delete_response)
            raise exception.ServiceUnavailable('delete_task not accepted by Globus')

    def bulk_delete(self, pfns: "Iterable[str]") -> None:
        """
            Submits an async task to bulk delete files on globus endpoint.

            :param pfns: list of pfns to delete

            :raises ServiceUnavailable: if unexpected response from the service.
        """
        if self.globus_collection_id:
            try:
                ddata = self.tools.build_delete_data(delete_items=pfns, endpoint_id=self.globus_collection_id)
                delete_response = self.tools.submit_deletion(ddata)
            except TransferAPIError as err:
                raise exception.ServiceUnavailable(err)
        else:
            raise exception.ServiceUnavailable('No rse attribute found for globus collection id.')

        if delete_response['code'] != 'Accepted':
            self.logger(logging.DEBUG, 'delete_response: %s' % delete_response)
            raise exception.ServiceUnavailable('delete_task not accepted by Globus')

    def connect(self) -> None:
        """
            Establishes the actual connection to the referred RSE.

            Pings the endpoint to establish connection credidentals.
        """
        if self.globus_endpoint_id:
            with self.tools.transfer_client() as tc:
                response = tc.get_endpoint(self.globus_endpoint_id)
            if response.http_status != 200:
                msg = f"Failed to fetch endpoint infomation.\n{response.text}"
                raise exception.ServiceUnavailable(msg)
        else:
            raise exception.ServiceUnavailable("No attribute found for globus endpoint id.")

    def close(self) -> None:
        """
            Closes the connection to RSE.
        """
        pass

    def get(self,
            path: str,
            dest: str,
            transfer_timeout: Optional[int] = None) -> None:
        """
        Download file to a local path.
        """
        msg = "Cannot download from Globus through Rucio. Please either visit the web portal to upload your file or use the Globus Personal Endpoint."
        raise NotImplementedError(msg)

    def put(self, *args, **kwargs) -> None:
        """Upload"""
        msg = "Cannot upload to Globus through Rucio. Please either visit the web portal to upload your file or use the Globus Personal Endpoint."
        raise NotImplementedError(msg)

    def rename(self, pfn: str, new_pfn: str) -> None:

        if not self.globus_collection_id:
            raise exception.ServiceUnavailable('No rse attribute found for globus collection id.')

        if not self.exists(pfn):
            raise exception.SourceNotFound()

        path = self.attributes['prefix'] + self.parse_pfns(pfn)[pfn]['name']
        new_path = self.attributes['prefix'] + self.parse_pfns(new_pfn)[new_pfn]['name']

        with self.tools.transfer_client() as tc:
            resp = tc.operation_rename(self.globus_collection_id, path, new_path)

        if resp.http_status != 200:
            msg = f"Could not submit rename request.\n{resp.text}"
            raise exception.ServiceUnavailable(msg)
