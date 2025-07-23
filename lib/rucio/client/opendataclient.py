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

import json
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import quote_plus

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.config import config_get
from rucio.common.utils import build_url, render_json

if TYPE_CHECKING:
    from rucio.common.constants import OPENDATA_DID_STATE_LITERAL


class OpenDataClient(BaseClient):
    opendata_public_base_url = "opendata/public"
    opendata_private_base_url = "opendata"

    opendata_public_dids_base_url = f"{opendata_public_base_url}/dids"
    opendata_private_dids_base_url = f"{opendata_private_base_url}/dids"

    opendata_host_from_config = config_get('client', 'opendata_host', raise_exception=False, default=None)

    def get_opendata_host(self, *, public: bool) -> str:
        """
        Get the Opendata host URL for the public or private endpoint.
        The private opendata host is the regular rucio server, while the public opendata host can be configured separately (defaults to the same as the private one).

        Parameters:
            public: If True, return the public Opendata host URL. If False, return the private Opendata host URL.

        Returns:
            The Opendata host URL.
        """

        if public and self.opendata_host_from_config is not None:
            return self.opendata_host_from_config

        return choice(self.list_hosts)

    def list_opendata_dids(
            self,
            *,
            state: Optional["OPENDATA_DID_STATE_LITERAL"] = None,
            public: bool = False,
    ) -> dict[str, Any]:
        """
        Return a list of Opendata DIDs, optionally filtered by state and access type.

        Parameters:
            state: The state to filter DIDs by. If None, all states are included.
            public: If True, queries the public Opendata endpoint. Defaults to False.

        Returns:
            A dictionary containing the list of Opendata DIDs.

        Raises:
            ValueError: If both `state` and `public=True` are provided.
            Exception: If the request fails or the server returns an error.
        """

        base_url = self.opendata_public_dids_base_url if public else self.opendata_private_dids_base_url
        path = '/'.join([base_url])

        params = {}

        if state is not None:
            params['state'] = state

        if state is not None and public:
            raise ValueError('state and public cannot be provided at the same time.')

        url = build_url(self.get_opendata_host(public=public), path=path)
        r = self._send_request(url, type_='GET', params=params)
        if r.status_code == codes.ok:
            return json.loads(r.content.decode('utf-8'))
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def add_opendata_did(
            self,
            *,
            scope: str,
            name: str,
    ) -> bool:
        """
        Adds an existing Rucio DID (Data Identifier) to the Opendata catalog.

        Parameters:
            scope: The scope under which the DID is registered.
            name: The name of the DID.

        Returns:
            True if the DID was successfully added to the Opendata catalog, otherwise raises an exception.

        Raises:
            Exception: If the request fails or the server returns an error.
        """

        path = '/'.join([self.opendata_private_dids_base_url, quote_plus(scope), quote_plus(name)])
        url = build_url(self.get_opendata_host(public=False), path=path)

        r = self._send_request(url, type_='POST')

        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def remove_opendata_did(
            self,
            *,
            scope: str,
            name: str,
    ) -> bool:
        """
        Remove an existing Opendata DID from the Opendata catalog.

        Parameters:
            scope: The scope under which the DID is registered.
            name: The name of the DID.

        Returns:
            True if the DID was successfully removed, otherwise raises an exception.

        Raises:
            Exception: If the request fails or the server returns an error.
        """

        path = '/'.join([self.opendata_private_dids_base_url, quote_plus(scope), quote_plus(name)])
        url = build_url(self.get_opendata_host(public=False), path=path)

        r = self._send_request(url, type_='DEL')

        if r.status_code == codes.no_content:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def update_opendata_did(
            self,
            *,
            scope: str,
            name: str,
            state: Optional["OPENDATA_DID_STATE_LITERAL"] = None,
            meta: Optional[dict] = None,
            doi: Optional[str] = None,
    ) -> bool:
        """
        Update an existing Opendata DID in the Opendata catalog.

        Parameters:
            scope: The scope under which the DID is registered.
            name: The name of the DID.
            state: The new state to set for the DID.
            meta: Metadata to update for the DID. Must be a valid JSON object.
            doi: DOI to associate with the DID. Must be a valid DOI string (e.g., "10.1234/foo.bar").

        Returns:
            True if the update was successful.

        Raises:
            ValueError: If none of 'meta', 'state', or 'doi' are provided.
            Exception: If the request fails or the server returns an error.
        """

        path = '/'.join([self.opendata_private_dids_base_url, quote_plus(scope), quote_plus(name)])
        url = build_url(self.get_opendata_host(public=False), path=path)

        if not any([meta, state, doi]):
            raise ValueError("Either 'meta', 'state', or 'doi' must be provided.")

        data: dict[str, Any] = {}

        if meta is not None:
            data['meta'] = meta

        if state is not None:
            data['state'] = state

        if doi is not None:
            data['doi'] = doi

        r = self._send_request(url, type_='PUT', data=render_json(**data))

        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def get_opendata_did(
            self,
            *,
            scope: str,
            name: str,
            include_files: bool = False,
            include_metadata: bool = False,
            include_doi: bool = True,
            public: bool = False,
    ) -> dict[str, Any]:
        """
        Retrieve information about an OpenData DID (Data Identifier).

        Parameters:
            scope: The scope under which the DID is registered.
            name: The name of the DID.
            include_files: If True, include a list of associated files. Defaults to False.
            include_metadata: If True, include extended metadata. Defaults to False.
            include_doi: If True, include DOI (Digital Object Identifier) information. Defaults to True.
            public: If True, only return data if the DID is publicly accessible. Defaults to False.

        Returns:
            A dictionary containing metadata about the specified DID.
            May include file list, extended metadata, and DOI details depending on the parameters.
        """

        base_url = self.opendata_public_dids_base_url if public else self.opendata_private_dids_base_url
        path = '/'.join([base_url, quote_plus(scope), quote_plus(name)])
        url = build_url(self.get_opendata_host(public=public), path=path)

        r = self._send_request(url, type_='GET', params={
            'files': 1 if include_files else 0,
            'meta': 1 if include_metadata else 0,
            'doi': 1 if include_doi else 0,
        })

        if r.status_code == codes.ok:
            return json.loads(r.content.decode('utf-8'))
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
