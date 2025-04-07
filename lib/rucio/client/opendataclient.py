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
from rucio.common.utils import build_url, render_json

if TYPE_CHECKING:
    from collections.abc import Iterator


class OpenDataClient(BaseClient):
    opendata_public_base_url = "opendata"
    opendata_private_base_url = "opendata-private"

    def list_opendata_dids(
            self,
            *,
            state: Optional[str] = None,
            public: bool = False,
    ) -> "Iterator[dict[str, Any]]":
        base_url = self.opendata_public_base_url if public else self.opendata_private_base_url
        path = '/'.join([base_url])

        params = {}

        if state is not None:
            state = state.upper().strip()
            params['state'] = state

        if state is not None and public:
            raise ValueError('state and public cannot be provided at the same time.')

        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type_='GET', params=params)
        if r.status_code == codes.ok:
            result = self._load_json_data(r)
            return result
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def add_opendata_did(
            self,
            *,
            scope: str,
            name: str,
    ) -> bool:
        path = '/'.join([self.opendata_private_base_url, quote_plus(scope), quote_plus(name)])
        url = build_url(choice(self.list_hosts), path=path)

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
        path = '/'.join([self.opendata_private_base_url, quote_plus(scope), quote_plus(name)])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type_='DEL')

        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def update_opendata_did(
            self,
            *,
            scope: str,
            name: str,
            opendata_json: Optional[dict] = None,
            state: Optional[str] = None,
    ) -> bool:
        path = '/'.join([self.opendata_private_base_url, quote_plus(scope), quote_plus(name)])
        url = build_url(choice(self.list_hosts), path=path)

        if state is not None:
            state = state.upper().strip()
            check_valid_opendata_did_state(state)
        if opendata_json is None and state is None:
            raise ValueError('Either opendata_json or state must be provided to update the OpenData DID.')
        if opendata_json is not None and state is not None:
            raise ValueError('Both opendata_json and state cannot be provided at the same time.')

        data: dict[str, Any] = {}

        if opendata_json is not None:
            data['opendata_json'] = opendata_json

        if state:
            data['state'] = state

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
            public: bool = False,
    ) -> dict[str, Any]:
        base_url = self.opendata_public_base_url if public else self.opendata_private_base_url
        path = '/'.join([base_url, quote_plus(scope), quote_plus(name)])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type_='GET')

        if r.status_code == codes.ok:
            return json.loads(next(self._load_json_data(r)))
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
