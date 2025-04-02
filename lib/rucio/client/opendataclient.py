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

from typing import TYPE_CHECKING, Any
from urllib.parse import quote_plus

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.utils import build_url, render_json

if TYPE_CHECKING:
    from collections.abc import Iterator


class OpenDataClient(BaseClient):
    """DataIdentifier client class for working with data identifiers"""
    opendata_base_url = "opendata"

    def list_opendata_dids(
            self,
            *,
            state: str = None,
    ) -> "Iterator[dict[str, Any]]":
        path = '/'.join([self.opendata_base_url])

        # TODO: filter on state
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type_='GET')

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
        path = '/'.join([self.opendata_base_url, quote_plus(scope), quote_plus(name)])
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
        path = '/'.join([self.opendata_base_url, quote_plus(scope), quote_plus(name)])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type_='DELETE')

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
            opendata_json: dict,
    ) -> bool:
        path = '/'.join([self.opendata_base_url, quote_plus(scope), quote_plus(name)])
        url = build_url(choice(self.list_hosts), path=path)

        data: dict[str, Any] = {}

        if opendata_json:
            data['metadata'] = opendata_json

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
    ) -> dict[str, Any]:
        path = '/'.join([self.opendata_base_url, quote_plus(scope), quote_plus(name)])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type_='GET')

        if r.status_code == codes.ok:
            result = self._load_json_data(r)
            return result
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
