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
from rucio.common.constants import HTTPMethod
from rucio.common.utils import build_url, render_json

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping


class LockClient(BaseClient):

    """Lock client class for working with rucio locks"""

    LOCKS_BASEURL = 'locks'

    def get_dataset_locks(
            self,
            scope: str,
            name: str
    ) -> "Iterator[dict[str, Any]]":
        """
        Get a dataset locks of the specified dataset.

        Parameters
        ----------
        scope :
            The scope of the DID of the locks to list.
        name :
            The name of the DID of the locks to list.

        """

        path = '/'.join([self.LOCKS_BASEURL, quote_plus(scope), quote_plus(name)])
        url = build_url(choice(self.list_hosts), path=path, params={'did_type': 'dataset'})

        result = self._send_request(url, method=HTTPMethod.GET)
        if result.status_code == codes.ok:   # pylint: disable-msg=E1101
            locks = self._load_json_data(result)
            return locks
        else:
            exc_cls, exc_msg = self._get_exception(headers=result.headers,
                                                   status_code=result.status_code)
            raise exc_cls(exc_msg)

    def get_locks_for_dids(
            self,
            dids: list["Mapping[str, Any]"],
            **filter_args: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """
        Get list of locks for for all the files found, recursively, in the listed datasets or containers.

        Parameters
        ----------
        dids :
            list of dictionaries {"scope":..., "name":..., "type":...}
            type can be either "dataset" or "container"
            type is optional, but if specified, improves the query performance

        Returns
        -------

            list of dictionaries with lock info
        """

        # convert DID list to list of dictionaries
        if not all(did.get("type", "dataset") in ("dataset", "container") for did in dids):
            raise ValueError("DID type can be either 'container' or 'dataset'")

        path = '/'.join([self.LOCKS_BASEURL, "bulk_locks_for_dids"])
        url = build_url(choice(self.list_hosts), path=path)

        result = self._send_request(url, method=HTTPMethod.POST, data=render_json(dids=dids))
        if result.status_code == codes.ok:   # pylint: disable-msg=E1101
            out = []
            for lock in self._load_json_data(result):
                filter_ok = (not filter_args) or all(lock.get(name) == value for name, value in filter_args.items())
                if filter_ok:
                    out.append(lock)
            return out
        else:
            exc_cls, exc_msg = self._get_exception(headers=result.headers,
                                                   status_code=result.status_code)
            raise exc_cls(exc_msg)

    def get_dataset_locks_by_rse(self, rse: str) -> "Iterator[dict[str, Any]]":
        """
        Get all dataset locks of the specified rse.

        Parameters
        ----------
        rse :
            The rse of the locks to list
        """

        path = '/'.join([self.LOCKS_BASEURL, rse])
        url = build_url(choice(self.list_hosts), path=path, params={'did_type': 'dataset'})

        result = self._send_request(url, method=HTTPMethod.GET)
        if result.status_code == codes.ok:   # pylint: disable-msg=E1101
            locks = self._load_json_data(result)
            return locks
        else:
            exc_cls, exc_msg = self._get_exception(headers=result.headers,
                                                   status_code=result.status_code)

            raise exc_cls(exc_msg)
