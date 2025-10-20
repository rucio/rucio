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

from typing import Any

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.constants import HTTPMethod
from rucio.common.utils import build_url, parse_response


class ExportClient(BaseClient):
    """RSE client class for exporting data from Rucio"""

    EXPORT_BASEURL = 'export'

    def export_data(self, distance: bool = True) -> dict[str, Any]:
        """
        Retrieve a detailed snapshot of the current RSE configuration.

        The exported information includes all registered RSEs with their settings and
        attributes. When `distance` is `True`, the RSE distance matrix is included as well.
        The snapshot is intended for use cases such as configuration back‑ups, migrations
        between instances, and monitoring (e.g. generating monitoring dashboards).

        Parameters
        ----------
        distance
            If *True* (default), the server also returns the inter‑RSE distance matrix in
            the payload.

            _**Note:**_ Omitting the distance information can significantly reduce the
            response size and improve transfer times.

        Returns
        -------
        dict[str, Any]
            A nested dictionary that mirrors the server‑side JSON structure.
            The top‑level keys are:

            **`rses`**:
                Per‑RSE settings (name, deterministic flag, QoS class, supported protocol, etc.).

            **`distances`**:
                Pairwise RSE‑to‑RSE distance values (only present when `distance=True`).

        Raises
        ------
        RucioException
            Raised if the HTTP status code is not *200 OK*.

        Examples
        --------
        ??? Example

            Retrieve a full export of all configured RSEs, including their attributes and
            inter-RSE distances:

            ```python
            from rucio.client.exportclient import ExportClient

            export_client = ExportClient()

            try:
                rse_data = export_client.export_data()  # distance=True by default
                print(f"Full RSE properties: {rse_data}")
            except Exception as err:
                print(f"Action failed: {err}")
            ```
        """
        payload = {'distance': distance}
        path = '/'.join([self.EXPORT_BASEURL])
        url = build_url(choice(self.list_hosts), path=path, params=payload)

        r = self._send_request(url, method=HTTPMethod.GET)
        if r.status_code == codes.ok:
            return parse_response(r.text)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
