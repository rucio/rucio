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

from json import loads
from typing import Any

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.common.constants import HTTPMethod
from rucio.common.utils import build_url


class PingClient(BaseClient):
    """Ping client class"""

    def ping(self) -> dict[str, Any]:
        """
        This is a light‑weight “are you alive?” call (*ping* request) to the configured Rucio.

        A quick way to verify (without any required authentication):

        - Network connectivity between the client and the server.

        - Whether the server process is running and able to respond.

        - The server’s build / version.

        Returns
        -------
        dict[str, Any]
            A dictionary with a single key: the server version (e.g. {'version': '37.0.0'})

        Raises
        ------
        rucio.common.exception.RucioException
            If the HTTP status code is not *200 OK*.

        Examples
        --------
        ??? Example

            Basic connectivity check:

            ```python
            from rucio.client.pingclient import PingClient
            ping_client = PingClient()

            try:
                info = ping_client.ping()
                print(f"Connected to Rucio {info['version']}")
            except Exception as err:
                print(f"Ping failed: {err}")
            ```
        """

        headers = None
        path = 'ping'
        url = build_url(self.host, path=path)
        r = self._send_request(url, headers=headers, method=HTTPMethod.GET)

        if r.status_code == codes.ok:
            server_info = loads(r.text)
            return server_info

        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)
