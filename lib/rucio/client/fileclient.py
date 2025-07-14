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
from urllib.parse import quote_plus

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.utils import build_url


class FileClient(BaseClient):
    """
    Client for retrieving replica information for file DIDs.

    This lightweight client exposes a single helper to query the Rucio
    catalogue for all physical replicas of a given file.  It is typically
    used by command line tools and scripts which need to inspect where a file
    is currently stored.
    """

    BASEURL = 'files'

    def list_file_replicas(self, scope: str, lfn: str) -> list[dict[str, Any]]:
        """
        Return all known replica locations of a file DID.

        The method issues a GET request to the ``/files/<scope>/<name>/rses``
        endpoint of the Rucio REST API. The server replies with a JSON list
        describing each RSE where the file is currently present. Each entry in
        the returned list contains the RSE name and may include additional
        attributes such as the physical file name (PFN), file size, checksum
        and replica state.

        _**Note:**_ This method is currently not available.

        Parameters
        ----------
        scope
            The scope part of the file DID (e.g. ``"user.alice"``).
        lfn
            The logical file name of the DID.

        Returns
        -------
        list[dict[str, Any]]
            A list of dictionaries describing each replica. Each entry at least
            contains the ``rse`` key and may include additional replica attributes
            provided by the server.

        Raises
        ------
        RucioException
            If the HTTP response status is not ``200 OK``.

        Examples
        --------
        ??? Example

            Print all replica locations for ``mock:file_b6222d9fe8e5434e84bfc002845348acanother.zip``:

            ```python
            >>> from rucio.client.fileclient import FileClient

            >>> fc = FileClient()
            >>> fc.list_file_replicas('mock', 'file_b6222d9fe8e5434e84bfc002845348acanother.zip')
            [{'rse': 'CERN-PROD', ..}, {'rse': 'BNL-OSG2', ..}, ...]
            ```
        """
        path = '/'.join([self.BASEURL, quote_plus(scope), quote_plus(lfn), 'rses'])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type_='GET')

        if r.status_code == codes.ok:
            rses = loads(r.text)
            return rses
        else:
            print(r.status_code)
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
