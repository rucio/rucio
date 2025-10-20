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

from json import dumps
from typing import TYPE_CHECKING, Any, Literal, Optional

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.constants import HTTPMethod
from rucio.common.utils import build_url

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping


class DiracClient(BaseClient):
    """
    Client for the DIRAC integration layer.

    This client wraps the REST calls used by the ``RucioFileCatalog`` plugin in DIRAC.
    Only `add_files` is currently provided and it behaves like any other ``BaseClient``
    method by handling authentication tokens and host selection automatically.
    """

    DIRAC_BASEURL = 'dirac'

    def add_files(
            self,
            lfns: "Iterable[Mapping[str, Any]]",
            ignore_availability: bool = False,
            parents_metadata: Optional["Mapping[str, Mapping[str, Any]]"] = None
    ) -> Literal[True]:
        """
        Register files and create missing parent structures.

        For each entry in ``lfns`` the method:

        * Creates the file and its replica on the specified RSE.
        * If the containing dataset does not exist, it is created with a replication
          rule using the RSE expression ``ANY=true``. This places the dataset on any
          RSE advertising the ``ANY`` attribute.
        * Creates all ancestor containers when needed.
        * Attaches metadata from ``parents_metadata`` to those parents.

        Parameters
        ----------
        lfns
            Iterable of dictionaries describing the files. Each dictionary must contain:

            * **``lfn``**  full logical file name with scope
            * **``rse``**  destination RSE name
            * **``bytes``**  file size in bytes
            * **``adler32``**  Adler‑32 checksum

            Optional keys include ``guid`` ``pfn`` and ``meta``.

        ignore_availability
            When ``True``, the availability status of RSEs is ignored and blocked RSEs are
            still accepted. Defaults to ``False`` which rejects blocked RSEs.
        parents_metadata
            Mapping of parent logical path names to metadata {'lpn': {key : value}}.
            Entries are only applied when new datasets or containers are created.
            Defaults to None.

        Returns
        -------
        Literal[True]
            When the server confirms the creation.

        Raises
        ------
        RucioException
            Raised when the HTTP request is not successful.

        Examples
        --------
        ??? Example

            Register a file using the DIRAC naming style. Dirac's scope extraction is
            required to be set for this to work:

            ```python
            >>> from rucio.client.diracclient import DiracClient
            >>> from rucio.common.utils import generate_uuid

            >>> dc = DiracClient()
            >>> lfn = f"/belle/mock/cont_{generate_uuid()}/dataset_{generate_uuid()}/file_{generate_uuid()}"
            >>> files = [{
            ...     "lfn": lfn,
            ...     "rse": "XRD1",
            ...     "bytes": 1,
            ...     "adler32": "0cc737eb",
            ...     'guid': generate_uuid()
            ... }]

            >>> dc.add_files(files)
            True
            ```
        """
        path = '/'.join([self.DIRAC_BASEURL, 'addfiles'])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(
            url,
            method=HTTPMethod.POST,
            data=dumps({'lfns': lfns, 'ignore_availability': ignore_availability, 'parents_metadata': parents_metadata})
        )

        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
