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

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.constants import HTTPMethod
from rucio.common.utils import build_url


class CredentialClient(BaseClient):
    """
    Client helper to request signed URLs from a Rucio server.

    A ``CredentialClient`` used to obtain temporary signed URLs from the server.
    Those URLs allow direct access to objects on a storage service (currently
    Google Cloud Storage, Amazon S3 or OpenStack Swift) without further authentication.
    The signature embeds the permitted operation and its validity period, after which
    the link becomes unusable.
    """

    CREDENTIAL_BASEURL = 'credentials'

    def get_signed_url(
            self,
            rse: str,
            service: str,
            operation: str,
            url: str,
            lifetime: int = 3600
    ) -> str:
        """
        Request a pre-signed URL for a storage object operation.

        This method contacts the Rucio server and asks it to cryptographically
        sign ``url`` so that it can be used for a single operation on the
        specified RSE. The signed link can then be handed to external tools or
        services to perform the action without additional authentication.

        Parameters
        ----------
        rse
            The name of the RSE to which the URL refers.
        service
            Storage service identifier. Must be one of ``"gcs"``, ``"s3"`` or ``"swift"``.
        operation
            Allowed operation for the signed URL: ``"read"``, ``"write"`` or ``"delete"``.
        url
            The full URL that should be authorised.
        lifetime
            Time in seconds for which the signature remains valid.  Defaults to ``3600`` (one hour).

        Returns
        -------
        str
            The signed URL that can be used until the lifetime expires.

        Raises
        ------
        RucioException
            If the server returns a status code other than ``200 OK``.

        Examples
        --------
        ??? Example

            Request a download link from the *MOCK* RSE for a file stored
            on Google Cloud Storage valid for ten minutes:

            ```python
            >>> from rucio.client.credentialclient import CredentialClient

            >>> cc = CredentialClient()
            >>> cc.get_signed_url(
            ...     rse="MOCK",
            ...     service="s3",
            ...     operation="read",
            ...     url="https://storage.googleapis.com/mybucket/data/file1.txt",
            ...     lifetime=600,
            ... )
            "https://storage.googleapis.com/mybucket/data/file1.txt?GoogleAccessId=rucio-test@rucio-test.iam.gserviceaccount.com&Expires=1752535247&Signature=oevpuzk4icQhjw3mk2wq..."
            ```
        """
        path = '/'.join([self.CREDENTIAL_BASEURL, 'signurl'])
        params = {
            'lifetime': lifetime,
            'rse': rse,
            'svc': service,
            'op': operation,
            'url': url
        }
        rurl = build_url(choice(self.list_hosts), path=path, params=params)
        r = self._send_request(rurl, method=HTTPMethod.GET)

        if r.status_code == codes.ok:
            return r.text

        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)
