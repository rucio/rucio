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

"""
Client class for callers of the Rucio system
"""

from rucio.client.accountclient import AccountClient
from rucio.client.accountlimitclient import AccountLimitClient
from rucio.client.configclient import ConfigClient
from rucio.client.credentialclient import CredentialClient
from rucio.client.didclient import DIDClient
from rucio.client.diracclient import DiracClient
from rucio.client.exportclient import ExportClient
from rucio.client.importclient import ImportClient
from rucio.client.lifetimeclient import LifetimeClient
from rucio.client.lockclient import LockClient
from rucio.client.metaconventionsclient import MetaConventionClient
from rucio.client.opendataclient import OpenDataClient
from rucio.client.pingclient import PingClient
from rucio.client.replicaclient import ReplicaClient
from rucio.client.requestclient import RequestClient
from rucio.client.rseclient import RSEClient
from rucio.client.ruleclient import RuleClient
from rucio.client.scopeclient import ScopeClient
from rucio.client.subscriptionclient import SubscriptionClient
from rucio.client.touchclient import TouchClient


class Client(AccountClient,
             AccountLimitClient,
             MetaConventionClient,
             PingClient,
             ReplicaClient,
             RequestClient,
             RSEClient,
             ScopeClient,
             DIDClient,
             OpenDataClient,
             RuleClient,
             SubscriptionClient,
             LockClient,
             ConfigClient,
             TouchClient,
             ImportClient,
             ExportClient,
             CredentialClient,
             DiracClient,
             LifetimeClient):

    """
    Main client class for accessing Rucio resources. Handles the authentication.

    Note:
    ------
        Used to access all client methods. Each entity client *can* be used to access methods, but using the main client class is recommended for ease of use.


    Example:
    -------
        from rucio.client import Client

        client = Client()  # authenticate with config or environ settings
        client.add_replication_rule(...)

        client = Client(
            rucio_host = "my_host",
            auth_host = "my_auth_host",
            account = "jdoe12345",
            auth_type = "userpass",
            creds = {
                "username": "jdoe12345",
                "password": "******",
            }
        ) # authenticate with kwargs
        client.list_replicas(...)


        # For using the upload and download clients

        from rucio.client import Client
        from rucio.client.uploadclient import UploadClient
        from rucio.client.downloadclient import DownloadClient

        client = Client(...) # Initialize a client using your preferred method

        upload_client = UploadClient(client) # Pass forward the initialized client
        upload_client.upload(items=...)

        download_client = DownloadClient(client)
        download_client.download_dids(items=...)
    """

    def __init__(self, **args):
        """
        Constructor for the Rucio main client class.

        Parameters
        ----------
        rucio_host :
            The host of the rucio system.
        auth_host :
            The host of the rucio authentication server.
        account :
            The rucio account that should be used to interact with the rucio system.
        ca_cert :
            The certificate to verify the server.
        auth_type :
            The type of authentication to use (e.g. userpass, x509 ...).
        creds :
            Credentials needed for authentication.
        timeout :
            Describes the timeout of the request (in seconds).
        vo :
            The vo that the client will interact with.
        logger :
            Logger instance to use.
        """
        super(Client, self).__init__(**args)
