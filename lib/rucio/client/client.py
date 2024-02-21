# -*- coding: utf-8 -*-
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

    """Main client class for accessing Rucio resources. Handles the authentication."""

    def __init__(self, **args):
        """
        Constructor for the Rucio main client class.

        :param rucio_host: the host of the rucio system.
        :param auth_host: the host of the rucio authentication server.
        :param account: the rucio account that should be used to interact with the rucio system.
        :param ca_cert: the certificate to verify the server.
        :param auth_type: the type of authentication to use (e.g. userpass, x509 ...)
        :param creds: credentials needed for authentication.
        :param timeout: Float describes the timeout of the request (in seconds).
        :param vo: The vo that the client will interact with.
        :param logger: Logger instance to use (optional)
        """
        super(Client, self).__init__(**args)
