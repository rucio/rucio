# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Vincent Garonne <vgaronne@gmail.com>, 2012-2018
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012-2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013-2015
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2016
# - Martin Barisits <martin.barisits@cern.ch>, 2014-2018
#
# PY3K COMPATIBLE

"""
Client class for callers of the Rucio system
"""

from rucio.client.accountclient import AccountClient
from rucio.client.accountlimitclient import AccountLimitClient
from rucio.client.didclient import DIDClient
from rucio.client.exportclient import ExportClient
from rucio.client.importclient import ImportClient
from rucio.client.lockclient import LockClient
from rucio.client.metaclient import MetaClient
from rucio.client.pingclient import PingClient
from rucio.client.replicaclient import ReplicaClient
from rucio.client.requestclient import RequestClient
from rucio.client.rseclient import RSEClient
from rucio.client.ruleclient import RuleClient
from rucio.client.scopeclient import ScopeClient
from rucio.client.subscriptionclient import SubscriptionClient
from rucio.client.configclient import ConfigClient
from rucio.client.touchclient import TouchClient


class Client(AccountClient, AccountLimitClient, MetaClient, PingClient, ReplicaClient, RequestClient, RSEClient, ScopeClient, DIDClient, RuleClient, SubscriptionClient, LockClient, ConfigClient, TouchClient, ImportClient, ExportClient):

    """Main client class for accessing Rucio resources. Handles the authentication."""

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=600, user_agent='rucio-clients'):
        """
        Constructor for the Rucio main client class.

        :param rucio_host: the host of the rucio system.
        :param auth_host: the host of the rucio authentication server.
        :param account: the rucio account that should be used to interact with the rucio system.
        :param ca_cert: the certificate to verify the server.
        :param auth_type: the type of authentication to use (e.g. userpass, x509 ...)
        :param creds: credentials needed for authentication.
        :param timeout: Float describes the timeout of the request (in seconds).
        """
        super(Client, self).__init__(rucio_host=rucio_host, auth_host=auth_host, account=account, ca_cert=ca_cert, auth_type=auth_type, creds=creds, timeout=timeout, user_agent=user_agent)
