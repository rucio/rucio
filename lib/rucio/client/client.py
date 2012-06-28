# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012


"""
Client class for callers of the Rucio system
"""

from rucio.client.accountclient import AccountClient
from rucio.client.locationclient import LocationClient
from rucio.client.scopeclient import ScopeClient


class Client(AccountClient, LocationClient, ScopeClient):

    """Main client class for accessing Rucio resources. Handles the authentication."""

    def __init__(self, host, port=None, account=None, use_ssl=True, ca_cert=None, auth_type=None, creds=None):
        """
        Constructor for the Rucio main client class.

        :param host: the hostname or ip address of the rucio system.
        :param port: the corresponding port.
        :param account: the rucio account that should be used to interact with the rucio system.
        :param use_ssl: flag indicating if a secure communication channel should be used.
        :param ca_cert: the certificate to verify the server.
        :param auth_type: the type of authentication to use (e.g. userpass, x509 ...)
        :param creds: credentials needed for authentication.
        """
        super(Client, self).__init__(host, port, account, use_ssl, ca_cert, auth_type, creds)
