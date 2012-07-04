# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012

from json import loads
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.common.utils import build_url


class ScopeClient(BaseClient):

    """Scope client class for working with rucio scopes"""

    def __init__(self, host, port=None, account=None, use_ssl=True, ca_cert=None, auth_type=None, creds=None):
        super(ScopeClient, self).__init__(host, port, account, use_ssl, ca_cert, auth_type, creds)

    def add_scope(self, accountName, scopeName):
        """
        Sends the request to add a new scope.

        :param accountName: the name of the account to the scope to.
        :param scopeName: the name of the new scope.
        :return: True if scope was created successfully.
        :raises Duplicate: if scope already exists.
        :raises AccountNotFound: if account doesn't exist.
        """

        path = 'scope/' + accountName + '/' + scopeName
        url = build_url(self.host, path=path, use_ssl=self.use_ssl)

        r = self._send_request(url, type='PUT')

        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def list_scopes_for_account(self, accountName):
        """
        Sends the request to list all scopes for a rucio account.

        :param accountName: the rucio account to list scopes for.
        :return: a list containing the names of all scopes for a rucio account.
        :raises AccountNotFound: if account doesn't exist.
        :raises ScopeNotFound: if no scopes exist for account.
        """

        path = 'scope/' + accountName
        url = build_url(self.host, path=path, use_ssl=self.use_ssl)

        r = self._send_request(url)
        if r.status_code == codes.ok:
            scopes = loads(r.text)
            return scopes
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)
