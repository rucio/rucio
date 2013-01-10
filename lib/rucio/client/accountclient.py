# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013

from json import dumps, loads
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.common.utils import build_url


class AccountClient(BaseClient):

    """Account client class for working with rucio accounts"""

    BASEURL = 'accounts'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None):
        super(AccountClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout)

    def add_account(self, account_name, account_type):
        """
        Sends the request to create a new account.

        :param account_name: the name of the account.
        :return: True if account was created successfully else False.
        :raises Duplicate: if account already exists.
        """

        data = dumps({'account_type': account_type})
        path = '/'.join([self.BASEURL, account_name])
        url = build_url(self.host, path=path)

        r = self._send_request(url, type='POST', data=data)

        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def delete_account(self, account_name):
        """
        Sends the request to disable an account.

        :param account_name: the name of the account.
        :return: True is account was disabled successfully. False otherwise.
        :raises AccountNotFound: if account doesn't exist.
        """

        path = '/'.join([self.BASEURL, account_name])
        url = build_url(self.host, path=path)

        r = self._send_request(url, type='DEL')

        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def get_account(self, account_name):
        """
        Sends the request to get information about a given account.

        :param account_name: the name of the account.
        :return: a list of attributes for the account. None if failure.
        :raises AccountNotFound: if account doesn't exist.
        """

        path = '/'.join([self.BASEURL, account_name])
        url = build_url(self.host, path=path)

        r = self._send_request(url)
        if r.status_code == codes.ok:
            acc = loads(r.text)
            return acc
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def list_accounts(self):
        """
        Sends the request to list all rucio accounts.

        :return: a list containing account info dictionary for all rucio accounts.
        :raises AccountNotFound: if account doesn't exist.
        """
        path = '/'.join([self.BASEURL, ''])
        url = build_url(self.host, path=path)

        r = self._send_request(url)

        if r.status_code == codes.ok:
            if 'content-type' in r.headers and r.headers['content-type'] == 'application/x-json-stream':
                for line in r.iter_lines():
                    if line:
                        yield loads(line)
            elif 'content-type' in r.headers and r.headers['content-type'] == 'application/json':
                yield loads(r.text)
            else:  # Exception ?
                yield r.text
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def whoami(self):
        """
        Get information about account whose token is used

        :return: a list of attributes for the account. None if failure.
        :raises AccountNotFound: if account doesn't exist.
        """
        return self.get_account('whoami')

    def add_identity(self, account_name, identity, authtype, default=False, email=None):
        """
        Adds a membership association between identity and account.

        :param account_name: The account name.
        :param identity: The identity key name. For example x509 DN, or a username.
        :param authtype: The type of the authentication (x509, gss, userpass).
        :param default: If True, the account should be used by default with the provided identity.
        :param email: The Email address associated with the identity.
        """

        data = dumps({'identity': identity, 'authtype': authtype, 'default': default, 'email': email})
        path = '/'.join([self.BASEURL, account_name, 'identities'])

        url = build_url(self.host, path=path)

        r = self._send_request(url, type='POST', data=data)

        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def list_identities(self, account_name):
        """
        List all identities on an account.

        :param account_name: The account name.
        """
        path = '/'.join([self.BASEURL, account_name, 'identities'])
        url = build_url(self.host, path=path)
        r = self._send_request(url)
        if r.status_code == codes.ok:
            identities = loads(r.text)
            return identities
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)
