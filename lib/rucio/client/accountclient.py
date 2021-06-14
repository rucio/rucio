# -*- coding: utf-8 -*-
# Copyright 2012-2021 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2012-2013
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2012-2013
# - Yun-Pin Sun <winter0128@gmail.com>, 2013
# - Martin Barisits <martin.barisits@cern.ch>, 2013-2020
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2019
# - Cheng-Hsi Chao <cheng-hsi.chao@cern.ch>, 2014
# - Ralph Vigne <ralph.vigne@cern.ch>, 2015
# - Joaquín Bogado <jbogado@linti.unlp.edu.ar>, 2015
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Eric Vaandering <ewv@fnal.gov>, 2020
# - Brandon White <bjwhite@fnal.gov>, 2020
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020

from json import dumps

from requests.status_codes import codes
from six.moves.urllib.parse import quote_plus

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url


class AccountClient(BaseClient):

    """Account client class for working with rucio accounts"""

    ACCOUNTS_BASEURL = 'accounts'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=600, user_agent='rucio-clients', vo=None):
        super(AccountClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout, user_agent, vo=vo)

    def add_account(self, account, type, email):
        """
        Sends the request to create a new account.

        :param account: the name of the account.
        :param type: The account type
        :param email: The Email address associated with the account.

        :return: True if account was created successfully else False.
        :raises Duplicate: if account already exists.
        """

        data = dumps({'type': type, 'email': email})
        path = '/'.join([self.ACCOUNTS_BASEURL, account])
        url = build_url(choice(self.list_hosts), path=path)

        res = self._send_request(url, type='POST', data=data)
        if res.status_code == codes.created:
            return True
        exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
        raise exc_cls(exc_msg)

    def delete_account(self, account):
        """
        Sends the request to disable an account.

        :param account: the name of the account.
        :return: True is account was disabled successfully. False otherwise.
        :raises AccountNotFound: if account doesn't exist.
        """

        path = '/'.join([self.ACCOUNTS_BASEURL, account])
        url = build_url(choice(self.list_hosts), path=path)

        res = self._send_request(url, type='DEL')

        if res.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
        raise exc_cls(exc_msg)

    def get_account(self, account):
        """
        Sends the request to get information about a given account.

        :param account: the name of the account.
        :return: a list of attributes for the account. None if failure.
        :raises AccountNotFound: if account doesn't exist.
        """

        path = '/'.join([self.ACCOUNTS_BASEURL, account])
        url = build_url(choice(self.list_hosts), path=path)

        res = self._send_request(url)
        if res.status_code == codes.ok:
            acc = self._load_json_data(res)
            return next(acc)
        exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
        raise exc_cls(exc_msg)

    def update_account(self, account, key, value):
        """ Update a property of an account.

        :param account: Name of the account.
        :param key: Account property like status.
        :param value: Property value.
        """
        data = dumps({key: value})
        path = '/'.join([self.ACCOUNTS_BASEURL, account])
        url = build_url(choice(self.list_hosts), path=path)

        res = self._send_request(url, type='PUT', data=data)

        if res.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def list_accounts(self, account_type=None, identity=None, filters=None):
        """
        Sends the request to list all rucio accounts.

        :param type: The account type
        :param identity: The identity key name. For example x509 DN, or a username.
        :param filters: A dictionnary key:account attribute to use for the filtering

        :return: a list containing account info dictionary for all rucio accounts.
        :raises AccountNotFound: if account doesn't exist.
        """
        path = '/'.join([self.ACCOUNTS_BASEURL])
        url = build_url(choice(self.list_hosts), path=path)
        params = {}
        if account_type:
            params['account_type'] = account_type
        if identity:
            params['identity'] = identity
        if filters:
            for key in filters:
                params[key] = filters[key]

        res = self._send_request(url, params=params)

        if res.status_code == codes.ok:
            accounts = self._load_json_data(res)
            return accounts
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def whoami(self):
        """
        Get information about account whose token is used

        :return: a list of attributes for the account. None if failure.
        :raises AccountNotFound: if account doesn't exist.
        """
        return self.get_account('whoami')

    def add_identity(self, account, identity, authtype, email, default=False, password=None):
        """
        Adds a membership association between identity and account.

        :param account: The account name.
        :param identity: The identity key name. For example x509 DN, or a username.
        :param authtype: The type of the authentication (x509, gss, userpass).
        :param default: If True, the account should be used by default with the provided identity.
        :param email: The Email address associated with the identity.
        :param password: Password if authtype is userpass.
        """

        data = dumps({'identity': identity, 'authtype': authtype, 'default': default, 'email': email, 'password': password})
        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'identities'])

        url = build_url(choice(self.list_hosts), path=path)

        res = self._send_request(url, type='POST', data=data)

        if res.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def del_identity(self, account, identity, authtype):
        """
        Delete an identity's membership association with an account.

        :param account: The account name.
        :param identity: The identity key name. For example x509 DN, or a username.
        :param authtype: The type of the authentication (x509, gss, userpass).
        :param default: If True, the account should be used by default with the provided identity.
        """

        data = dumps({'identity': identity, 'authtype': authtype})
        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'identities'])

        url = build_url(choice(self.list_hosts), path=path)

        res = self._send_request(url, type='DEL', data=data)

        if res.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def list_identities(self, account):
        """
        List all identities on an account.

        :param account: The account name.
        """
        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'identities'])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url)
        if res.status_code == codes.ok:
            identities = self._load_json_data(res)
            return identities
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def list_account_rules(self, account):
        """
        List the associated rules of an account.

        :param account: The account name.
        """

        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'rules'])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, type='GET')
        if res.status_code == codes.ok:
            return self._load_json_data(res)
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def get_account_limits(self, account, rse_expression, locality):
        """
        Return the correct account limits for the given locality.

        :param account:        The account name.
        :param rse_expression: Valid RSE expression
        :param locality:       The scope of the account limit. 'local' or 'global'.
        """

        if locality == 'local':
            return self.get_local_account_limit(account, rse_expression)
        elif locality == 'global':
            return self.get_global_account_limit(account, rse_expression)
        else:
            from rucio.common.exception import UnsupportedOperation
            raise UnsupportedOperation('The provided locality (%s) for the account limit was invalid' % locality)

    def get_global_account_limit(self, account, rse_expression):
        """
        List the account limit for the specific RSE expression.

        :param account:        The account name.
        :param rse_expression: The rse expression.
        """

        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'limits', 'global', quote_plus(rse_expression)])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, type='GET')
        if res.status_code == codes.ok:
            return next(self._load_json_data(res))
        exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
        raise exc_cls(exc_msg)

    def get_global_account_limits(self, account):
        """
        List all RSE expression limits of this account.

        :param account: The account name.
        """

        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'limits', 'global'])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, type='GET')
        if res.status_code == codes.ok:
            return next(self._load_json_data(res))
        exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
        raise exc_cls(exc_msg)

    def get_local_account_limits(self, account):
        """
        List the account rse limits of this account.

        :param account: The account name.
        """

        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'limits', 'local'])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, type='GET')
        if res.status_code == codes.ok:
            return next(self._load_json_data(res))
        exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
        raise exc_cls(exc_msg)

    def get_local_account_limit(self, account, rse):
        """
        List the account rse limits of this account for the specific rse.

        :param account: The account name.
        :param rse:     The rse name.
        """

        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'limits', 'local', rse])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, type='GET')
        if res.status_code == codes.ok:
            return next(self._load_json_data(res))
        exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
        raise exc_cls(exc_msg)

    def get_local_account_usage(self, account, rse=None):
        """
        List the account usage for one or all rses of this account.

        :param account: The account name.
        :param rse:     The rse name.
        """
        if rse:
            path = '/'.join([self.ACCOUNTS_BASEURL, account, 'usage', 'local', rse])
        else:
            path = '/'.join([self.ACCOUNTS_BASEURL, account, 'usage', 'local'])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, type='GET')
        if res.status_code == codes.ok:
            return self._load_json_data(res)
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def get_global_account_usage(self, account, rse_expression=None):
        """
        List the account usage for one or all RSE expressions of this account.

        :param account:        The account name.
        :param rse_expression: The rse expression.
        """
        if rse_expression:
            path = '/'.join([self.ACCOUNTS_BASEURL, account, 'usage', 'global', quote_plus(rse_expression)])
        else:
            path = '/'.join([self.ACCOUNTS_BASEURL, account, 'usage', 'global'])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, type='GET')
        if res.status_code == codes.ok:
            return self._load_json_data(res)
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def get_account_usage_history(self, account, rse):
        """
        List the account usage history of this account on rse.

        :param account: The account name.
        :param rse:     The rse name.
        """
        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'usage/history', rse])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, type='GET')
        if res.status_code == codes.ok:
            return next(self._load_json_data(res))
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def list_account_attributes(self, account):
        """
        List the attributes for an account.

        :param account: The account name.
        """
        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'attr/'])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, type='GET')
        if res.status_code == codes.ok:
            return self._load_json_data(res)
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def add_account_attribute(self, account, key, value):
        """
        Adds an attribute to an account.

        :param account: The account name.
        :param key: The attribute key.
        :param value: The attribute value.
        """

        data = dumps({'key': key, 'value': value})
        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'attr', key])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, type='POST', data=data)
        if res.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)

    def delete_account_attribute(self, account, key):
        """
        Delete an attribute for an account.

        :param account: The account name.
        :param key: The attribute key.
        """

        path = '/'.join([self.ACCOUNTS_BASEURL, account, 'attr', key])
        url = build_url(choice(self.list_hosts), path=path)
        res = self._send_request(url, type='DEL', data=None)
        if res.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=res.headers, status_code=res.status_code, data=res.content)
            raise exc_cls(exc_msg)
