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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2012-2018
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014
# - Ralph Vigne <ralph.vigne@cern.ch>, 2015
# - Brian Bockelman <bbockelm@cse.unl.edu>, 2018
# - asket <asket.agarwal96@gmail.com>, 2018
# - Martin Barisits <martin.barisits@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2021

from json import dumps, loads

from requests.status_codes import codes
from six.moves.urllib.parse import quote_plus

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url


class MetaClient(BaseClient):

    """Meta client class for working with data identifier attributes"""

    META_BASEURL = 'meta'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=600, user_agent='rucio-clients', vo=None):
        super(MetaClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout, user_agent, vo=vo)

    def add_key(self, key, key_type, value_type=None, value_regexp=None):
        """
        Sends the request to add a new key.

        :param key: the name for the new key.
        :param key_type: the type of the key: all(container, dataset, file), collection(dataset or container), file, derived(compute from file for collection).
        :param value_type: the type of the value, if defined.
        :param value_regexp: the regular expression that values should match, if defined.

        :return: True if key was created successfully.
        :raises Duplicate: if key already exists.
        """

        path = '/'.join([self.META_BASEURL, quote_plus(key)])
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'value_type': value_type and str(value_type),
                      'value_regexp': value_regexp,
                      'key_type': key_type})

        r = self._send_request(url, type='POST', data=data)

        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_keys(self):
        """
        Sends the request to list all keys.

        :return: a list containing the names of all keys.
        """
        path = self.META_BASEURL + '/'
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url)
        if r.status_code == codes.ok:
            keys = loads(r.text)
            return keys
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_values(self, key):
        """
        Sends the request to list all values for a key.

        :return: a list containing the names of all values for a key.
        """
        path = '/'.join([self.META_BASEURL, quote_plus(key)]) + '/'
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url)
        if r.status_code == codes.ok:
            values = loads(r.text)
            return values
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def add_value(self, key, value):
        """
        Sends the request to add a value to a key.

        :param key: the name for key.
        :param value: the value.

        :return: True if value was created successfully.
        :raises Duplicate: if valid already exists.
        """

        path = '/'.join([self.META_BASEURL, quote_plus(key)]) + '/'
        data = dumps({'value': value})
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type='POST', data=data)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def del_value(self, key, value):
        """
        Delete a value for a key.

        :param key: the name for key.
        :param value: the value.
        """
        pass

    def del_key(self, key):
        """
        Delete an allowed key.

        :param key: the name for key.
        """
        pass

    def update_key(self, key, type=None, regepx=None):
        """
        Update a key.

        :param key: the name for key.
        :param type: the type of the value, if defined.
        :param regexp: the regular expression that values should match, if defined.
        """
        pass
