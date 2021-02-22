# Copyright 2014-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014
# - Vincent Garonne <vgaronne@gmail.com>, 2014-2018
# - Ralph Vigne <ralph.vigne@cern.ch>, 2015
# - Martin Barisits <martin.barisits@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Radu Carpa <radu.carpa@cern.ch>, 2021
#
# PY3K COMPATIBLE

from json import dumps

from requests.status_codes import codes

try:
    from exceptions import ValueError
except ImportError:
    pass

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url


class ConfigClient(BaseClient):

    """Client class for working with the configuration"""

    CONFIG_BASEURL = 'config'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=600, user_agent='rucio-clients', vo=None):
        super(ConfigClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout, user_agent, vo=vo)

    def get_config(self, section=None, option=None):
        """
        Sends the request to get the matching configuration.

        :param section: the optional name of the section.
        :param option: the optional option within the section.
        :return: dictionary containing the configuration.
        """

        if section is None and option is not None:
            raise ValueError('--section not specified')

        path = self.CONFIG_BASEURL
        if section is not None and option is None:
            path += '/' + section
        elif section is not None and option is not None:
            path += '/'.join(['', section, option])

        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return r.json()
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def set_config_option(self, section, option, value, use_body_for_params=True):
        """
        Sends the request to create or set an option within a section. Missing sections will be created.

        :param section: the name of the section.
        :param option: the name of the option.
        :param value: the value to set on the config option
        :param use_body_for_params: send parameters in a json-encoded request body instead of url-encoded
        TODO: remove this parameter
        The format of the /config endpoint was recently changed. We migrated from performing a PUT on
        "/config/<section>/<option>/<value>" to sending the parameters using a json-encoded body.
        This was done to fix multiple un-wanted side effects related to how the middleware treats
        values encoded in a path.
        For a smooth transition, we allow both cases for now, but we should migrate to only passing
        values via the request body.
        :return: True if option was removed successfully. False otherwise.
        """

        if use_body_for_params:
            url = build_url(choice(self.list_hosts), path=self.CONFIG_BASEURL)
            data = dumps({
                section: {
                    option: value
                }
            })
            r = self._send_request(url, type='POST', data=data)
        else:
            path = '/'.join([self.CONFIG_BASEURL, section, option, value])
            url = build_url(choice(self.list_hosts), path=path)
            r = self._send_request(url, type='PUT')

        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def delete_config_option(self, section, option):
        """
        Sends the request to remove an option from a section

        :param section: the name of the section.
        :param option: the name of the option.
        :return: True if option was removed successfully. False otherwise.
        """

        path = '/'.join([self.CONFIG_BASEURL, section, option])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type='DEL')

        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
