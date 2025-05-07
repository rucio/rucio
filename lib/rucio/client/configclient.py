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

from json import dumps
from typing import Any, Optional

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.utils import build_url


class ConfigClient(BaseClient):

    """Client class for working with the configuration"""

    CONFIG_BASEURL = 'config'

    def get_config(
            self,
            section: Optional[str] = None,
            option: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Sends the request to get the matching configuration.

        Parameters
        ----------
        section :
            The name of the section.
        option :
            The option within the section.
        """

        if section is None and option is not None:
            raise ValueError('--section not specified')

        path = self.CONFIG_BASEURL
        if section is not None and option is None:
            path += '/' + section
        elif section is not None and option is not None:
            path += '/'.join(['', section, option])

        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return r.json()
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def set_config_option(
            self,
            section: str,
            option: str,
            value: Any,
            use_body_for_params: bool = True
    ) -> bool:
        """
        Sends the request to create or set an option within a section. Missing sections will be created.

        Parameters
        ----------
        section :
            The name of the section.
        option :
            The name of the option.
        value :
            The value to set on the config option.
        use_body_for_params :
            Send parameters in a json-encoded request body instead of url-encoded.

        Returns
        -------
        bool
            True if option was set successfully.

        Note:
        ------
        The format of the /config endpoint was recently changed. We migrated from performing a PUT on
        "/config/<section>/<option>/<value>" to sending the parameters using a json-encoded body.
        This was done to fix multiple un-wanted side effects related to how the middleware treats
        values encoded in a path.
        For a smooth transition, we allow both cases for now, but we should migrate to only passing
        values via the request body.
        """

        if use_body_for_params:
            url = build_url(choice(self.list_hosts), path=self.CONFIG_BASEURL)
            data = dumps({
                section: {
                    option: value
                }
            })
            r = self._send_request(url, type_='POST', data=data)
        else:
            path = '/'.join([self.CONFIG_BASEURL, section, option, value])
            url = build_url(choice(self.list_hosts), path=path)
            r = self._send_request(url, type_='PUT')

        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def delete_config_option(
            self,
            section: str,
            option: str
    ) -> bool:
        """
        Sends the request to remove an option from a section.

        Parameters
        ----------
        section :
            The name of the section.
        option :
            The name of the option.

        Returns
        -------

            True if option was removed successfully.
        """

        path = '/'.join([self.CONFIG_BASEURL, section, option])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type_='DEL')

        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)
