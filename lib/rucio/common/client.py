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

import os
import socket
from configparser import NoOptionError, NoSectionError
from typing import TYPE_CHECKING

from rucio.common.config import config_get, config_has_section
from rucio.common.exception import ConfigNotFound

if TYPE_CHECKING:
    from rucio.common.types import IPWithLocationDict


def is_client() -> bool:
    """"
    Checks if the function is called from a client or from a server/daemon

    :returns client_mode: True if is called from a client, False if it is called from a server/daemon
    """
    if 'RUCIO_CLIENT_MODE' not in os.environ:
        try:
            if config_has_section('database'):
                client_mode = False
            elif config_has_section('client'):
                client_mode = True
            else:
                client_mode = False
        except (RuntimeError, ConfigNotFound):
            # If no configuration file is found the default value should be True
            client_mode = True
    else:
        if os.environ['RUCIO_CLIENT_MODE']:
            client_mode = True
        else:
            client_mode = False

    return client_mode


def get_client_vo() -> str:
    """
    Get the client VO from the environment or the configuration file.

    :returns vo: The client VO as a string; default = 'def'.
    """
    if 'RUCIO_VO' in os.environ:
        vo = os.environ['RUCIO_VO']
    else:
        try:
            vo = str(config_get('client', 'vo'))
        except (NoOptionError, NoSectionError):
            vo = 'def'
    return vo


def detect_client_location() -> "IPWithLocationDict":
    """
    Normally client IP will be set on the server side (request.remote_addr)
    Here setting ip on the one seen by the host itself. There is no connection
    to Google DNS servers.
    Try to determine the sitename automatically from common environment variables,
    in this order: SITE_NAME, ATLAS_SITE_NAME, OSG_SITE_NAME. If none of these exist
    use the fixed string 'ROAMING'.

    If environment variables sets location, it uses it.
    """

    ip = None

    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.connect(("2001:4860:4860:0:0:0:0:8888", 80))
            ip = s.getsockname()[0]
    except Exception:
        pass

    if not ip:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
        except Exception:
            pass

    if not ip:
        ip = '0.0.0.0'  # noqa: S104

    site = os.environ.get('SITE_NAME',
                          os.environ.get('ATLAS_SITE_NAME',
                                         os.environ.get('OSG_SITE_NAME',
                                                        'ROAMING')))

    latitude = os.environ.get('RUCIO_LATITUDE')
    longitude = os.environ.get('RUCIO_LONGITUDE')
    if latitude and longitude:
        try:
            latitude = float(latitude)
            longitude = float(longitude)
        except ValueError:
            latitude = longitude = 0
            print('Client set latitude and longitude are not valid.')
    else:
        latitude = longitude = None

    return {'ip': ip,
            'fqdn': socket.getfqdn(),
            'site': site,
            'latitude': latitude,
            'longitude': longitude}
