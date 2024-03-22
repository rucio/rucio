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

import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request


def wait_for_server(host, port, max_wait):
    timer = 0
    while timer < max_wait:
        try:
            response = urllib.request.urlopen(urllib.request.Request(f'http://{host}:{port}'))
            if response.status == 200:
                return
        except Exception:
            if timer > max_wait:
                raise
        time.sleep(1)
        timer += 1


def configure(
        host,
        port,
        username,
        password,
        new_config,
):
    scheme = 'http'
    headers = {
        'content-type': 'application/x-www-form-urlencoded'
    }

    # Authenticate
    req = urllib.request.Request(
        f'{scheme}://{host}:{port}/api/v2/auth/login',
        headers=headers,
        data=urllib.parse.urlencode({
            'username': username,
            'password': password
        }).encode(),
        method='POST',
    )
    response = urllib.request.urlopen(req)
    headers['Cookie'] = response.getheader("Set-Cookie")

    # Update the config
    req = urllib.request.Request(
        f'{scheme}://{host}:{port}/api/v2/app/setPreferences',
        headers=headers,
        data=urllib.parse.urlencode({'json': json.dumps(new_config)}).encode(),
        method='POST',
    )
    urllib.request.urlopen(req)

    scheme = 'https' if new_config.get('use_https') else scheme
    port = new_config.get('web_ui_port', port)

    # Logout
    req = urllib.request.Request(f'{scheme}://{host}:{port}/api/v2/auth/logout', headers=headers, method='POST')
    urllib.request.urlopen(req)


if __name__ == "__main__":
    initial_config_done = False
    extract_password = re.compile(r'.*: ([23456789ABCDEFGHIJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz]{9})$')
    for line in sys.stdin:
        if initial_config_done:
            continue

        automatic_password = extract_password.search(line)
        if not automatic_password:
            continue
        automatic_password = automatic_password.group(1)

        port = 8080
        host = 'localhost'

        wait_for_server(host=host, port=port, max_wait=60)

        config = {
            'listen_port': int(os.environ.get('QBITTORRENT_LISTEN_PORT', 10000)),
            # 'ssl_enabled': True,
            # 'ssl_listen_port': 20000,
            'upnp': False,
            'dht': False,
            'pex': False,
            'lsd': False,
            'encryption': 1,  # require encryption
            'bypass_local_auth': False,
            'web_ui_upnp': False,
            # 'web_ui_address': '',
            'enable_embedded_tracker': True,
            'embedded_tracker_port': int(os.environ.get('QBITTORRENT_TRACKER_PORT', 10001)),
            'enable_multi_connections_from_same_ip': True,
        }

        if os.environ.get('QBITTORRENT_UI_PASSWORD'):
            config['web_ui_password'] = os.environ['QBITTORRENT_UI_PASSWORD']
            if os.environ.get('QBITTORRENT_UI_USERNAME'):
                config['web_ui_username'] = os.environ['QBITTORRENT_UI_USERNAME']
        if os.environ.get('QBITTORRENT_UI_PORT'):
            config['web_ui_port'] = os.environ['QBITTORRENT_UI_PORT']

        if os.environ.get('QBITTORRENT_UI_CERT') and os.environ.get('QBITTORRENT_UI_KEY'):
            config['use_https'] = True
            config['web_ui_https_cert_path'] = os.environ['QBITTORRENT_UI_CERT']
            config['web_ui_https_key_path'] = os.environ['QBITTORRENT_UI_KEY']

        configure(
            host=host,
            port=port,
            username='admin',
            password=automatic_password,
            new_config=config,
        )

        initial_config_done = True
