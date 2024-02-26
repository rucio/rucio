#!/bin/bash
# -*- coding: utf-8 -*-
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

set -e

. /etc/apache2/envvars

a2dismod want_digest
a2dismod zgridsite
a2ensite default-ssl
a2dissite default

if [ -n "$QBITTORRENT_UI_PORT" ]
then
  export QBITTORRENT_UI_CERT=/etc/grid-security/hostcert.pem
  export QBITTORRENT_UI_KEY=/etc/grid-security/hostkey.pem
  chown www-data /var/www/
  su -s /bin/bash -c qbittorrent-nox www-data | tee >(python3 /configure_qbittorrent.py) &
fi

exec "$@"
