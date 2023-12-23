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


echo 'Fixing ownership and permissions'
cp /tmp/xrdcert.pem /etc/grid-security/xrd/xrdcert.pem
cp /tmp/xrdkey.pem /etc/grid-security/xrd/xrdkey.pem
chown -R xrootd:xrootd /etc/grid-security/xrd
chmod 0400 /etc/grid-security/xrd/xrdkey.pem

xrootd -R xrootd -n rucio -c /etc/xrootd/xrdrucio.cfg

exec "$@"
