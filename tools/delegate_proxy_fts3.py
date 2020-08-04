#!/usr/bin/env python
# Copyright 2014-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import commands
import os
import pprint
import requests
import sys
import time

from dateutil import parser


v = '/etc/pki/tls/certs/CERN-bundle.pem'

c = '/opt/rucio/tools/rucio01.proxy'
s = '/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=rucio01/CN=663551/CN=Robot: Rucio Service Account 01/CN=proxy/CN=proxy/CN=proxy'
if '--ddmadmin' in sys.argv:
    c = '/opt/rucio/tools/x509up'
    s = '/DC=ch/DC=cern/OU=Organic Units/OU=Users/CN=ddmadmin/CN=531497/CN=Robot: ATLAS Data Management/CN=proxy/CN=proxy/CN=proxy'
print(c)
print(s)

h = 'https://fts3-pilot.cern.ch:8446'
if '--prod' in sys.argv:
    h = 'https://fts3.cern.ch:8446'
elif '--devel' in sys.argv:
    h = 'https://fts3-devel.cern.ch:8446'
elif '--raltest' in sys.argv:
    h = 'https://fts3-test.gridpp.rl.ac.uk:8446'
print(h)

w = requests.get('%s/whoami' % h, verify=False, cert=c).json()
pprint.pprint(w)

b = requests.get('%s/delegation/%s' % (h, w['delegation_id']), verify=False, cert=c).json()
pprint.pprint(b)
bt = parser.parse('1970-01-01 00:00:01')
if b is not None:
    bt = parser.parse(b['termination_time'])
at = parser.parse('1970-01-01 00:00:00')

while at < bt:
    with open('/tmp/fts3request.pem', 'w') as fd:
        fd.write(requests.get('%s/delegation/%s/request' % (h, w['delegation_id']), verify=False, cert=c).text)

    commands.getstatusoutput('/bin/echo -n > /etc/pki/CA/index.txt')
    commands.getstatusoutput('/bin/echo "00" > /etc/pki/CA/serial')
    commands.getstatusoutput('/usr/bin/openssl ca -in /tmp/fts3request.pem -preserveDN -days 365 -cert %s -keyfile %s -md sha1 -out /tmp/fts3proxy.pem -subj "%s" -policy policy_anything -batch' % (c, c, s))
    commands.getstatusoutput('/bin/cat /tmp/fts3proxy.pem %s > /tmp/fts3full.pem' % c)

    print(requests.put('%s/delegation/%s/credential' % (h, w['delegation_id']), verify=False, cert=c,
                       data=open('/tmp/fts3full.pem', 'r')).text)
    a = requests.get('%s/delegation/%s' % (h, w['delegation_id']), verify=False, cert=c).json()
    pprint.pprint(a)
    if a is not None:
        at = parser.parse(a['termination_time'])

    os.unlink('/tmp/fts3request.pem')
    os.unlink('/tmp/fts3proxy.pem')
    os.unlink('/tmp/fts3full.pem')

    if at < bt:
        print('retrying')
        time.sleep(1)
