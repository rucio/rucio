#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN) 2013
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2017

import datetime
import requests
import sys

from dateutil import parser

from rucio.common.config import config_get

requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


UNKNOWN = 3
CRITICAL = 2
WARNING = 1
OK = 0

PROXY = config_get('nagios', 'rfcproxy')
FTS_SERVERS = config_get('nagios', 'fts_servers').split(',')

status = OK
for FTS_SERVER in FTS_SERVERS:
    FTS_SERVER = FTS_SERVER.strip()
    whoami = requests.get('%s/whoami' % FTS_SERVER, verify=False, cert=PROXY).json()
    delegation = requests.get('%s/delegation/%s' % (FTS_SERVER, whoami['delegation_id']), verify=False, cert=PROXY).json()
    expiration = parser.parse(delegation['termination_time'])
    if expiration < datetime.datetime.now() + datetime.timedelta(days=30):
        print FTS_SERVER, expiration.strftime("%Y-%m-%d"), 'CRITICAL'
        status = CRITICAL
    elif expiration < datetime.datetime.now() + datetime.timedelta(days=100):
        print FTS_SERVER, expiration.strftime("%Y-%m-%d"), 'WARNING'
        status = WARNING
    else:
        print FTS_SERVER, expiration.strftime("%Y-%m-%d"), 'OK'

sys.exit(status)
