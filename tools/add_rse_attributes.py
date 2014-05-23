#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#                       http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013-2014
# - David Cameron, <david.cameron@cern.ch>, 2014
# - Tomas Kouba, <tomas.kouba@cern.ch>, 2014

import json
import requests
import sys

from rucio.client import Client
from rucio.common.exception import RucioException, RSENotFound

UNKNOWN = 3
CRITICAL = 2
WARNING = 1
OK = 0

# Takes DDM endpoint information from AGIS and adds selected attributes to RSEs
if __name__ == '__main__':

    url = 'http://atlas-agis-api.cern.ch/request/ddmendpoint/query/list/?json'
    resp = requests.get(url=url)
    data = json.loads(resp.content)

    c = Client()
    for rse in data:

        # Only use active endpoints in AGIS
        if rse['state'] != 'ACTIVE':
            continue

        # TODO: remove when Conveyor is fixed for nondeterministic endpoints
        if rse['is_tape']:
            continue

        # Check if RSE exists
        try:
            c.get_rse(rse['name'])
        except RSENotFound:
            continue

        print rse['name']

        try:
            c.add_rse_attribute(rse['name'], 'tier', str(rse['tier_level']))
            c.add_rse_attribute(rse['name'], 'istape', str(rse['is_tape']))
            c.add_rse_attribute(rse['name'], 'cloud', str(rse['cloud']))
            c.add_rse_attribute(rse['name'], 'spacetoken', str(rse['token']))
            c.add_rse_attribute(rse['name'], 'country', str(rse['country']))
            c.add_rse_attribute(rse['name'], 'site', str(rse['site']))
            for group in rse['ddmgroups']:
                c.add_rse_attribute(rse['name'], str(group), True)
        except RucioException as e:
            print str(e)
            sys.exit(CRITICAL)

    sys.exit(OK)
