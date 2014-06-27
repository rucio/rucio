#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013-2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

import json
import os.path
import requests
import sys
import traceback
import urlparse


from rucio.client import Client

UNKNOWN = 3
CRITICAL = 2
WARNING = 1
OK = 0

if __name__ == '__main__':

    url = 'http://atlas-agis-api.cern.ch/request/ddmendpoint/query/list/?json'
    resp = requests.get(url=url)
    data = json.loads(resp.content)

    c = Client()
    for rse in data:

        if rse['state'] != 'ACTIVE':
            continue

        try:
            deterministic = not rse['is_tape']
            volatile = False
            c.add_rse(rse=rse['name'], deterministic=deterministic, volatile=volatile)
        except:
            errno, errstr = sys.exc_info()[:2]
            trcbck = traceback.format_exc()
            print 'Interrupted processing with %s %s %s.' % (errno, errstr, trcbck)

        prefix = rse['endpoint']
        space_token = rse['token']

        # Add mock protocol for testing
        params = {'hostname': 'mock.ndgf.org',
                  'scheme': 'mock',
                  'port': None,
                  'prefix': '',
                  'impl': 'rucio.rse.protocols.mock.Default',
                  'extended_attributes': None,
                  'domains': {"lan": {"read": 2,
                                      "write": 2,
                                      "delete": 1},
                              "wan": {"read": 2,
                                      "write": 2,
                                      "delete": 1}}}

        # c.add_protocol(rse=rse['name'], params=params)
        for protocol in rse['protocols']:
            try:
                o = urlparse.urlparse(protocol)

                if o.scheme not in ('https', 'http', 'srm', 'gsiftp'):
                    continue

                extended_attributes = None
                if o.scheme == 'srm':
                    extended_attributes = {"web_service_path": o.path + '?SFN=', "space_token": space_token}
                    impl = 'rucio.rse.protocols.srm.Default'
                    priority = 1
                elif o.scheme == 'https' or o.scheme == 'http':
                    extended_attributes = None
                    impl = 'rucio.rse.protocols.webdav.Default'
                    priority = 2
                    continue
                elif o.scheme == 'gsiftp':
                    extended_attributes = None
                    impl = 'rucio.rse.protocols.gsiftp.Default'
                    priority = 3
                else:
                    continue

                netloc = o.netloc
                if o.port and str(o.port) in o.netloc:
                    netloc = o.netloc[:-len(':' + str(o.port))]

                # For disk end-points nto for tape
                prefix = rse['protocols'][protocol][0][2]
                if not rse['is_tape'] and not prefix.endswith('/rucio') and not prefix.endswith('/rucio/'):
                    prefix = os.path.join(prefix, 'rucio/')

                params = {'hostname': netloc,
                          'scheme': o.scheme,
                          'port': o.port or 443,
                          'prefix': prefix,
                          'impl': impl,
                          'extended_attributes': extended_attributes,
                          'domains': {"lan": {"read": priority,
                                              "write": priority,
                                              "delete": priority},
                                      "wan": {"read": priority,
                                              "write": priority,
                                              "delete": priority}}}

                print 'Add protocol', rse['name'], params
                c.add_protocol(rse=rse['name'], params=params)
            except:
                errno, errstr = sys.exc_info()[:2]
                trcbck = traceback.format_exc()
                print 'Interrupted processing with %s %s %s.' % (errno, errstr, trcbck)

    sys.exit(OK)
