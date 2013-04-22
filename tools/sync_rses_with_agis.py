#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#                       http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

import json
import sys
import traceback
# import urlparse

import requests

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
        try:
            print rse['name']
            deterministic = False
            volatile = False
            c.add_rse(rse=rse['name'], deterministic=deterministic, volatile=volatile)
        except:
            errno, errstr = sys.exc_info()[:2]
            trcbck = traceback.format_exc()
            print 'Interrupted processing with %s %s %s.' % (errno, errstr, trcbck)

        prefix = rse['endpoint']
        space_token = rse['token']

        # Add mock protocol for testing
        params = {'hostname': None,
                  'port': None,
                  'prefix': prefix,
                  'impl': 'rucio.rse.protocols.mock.Default',
                  'extended_attributes': None,
                  'domains': {"LAN": {"read": 1,
                                      "write": 1,
                                      "delete": 1},
                              "WAN": {"read": 1,
                                      "write": 1,
                                      "delete": 1}}}
        c.add_protocol(rse=rse['name'], scheme='mock', params=params)

#
#         for protocol in rse['protocols']:
#             try:
#
#                 o = urlparse.urlparse(protocol)
#
#                 extended_attributes = None
#                 if o.scheme == 'srm':
#                     extended_attributes =  {"web_service_path": o.path, "space_token": space_token}
#
#                 params = {'hostname': o.netloc,
#                           'port': o.port,
#                           'prefix': prefix,
#                           'impl': 'rucio.rse.protocols.srm.Default',
#                           'extended_attributes': extended_attributes,
#                           'domains': {
#                                      "LAN": {
#                                               "read": 1,
#                                               "write": 1,
#                                               "delete": 1
#                                             },
#                                     "WAN": {
#                                               "read": 1,
#                                               "write": 1,
#                                               "delete": 1
#                                             }
#                                     }
#                          }
#                 c.add_protocol(rse=rse['name'], scheme=o.scheme, params=params)
#             except:
#                 errno, errstr = sys.exc_info()[:2]
#                 trcbck = traceback.format_exc()
#                 print 'Interrupted processing with %s %s %s.' % (errno, errstr, trcbck)

    sys.exit(OK)
