#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2016

import cgi
import json
import os.path
import requests
import sys
import httplib
import traceback
import urllib


UNKNOWN = 3
CRITICAL = 2
WARNING = 1
OK = 0


certKey = os.environ['X509_USER_PROXY']


def getKeyPair(publicKeyName, privateKeyName):
    node = {}
    node['privateKeyName'] = privateKeyName
    node['publicKeyName'] = publicKeyName
    host = 'pandaserver.cern.ch:25443'
    path = '/server/panda/getKeyPair'
    conn = httplib.HTTPSConnection(host, key_file=certKey, cert_file=certKey)
    conn.request('POST', path, urllib.urlencode(node))
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    dic = cgi.parse_qs(data)
    if dic['StatusCode'][0] == '0':
        return {"publicKey": dic["publicKey"][0], "privateKey": dic["privateKey"][0]}
    return None


if __name__ == '__main__':

    URL = 'http://atlas-agis-api.cern.ch/request/ddmendpoint/query/list/?json&state=ACTIVE&site_state=ACTIVE'
    RESP = requests.get(url=URL)
    DATA = json.loads(RESP.content)
    RETVALUE = OK

    accounts = {}
    for rse in DATA:
        if 'AWS-S3' not in rse['se_flavour']:
            continue

        accounts[rse['name']] = {"access_key": None,
                                 "host_bucket": None,
                                 "progress_meter": "False",
                                 "skip_existing": "False",
                                 "host_base": None,
                                 "is_secure": {},
                                 "secret_key": None}
        try:
            if 'rprotocols' in rse and rse['rprotocols']:
                for id in rse['rprotocols']:
                    if rse['rprotocols'][id]['flavour']:
                        if rse['rprotocols'][id]['settings']['access_key'] and len(rse['rprotocols'][id]['settings']['access_key']):
                            keys = getKeyPair(rse['rprotocols'][id]['settings']['access_key'], rse['rprotocols'][id]['settings']['secret_key'])
                            if keys:
                                accounts[rse['name']]['access_key'] = keys['publicKey']
                                accounts[rse['name']]['secret_key'] = keys['privateKey']
                            # accounts[rse['name']]['host_base'] = rse['rprotocols'][id]['endpoint']
                            # accounts[rse['name']]['host_bucket'] = rse['rprotocols'][id]['endpoint']
                            accounts[rse['name']]['is_secure'][rse['rprotocols'][id]['endpoint']] = rse['rprotocols'][id]['settings']['is_secure']
                            if rse['rprotocols'][id]['endpoint'].startswith("s3://"):
                                accounts[rse['name']]['is_secure'][rse['rprotocols'][id]['endpoint'].replace("s3://", "s3+rucio://")] = rse['rprotocols'][id]['settings']['is_secure']
        except:
            print "Failed to get key pair for RSE %s: %s" % (rse['name'], traceback.format_exc())

    print json.dumps(accounts, sort_keys=True, indent=4)

    sys.exit(RETVALUE)
