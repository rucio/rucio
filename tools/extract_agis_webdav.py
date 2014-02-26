#!/opt/rucio/.venv/bin/python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

import requests
import urlparse


def run():
    sites = requests.get('http://atlas-agis-api.cern.ch/request/ddmendpoint/query/list/?json').json()

    tmp = []  # needed because urlparse returns constant tuples
    res = []

    for site in sites:
        try:
            # let's hope the JSON schema doesn't change in the future
            tmp.append(urlparse.urlparse(str(''.join([s for s in site['protocols'] if s.startswith('http')][0] + [site['protocols'][s] for s in site['protocols'] if s.startswith('http')][0][0][2]))))
        except:
            pass
    for t in tmp:
        u = list(t)

        # Force default HTTPS port if missing, makes later parsing easier
        if t.port is None:
            u[1] += ':443'

        v = urlparse.urlunparse(u)

        # Sites that do not have a prefix defined are removed
        if v.endswith('/'):
            res.append(v)

    res.sort()
    for r in res:
        print r

if __name__ == '__main__':
    run()
