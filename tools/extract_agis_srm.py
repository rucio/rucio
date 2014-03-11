#!/usr/bin/env python
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
            tmp.append((site['token'], urlparse.urlparse(str(''.join([s for s in site['protocols'] if s.startswith('srm')][0] + [site['protocols'][s] for s in site['protocols'] if s.startswith('srm')][0][0][2])))))
        except:
            pass
    for t in tmp:
        u = list(t[1])
        v = urlparse.urlunparse(u)

        # Sites that do not have a prefix defined are removed
        if v.endswith('/'):
            res.append((v, str(t[0])))

    res.sort()
    for r in res:
        print '%s:%s' % (r[1], ':'.join(r[0].split(':')[1:]))

if __name__ == '__main__':
    run()
