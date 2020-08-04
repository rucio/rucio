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
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

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
        print('%s:%s' % (r[1], ':'.join(r[0].split(':')[1:])))


if __name__ == '__main__':
    run()
