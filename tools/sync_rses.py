#!/usr/bin/env python
# Copyright 2013-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2013
# - Ralph Vigne <ralph.vigne@cern.ch>, 2013-2014
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Cedric Serfon <cedric.serfon@cern.ch>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Gabriele Gaetano Fronze' <gabriele.fronze@to.infn.it>, 2020

import sys
import os.path
base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_path)
os.chdir(base_path)

import json  # noqa: E402
import sys  # noqa: E402
import traceback  # noqa: E402

from rucio.client import Client  # noqa: E402
from rucio.common.exception import Duplicate  # noqa: E402

UNKNOWN = 3
CRITICAL = 2
WARNING = 1
OK = 0


def main(argv):
    # parameters
    if argv:
        rse_repo_file = argv[0]
    else:
        rse_repo_file = 'etc/rse_repository.json'

    json_data = open(rse_repo_file)
    repo_data = json.load(json_data)
    json_data.close()

    c = Client()
    for rse in repo_data:
        try:
            deterministic = repo_data[rse].get('deterministic', True)
            volatile = repo_data[rse].get('volatile', False)
            region_code = repo_data[rse].get('region_code')
            country_name = repo_data[rse].get('country_name')
            staging_area = repo_data[rse].get('staging_area')
            continent = repo_data[rse].get('continent')
            time_zone = repo_data[rse].get('time_zone')
            ISP = repo_data[rse].get('ISP')
            c.add_rse(rse, deterministic=deterministic, volatile=volatile,
                      region_code=region_code, country_name=country_name, staging_area=staging_area,
                      continent=continent, time_zone=time_zone, ISP=ISP)
        except Duplicate:
            print('%(rse)s already added' % locals())
        except:
            errno, errstr = sys.exc_info()[:2]
            trcbck = traceback.format_exc()
            print('Interrupted processing with %s %s %s.' % (errno, errstr, trcbck))
        for p_id in repo_data[rse]['protocols']['supported']:
            try:
                p = repo_data[rse]['protocols']['supported'][p_id]
                p['scheme'] = p_id
                c.add_protocol(rse, p)
            except ValueError as e:
                print(rse, e)
            except Duplicate as e:
                print(rse, e)
            except Exception:
                errno, errstr = sys.exc_info()[:2]
                trcbck = traceback.format_exc()
                print('Interrupted processing for %s with %s %s %s.' % (rse, errno, errstr, trcbck))


if __name__ == '__main__':
    main(sys.argv[1:])
