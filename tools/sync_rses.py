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
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013

import json
import sys
import traceback

from rucio.client import Client
from rucio.common.exception import Duplicate

UNKNOWN = 3
CRITICAL = 2
WARNING = 1
OK = 0

if __name__ == '__main__':

    # parameters
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
            continent = repo_data[rse].get('continent')
            time_zone = repo_data[rse].get('time_zone')
            ISP = repo_data[rse].get('ISP')
            c.add_rse(rse, deterministic=deterministic, volatile=volatile,
                      region_code=region_code, country_name=country_name,
                      continent=continent, time_zone=time_zone, ISP=ISP)
        except Duplicate:
            print '%(rse)s already added' % locals()
        except:
            errno, errstr = sys.exc_info()[:2]
            trcbck = traceback.format_exc()
            print 'Interrupted processing with %s %s %s.' % (errno, errstr, trcbck)
        for p_id in repo_data[rse]['protocols']['supported']:
            try:
                p = repo_data[rse]['protocols']['supported'][p_id]
                p['scheme'] = p_id
                c.add_protocol(rse, p)
            except ValueError, e:
                print rse, e
            except Duplicate, e:
                print rse, e
            except Exception, e:
                errno, errstr = sys.exc_info()[:2]
                trcbck = traceback.format_exc()
                print 'Interrupted processing for %s with %s %s %s.' % (rse, errno, errstr, trcbck)
