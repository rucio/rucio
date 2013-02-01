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

import sys
import traceback

from rucio.client import Client
from rucio.common.exception import Duplicate

UNKNOWN = 3
CRITICAL = 2
WARNING = 1
OK = 0

if __name__ == '__main__':

    meta_keys = ['project', 'run_number', 'stream_name',
                 'prod_step', 'datatype', 'version', 'guid']

    c = Client()
    for key in meta_keys:
        try:
            c.add_key(key=key)
        except Duplicate:
            print '%(key)s already added' % locals()
        except:
            errno, errstr = sys.exc_info()[:2]
            trcbck = traceback.format_exc()
            print 'Interrupted processing with %s %s %s.' % (errno, errstr, trcbck)
    sys.exit(OK)
