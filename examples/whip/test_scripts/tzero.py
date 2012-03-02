# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#              http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne,  <vincent.garonne@cern.ch> , 2012

'''
tzero use case:
#(1)every 600 seconds do :
#(2)        for each dataset that has new files to upload into DQ2 do :
#(3)             dq2-register -a -x -C -L ... -m <file with data of new files> <DSN> [#calls = O(1500/day), on avg. 30 files per call O(40K/day)]
#(4)             if there will be no more files arriving for this dataset do:
#(5)                    dq2-freeze-dataset -x <DSN> [#calls = O(200/day)]
'''

import random
import time
import uuid

from rucio.api.dataset import add_dataset, close_dataset


class Transaction(object):

    def __init__(self):
        pass

    def run(self):
        factor = 100
        delay = 24 * 60 * 60 / 1500 * factor  # O(1500/day)
        cycles = (24 * 60 * 60 / 200) / delay * factor  # O(200/day)
        nbfiles = 30
        scope = 'tzero'
        rse = 'CERN-PROD_TZERO'
        dataset_meta = {'project': 'data12_7TeV',
                         'run_number':  str(uuid.uuid4()),
                         'stream_name': 'physics_CosmicCalo',
                         'prod_step': 'merge',
                         'datatype': 'NTUP_TRIG',
                         'version': 'f392_m927',
                       }
        dsn = '%(project)s.%(run_number)s.%(stream_name)s.%(prod_step)s.%(datatype)s.%(version)s' % dataset_meta
        for cycle in xrange(1, cycles):
            content = {'rse': rse, 'files': [dsn + '.' + str(uuid.uuid4()) for i in xrange(nbfiles)]}
            # start = time.time()
            add_dataset(scope=scope, dsn=dsn, content=content, dataset_meta=dataset_meta)
            #self.custom_timers['add_dataset']= time.time() - start
            time.sleep(delay)
        # start = time.time()
        close_dataset(scope=scope, dsn=dsn)
        # self.custom_timers['close_dataset'] = time.time() - start


if __name__ == '__main__':
    trans = Transaction()
    trans.run()
