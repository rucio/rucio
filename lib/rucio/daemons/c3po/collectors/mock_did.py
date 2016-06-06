# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2015

from random import choice


class MockDIDCollector():
    def __init__(self, queue):
        self._queue = queue
        self._read_file('/opt/rucio/etc/dids_mc15_13TeV.csv')

    def _read_file(self, infile):
        dids = []
        with open(infile, 'r') as f:
            f.readline()
            for line in f:
                items = line.strip().split('\t')
                scope = items[0]
                name = items[1]
                dids.append((scope, name))

        self._dids = tuple(dids)

    def get_dids(self):
        did = choice(self._dids)
        self._queue.put(did)
