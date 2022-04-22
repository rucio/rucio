# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

"""
Mock DID collector
"""

from random import choice


class MockDIDCollector(object):
    """
    Simple collector that reads dids from a file. Used to
    test the interface.
    """
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
