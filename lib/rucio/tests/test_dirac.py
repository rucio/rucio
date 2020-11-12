# -*- coding: utf-8 -*-
# Copyright 2020 CERN for the benefit of the ATLAS collaboration.
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
#
# PY3K COMPATIBLE

from __future__ import print_function

import unittest

import pytest

from rucio.client import Client
from rucio.common.exception import DataIdentifierAlreadyExists
from rucio.common.utils import extract_scope


class TestDiracClients(unittest.TestCase):

    def setUp(self):
        self.client = Client()
        self.account = 'root'
        self.scope = 'mc'
        self.rse = 'Mock'
        self.prefix = 'srm://mock.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests'
        scopes = [_ for _ in self.client.list_scopes()]
        if 'other' not in scopes:
            self.client.add_scope(self.account, 'other')
        try:
            self.client.add_container('other', '/belle')
        except DataIdentifierAlreadyExists:
            pass
        if self.scope not in scopes:
            self.client.add_scope(self.account, self.scope)
        if 'ANY' not in self.client.list_rse_attributes(self.rse):
            self.client.add_rse_attribute(self.rse, key='ANY', value=True)

    @pytest.mark.xfail(reason='fails with: RSE does not exist')
    def test_add_files(self):
        """ DIRAC (CLIENT): Add a list of files."""
        lfn = '/belle/MC/bnl/release-06-00-08/DB00000000/MC13/prod00000002/s00/e0000/4S/r00000/1310040140/mdst/sub00/myfile.root'
        lfns = {lfn: {'rse': self.rse, 'bytes': 1234, 'adler32': 'AB1463EF', 'pfn': self.prefix + lfn}}
        lfns = []
        for cnt in range(30):
            lfns.append({'rse': 'Mock', 'bytes': 1234, 'adler32': 'AB1463EF', 'pfn': '%s%s.%s' % (self.prefix, lfn, cnt), 'lfn': '%s.%s' % (lfn, cnt)})
        self.client.add_files(lfns=lfns)
        lfn_split = lfn.split('/')
        lpns = ["/".join(lfn_split[:idx]) for idx in range(2, len(lfn_split))]
        idx = 1
        for lpn in lpns:
            scope, name = extract_scope(lpn)
            content = [str(did['name']) for did in self.client.list_content(scope, name)]
            if idx < len(lpns):
                print(content)
                assert lpns[idx] in content
            idx += 1
        dsn = "/".join(lfn_split[:-1])

        scope, name = extract_scope(dsn)
        files = [str(did['name']) for did in self.client.list_files(scope, name)]
        files.sort()
        list_lfns = [str(did['lfn']) for did in lfns]
        list_lfns.sort()
        assert files == list_lfns

        files = [str(did['rses'][self.rse][0]) for did in self.client.list_replicas([{'scope': scope, 'name': name}], schemes=['srm'])]
        files.sort()
        print(files)
        list_pfns = [str(did['pfn']) for did in lfns]
        list_pfns.sort()
        assert files == list_pfns
