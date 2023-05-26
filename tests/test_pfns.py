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

from rucio.rse import rsemanager as rsemgr


class TestPFNs:

    def test_pfn_srm(self, vo):
        """ PFN (CORE): Test the splitting of PFNs with SRM"""

        rse_info = rsemgr.get_rse_info('MOCK', vo=vo)
        proto = rsemgr.create_protocol(rse_info, 'read', scheme='srm')
        pfns = ['srm://mock.com:8443/rucio/tmpdisk/rucio_tests/whatever',
                'srm://mock.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/whatever',
                'srm://mock.com:8443/srm/v2/server?SFN=/rucio/tmpdisk/rucio_tests/whatever']
        for pfn in pfns:
            ret = proto.parse_pfns([pfn])
            assert ret[pfn]['scheme'] == 'srm'
            assert ret[pfn]['hostname'] == 'mock.com'
            assert ret[pfn]['port'] == 8443
            assert ret[pfn]['prefix'] == '/rucio/tmpdisk/rucio_tests/'
            assert ret[pfn]['path'] == '/'
            assert ret[pfn]['name'] == 'whatever'

    def test_pfn_https(self, vo):
        """ PFN (CORE): Test the splitting of PFNs with https"""

        rse_info = rsemgr.get_rse_info('MOCK', vo=vo)
        proto = rsemgr.create_protocol(rse_info, 'read', scheme='https')
        pfn = 'https://mock.com:2880/pnfs/rucio/disk-only/scratchdisk/whatever'
        ret = proto.parse_pfns([pfn])
        assert ret[pfn]['scheme'] == 'https'
        assert ret[pfn]['hostname'] == 'mock.com'
        assert ret[pfn]['port'] == 2880
        assert ret[pfn]['prefix'] == '/pnfs/rucio/disk-only/scratchdisk/'
        assert ret[pfn]['path'] == '/'
        assert ret[pfn]['name'] == 'whatever'

    def test_pfn_mock(self, vo):
        """ PFN (CORE): Test the splitting of PFNs with mock"""
        rse_info = rsemgr.get_rse_info('MOCK', vo=vo)
        proto = rsemgr.create_protocol(rse_info, 'read', scheme='mock')
        pfn = 'mock://localhost/tmp/rucio_rse/whatever'
        ret = proto.parse_pfns([pfn])
        assert ret[pfn]['scheme'] == 'mock'
        assert ret[pfn]['hostname'] == 'localhost'
        assert ret[pfn]['port'] == 0
        assert ret[pfn]['prefix'] == '/tmp/rucio_rse/'
        assert ret[pfn]['path'] == '/'
        assert ret[pfn]['name'] == 'whatever'

    def test_pfn_filename_in_dataset(self, vo):
        """ PFN (CORE): Test the splitting of PFNs cornercase: filename in prefix"""
        rse_info = rsemgr.get_rse_info('MOCK', vo=vo)
        proto = rsemgr.create_protocol(rse_info, 'read', scheme='mock')

        pfn = 'mock://localhost/tmp/rucio_rse/rucio_rse'
        ret = proto.parse_pfns([pfn])
        assert ret[pfn]['scheme'] == 'mock'
        assert ret[pfn]['hostname'] == 'localhost'
        assert ret[pfn]['port'] == 0
        assert ret[pfn]['prefix'] == '/tmp/rucio_rse/'
        assert ret[pfn]['path'] == '/'
        assert ret[pfn]['name'] == 'rucio_rse'

        proto = rsemgr.create_protocol(rse_info, 'read', scheme='srm')
        pfn = 'srm://mock.com/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/group/phys-fake/mc15_13TeV/group.phys-fake.mc15_13TeV/mc15c.MGHwpp_tHjb125_yt_minus1.MxAODFlavorSys.p2908.h015.totape_20170825.root'
        ret = proto.parse_pfns([pfn])
        assert ret[pfn]['scheme'] == 'srm'
        assert ret[pfn]['hostname'] == 'mock.com'
        assert ret[pfn]['port'] == 8443
        assert ret[pfn]['prefix'] == '/rucio/tmpdisk/rucio_tests/'
        assert ret[pfn]['path'] == '/group/phys-fake/mc15_13TeV/group.phys-fake.mc15_13TeV/'
        assert ret[pfn]['name'] == 'mc15c.MGHwpp_tHjb125_yt_minus1.MxAODFlavorSys.p2908.h015.totape_20170825.root'
