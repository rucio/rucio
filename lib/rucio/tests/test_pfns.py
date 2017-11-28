# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2017

from nose.tools import assert_equal

from rucio.rse import rsemanager as rsemgr


class TestPFNs(object):

    def test_pfn_srm(self):
        """ PFN (CORE): Test the splitting of PFNs with SRM"""

        rse_info = rsemgr.get_rse_info('MOCK')
        proto = rsemgr.create_protocol(rse_info, 'read', scheme='srm')
        pfns = ['srm://mock.com:8443/rucio/tmpdisk/rucio_tests/whatever',
                'srm://mock.com:8443/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/whatever',
                'srm://mock.com:8443/srm/v2/server?SFN=/rucio/tmpdisk/rucio_tests/whatever']
        for pfn in pfns:
            ret = proto.parse_pfns([pfn])
            assert_equal(ret[pfn]['scheme'], 'srm')
            assert_equal(ret[pfn]['hostname'], 'mock.com')
            assert_equal(ret[pfn]['port'], 8443)
            assert_equal(ret[pfn]['prefix'], '/rucio/tmpdisk/rucio_tests/')
            assert_equal(ret[pfn]['path'], '/')
            assert_equal(ret[pfn]['name'], 'whatever')

    def test_pfn_https(self):
        """ PFN (CORE): Test the splitting of PFNs with https"""

        rse_info = rsemgr.get_rse_info('MOCK')
        proto = rsemgr.create_protocol(rse_info, 'read', scheme='https')
        pfn = 'https://mock.com:2880/pnfs/rucio/disk-only/scratchdisk/whatever'
        ret = proto.parse_pfns([pfn])
        assert_equal(ret[pfn]['scheme'], 'https')
        assert_equal(ret[pfn]['hostname'], 'mock.com')
        assert_equal(ret[pfn]['port'], 2880)
        assert_equal(ret[pfn]['prefix'], '/pnfs/rucio/disk-only/scratchdisk/')
        assert_equal(ret[pfn]['path'], '/')
        assert_equal(ret[pfn]['name'], 'whatever')

    def test_pfn_mock(self):
        """ PFN (CORE): Test the splitting of PFNs with mock"""
        rse_info = rsemgr.get_rse_info('MOCK')
        proto = rsemgr.create_protocol(rse_info, 'read', scheme='mock')
        pfn = 'mock://localhost/tmp/rucio_rse/whatever'
        ret = proto.parse_pfns([pfn])
        assert_equal(ret[pfn]['scheme'], 'mock')
        assert_equal(ret[pfn]['hostname'], 'localhost')
        assert_equal(ret[pfn]['port'], 0)
        assert_equal(ret[pfn]['prefix'], '/tmp/rucio_rse/')
        assert_equal(ret[pfn]['path'], '/')
        assert_equal(ret[pfn]['name'], 'whatever')

    def test_pfn_filename_in_dataset(self):
        """ PFN (CORE): Test the splitting of PFNs cornercase: filename in prefix"""
        rse_info = rsemgr.get_rse_info('MOCK')
        proto = rsemgr.create_protocol(rse_info, 'read', scheme='mock')

        pfn = 'mock://localhost/tmp/rucio_rse/rucio_rse'
        ret = proto.parse_pfns([pfn])
        assert_equal(ret[pfn]['scheme'], 'mock')
        assert_equal(ret[pfn]['hostname'], 'localhost')
        assert_equal(ret[pfn]['port'], 0)
        assert_equal(ret[pfn]['prefix'], '/tmp/rucio_rse/')
        assert_equal(ret[pfn]['path'], '/')
        assert_equal(ret[pfn]['name'], 'rucio_rse')

        proto = rsemgr.create_protocol(rse_info, 'read', scheme='srm')
        pfn = 'srm://mock.com/srm/managerv2?SFN=/rucio/tmpdisk/rucio_tests/group/phys-fake/mc15_13TeV/group.phys-fake.mc15_13TeV/mc15c.MGHwpp_tHjb125_yt_minus1.MxAODFlavorSys.p2908.h015.totape_20170825.root'
        ret = proto.parse_pfns([pfn])
        assert_equal(ret[pfn]['scheme'], 'srm')
        assert_equal(ret[pfn]['hostname'], 'mock.com')
        assert_equal(ret[pfn]['port'], 8443)
        assert_equal(ret[pfn]['prefix'], '/rucio/tmpdisk/rucio_tests/')
        assert_equal(ret[pfn]['path'], '/group/phys-fake/mc15_13TeV/group.phys-fake.mc15_13TeV/')
        assert_equal(ret[pfn]['name'], 'mc15c.MGHwpp_tHjb125_yt_minus1.MxAODFlavorSys.p2908.h015.totape_20170825.root')
