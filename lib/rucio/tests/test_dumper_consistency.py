# Copyright 2015-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Fernando Lopez <fernando.e.lopez@gmail.com>, 2015
# - Vincent Garonne <vincent.garonne@cern.ch>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime

from six import PY3

from rucio.common.dumper.consistency import Consistency
from rucio.common.dumper.consistency import _try_to_advance
from rucio.common.dumper.consistency import compare3
from rucio.common.dumper.consistency import gnu_sort
from rucio.common.dumper.consistency import min3
from rucio.common.dumper.consistency import parse_and_filter_file
from rucio.tests.common import make_temp_file

if sys.version_info >= (3, 3):
    from unittest import mock
else:
    import mock


def mocked_requests(*args, **kwargs):
    class MockResponse:
        def __init__(self, json_data, status_code):
            self.status_code = status_code
            self.json_data = json_data
            self.text = json.dumps(json_data)
            self.iter_content = lambda _: json_data

        def json(self):
            return self.json_data

    rucio_dump_1 = (
        'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.filename\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.filename\t2015-09-20 21:22:17\tA\n'
        'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.lost\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.lost\t2015-09-20 21:22:17\tA\n'
    )
    rucio_dump_2 = (
        'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.filename\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.filename\t2015-09-20 21:22:17\tA\n'
        'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.lost\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.lost\t2015-09-20 21:22:17\tA\n'
    )
    if '29-09-2015' in args[0]:
        return MockResponse([rucio_dump_1], 200)
    else:
        return MockResponse([rucio_dump_2], 200)


class TestConsistency(unittest.TestCase):
    '''
    TestConsistency
    '''
    case_mixed_rrd_1 = [
        'path1,A',
        'path20,U',
        'path01,U',
        'path23,U',
        'path26,A',
        'path6,A',
    ]
    case_mixed_sed = [
        'path1',
        'path66',
        'path46',
        'path20',
        'pathsda',
    ]
    case_mixed_rrd_2 = [
        'path1,A',
        'path26,A',
        'path01,U',
        'path6,A',
        'path20,A',
    ]

    def setUp(self):  # pylint: disable=invalid-name
        self.tmp_dir = tempfile.mkdtemp()
        self.fake_agis_data = [{
            'name': 'MOCK_SCRATCHDISK',
            'se': 'srm://example.com:8446/',
            'endpoint': '/pnfs/example.com/atlas/atlasdatadisk/'
        }]

    def tearDown(self):  # pylint: disable=invalid-name
        shutil.rmtree(self.tmp_dir)

    @mock.patch('rucio.common.dumper.agis_endpoints_data')
    def test_consistency_manual_correct_file_default_args(self, mock_get):
        ''' DUMPER '''
        rucio_dump = 'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.filename\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.filename\t2015-09-20 21:22:17\tA\n'
        storage_dump = 'user/someuser/aa/bb/user.someuser.filename\n'

        rrdf1 = make_temp_file(self.tmp_dir, rucio_dump)
        rrdf2 = make_temp_file(self.tmp_dir, rucio_dump)
        sdf = make_temp_file(self.tmp_dir, storage_dump)

        mock_get.return_value = self.fake_agis_data
        consistency = Consistency.dump(
            'consistency-manual',
            'MOCK_SCRATCHDISK',
            sdf,
            prev_date_fname=rrdf1,
            next_date_fname=rrdf2,
            cache_dir=self.tmp_dir,
        )
        assert len(list(consistency)) == 0

    @mock.patch('rucio.common.dumper.agis_endpoints_data')
    def test_consistency_manual_lost_file(self, mock_get):
        ''' DUMPER '''
        rucio_dump = 'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.filename\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.filename\t2015-09-20 21:22:17\tA\n'
        rucio_dump += 'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.filename2\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.filename2\t2015-09-20 21:22:17\tA\n'
        storage_dump = 'user/someuser/aa/bb/user.someuser.filename\n'

        rrdf1 = make_temp_file(self.tmp_dir, rucio_dump)
        rrdf2 = make_temp_file(self.tmp_dir, rucio_dump)
        sdf = make_temp_file(self.tmp_dir, storage_dump)

        mock_get.return_value = self.fake_agis_data

        consistency = Consistency.dump(
            'consistency-manual',
            'MOCK_SCRATCHDISK',
            sdf,
            prev_date_fname=rrdf1,
            next_date_fname=rrdf2,
            cache_dir=self.tmp_dir,
        )
        consistency = list(consistency)
        assert len(consistency) == 1
        assert consistency[0].apparent_status == 'LOST'
        assert consistency[0].path == 'user/someuser/aa/bb/user.someuser.filename2'

    @mock.patch('rucio.common.dumper.agis_endpoints_data')
    def test_consistency_manual_transient_file_is_not_lost(self, mock_get):
        ''' DUMPER '''
        rucio_dump = 'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.filename\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.filename\t2015-09-20 21:22:17\tA\n'
        rucio_dump_1 = rucio_dump + 'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.filename2\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.filename2\t2015-09-20 21:22:17\tU\n'
        rucio_dump_2 = rucio_dump + 'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.filename2\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.filename2\t2015-09-20 21:22:17\tA\n'
        storage_dump = 'user/someuser/aa/bb/user.someuser.filename\n'

        rrdf1 = make_temp_file(self.tmp_dir, rucio_dump_1)
        rrdf2 = make_temp_file(self.tmp_dir, rucio_dump_2)
        sdf = make_temp_file(self.tmp_dir, storage_dump)

        mock_get.return_value = self.fake_agis_data

        consistency = Consistency.dump(
            'consistency-manual',
            'MOCK_SCRATCHDISK',
            sdf,
            prev_date_fname=rrdf1,
            next_date_fname=rrdf2,
            cache_dir=self.tmp_dir,
        )
        assert len(list(consistency)) == 0

    @mock.patch('rucio.common.dumper.agis_endpoints_data')
    def test_consistency_manual_dark_file(self, mock_get):
        ''' DUMPER '''
        rucio_dump = 'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.filename\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.filename\t2015-09-20 21:22:17\tA\n'
        storage_dump = 'user/someuser/aa/bb/user.someuser.filename\n'
        storage_dump += 'user/someuser/aa/bb/user.someuser.filename2\n'

        rrdf1 = make_temp_file(self.tmp_dir, rucio_dump)
        rrdf2 = make_temp_file(self.tmp_dir, rucio_dump)
        sdf = make_temp_file(self.tmp_dir, storage_dump)

        mock_get.return_value = self.fake_agis_data

        consistency = Consistency.dump(
            'consistency-manual',
            'MOCK_SCRATCHDISK',
            sdf,
            prev_date_fname=rrdf1,
            next_date_fname=rrdf2,
            cache_dir=self.tmp_dir,
        )
        consistency = list(consistency)

        assert len(consistency) == 1
        assert consistency[0].apparent_status == 'DARK'
        assert consistency[0].path == 'user/someuser/aa/bb/user.someuser.filename2'

    @mock.patch('rucio.common.dumper.agis_endpoints_data')
    def test_consistency_manual_multiple_slashes_in_storage_dump_do_not_generate_false_positive(self, mock_get):
        ''' DUMPER '''
        rucio_dump = 'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.filename\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.filename\t2015-09-20 21:22:17\tA\n'
        storage_dump = '/pnfs/example.com/atlas///atlasdatadisk/rucio//user/someuser/aa/bb/user.someuser.filename\n'

        rrdf1 = make_temp_file(self.tmp_dir, rucio_dump)
        rrdf2 = make_temp_file(self.tmp_dir, rucio_dump)
        sdf = make_temp_file(self.tmp_dir, storage_dump)

        mock_get.return_value = self.fake_agis_data

        consistency = Consistency.dump(
            'consistency-manual',
            'MOCK_SCRATCHDISK',
            sdf,
            prev_date_fname=rrdf1,
            next_date_fname=rrdf2,
            cache_dir=self.tmp_dir,
        )
        consistency = list(consistency)

        assert len(consistency) == 0

    @mock.patch('requests.Session.head', side_effect=mocked_requests)
    @mock.patch('requests.Session.get', side_effect=mocked_requests)
    @mock.patch('rucio.common.dumper.agis_endpoints_data')
    def test_consistency(self, mock_dumper_get, mock_request_get, mock_request_head):
        ''' DUMPER '''
        storage_dump = (
            '/pnfs/example.com/atlas///atlasdatadisk/rucio//user/someuser/aa/bb/user.someuser.filename\n'
            '/pnfs/example.com/atlas///atlasdatadisk/rucio//user/someuser/aa/bb/user.someuser.dark\n'
        )
        sd = make_temp_file(self.tmp_dir, storage_dump)

        agisdata = [{
            'name': 'MOCK_SCRATCHDISK',
            'se': 'srm://example.com/',
            'endpoint': 'pnfs/example.com/atlas/atlasdatadisk/',
        }]
        mock_dumper_get.return_value = agisdata
        consistency = Consistency.dump('consistency',
                                       'MOCK_SCRATCHDISK',
                                       storage_dump=sd,
                                       prev_date=datetime(2015, 9, 29),
                                       next_date=datetime(2015, 10, 4),
                                       cache_dir=self.tmp_dir)
        consistency = list(consistency)

        assert len(consistency) == 2
        dark = next(
            entry.path for entry in consistency if entry.apparent_status == 'DARK'
        )
        lost = next(
            entry.path for entry in consistency if entry.apparent_status == 'LOST'
        )
        assert 'user.someuser.dark' in dark
        assert 'user.someuser.lost' in lost

    def test__try_to_advance(self):
        ''' DUMPER '''
        i = iter(['   abc  '])
        assert _try_to_advance(i) == 'abc'
        assert _try_to_advance(i) is None
        assert _try_to_advance(i, 42) == 42

    def test_compare3(self):
        ''' DUMPER '''
        sorted_rdd_1 = sorted(self.case_mixed_rrd_1, key=lambda s: s.split(',')[0])
        sorted_rdd_2 = sorted(self.case_mixed_rrd_2, key=lambda s: s.split(',')[0])
        sorted_sed = sorted(self.case_mixed_sed)

        value = sorted(list(compare3(sorted_rdd_1, sorted_sed, sorted_rdd_2)))
        expected = sorted([
            ('path1', (True, True, True), ('A', 'A')),
            ('path20', (True, True, True), ('U', 'A')),
            ('path01', (True, False, True), ('U', 'U')),
            ('path23', (True, False, False), ('U', None)),
            ('path26', (True, False, True), ('A', 'A')),
            ('path6', (True, False, True), ('A', 'A')),
            ('path66', (False, True, False), (None, None)),
            ('path46', (False, True, False), (None, None)),
            ('pathsda', (False, True, False), (None, None)),
        ])
        assert value == expected

    def test_compare3_file_name_with_comma_in_storage_dump_ATLDDMOPS_4105(self):
        ''' DUMPER '''
        rucio_replica_dump = 'user/mfauccig/8d/46/user.mfauccig.410000.PowhegPythiaEvtGen.DAOD_TOPQ1.e3698_s2608_s2183_r6630_r6264_p2377.v1.log.6466214.000001.log.tgz,A'
        storage_dump = 'user/mdobre/01/6b/user.mdobre.C1C1bkg.WWVBH,nometcut.0711.log.4374089.000029.log.tgz'
        value = list(compare3([rucio_replica_dump], [storage_dump], [rucio_replica_dump]))
        expected = [
            (
                'user/mdobre/01/6b/user.mdobre.C1C1bkg.WWVBH,nometcut.0711.log.4374089.000029.log.tgz',
                (False, True, False),
                (None, None),
            ),
            (
                'user/mfauccig/8d/46/user.mfauccig.410000.PowhegPythiaEvtGen.DAOD_TOPQ1.e3698_s2608_s2183_r6630_r6264_p2377.v1.log.6466214.000001.log.tgz',
                (True, False, True),
                ('A', 'A'),
            ),
        ]
        assert value == expected

    def test_min3_simple_strings(self):
        ''' DUMPER '''
        assert min3('a', 'b', 'c') == 'a'

    def test_min3_repeated_strings(self):
        ''' DUMPER '''
        assert min3('b', 'a', 'a') == 'a'

    def test_min3_parsing_the_strings_is_not_a_responsability_of_this_function(self):
        ''' DUMPER '''
        assert min3('a,b', 'cab', 'b,a') == 'a,b'

    def test_parse_and_filter_file_default_parameters(self):
        ''' DUMPER '''
        fake_data = 'asd\nasda\n'
        path = make_temp_file(self.tmp_dir, fake_data)

        parsed_file = parse_and_filter_file(path, cache_dir=self.tmp_dir)
        with open(parsed_file) as f:
            data = f.read()

        assert fake_data.replace('\n', '\n\n') == data

        os.unlink(path)
        os.unlink(parsed_file)

    def test_parse_and_filter_file_parser_function(self):
        ''' DUMPER '''
        fake_data = 'asd\nasda\n'
        path = make_temp_file(self.tmp_dir, fake_data)

        parsed_file = parse_and_filter_file(path, parser=str.strip, cache_dir=self.tmp_dir)
        with open(parsed_file) as f:
            data = f.read()
        assert fake_data == data

        os.unlink(path)
        os.unlink(parsed_file)

    def test_parse_and_filter_file_filter_function(self):
        ''' DUMPER '''
        fake_data = 'asd\nasda\n'
        path = make_temp_file(self.tmp_dir, fake_data)

        parsed_file = parse_and_filter_file(path, filter_=lambda s: s == 'asd\n', cache_dir=self.tmp_dir)
        with open(parsed_file) as f:
            data = f.read()

        assert 'asd\n\n' == data

        os.unlink(path)
        os.unlink(parsed_file)

    def test_parse_and_filter_file_default_naming(self):
        ''' DUMPER '''
        path = make_temp_file(self.tmp_dir, 'x\n')

        parsed_file = parse_and_filter_file(path, cache_dir=self.tmp_dir)

        assert parsed_file == os.path.join(self.tmp_dir, os.path.basename(path) + '_parsed')

        os.unlink(path)
        os.unlink(parsed_file)

    def test_parse_and_filter_file_prefix_specified(self):
        ''' DUMPER '''
        path = make_temp_file(self.tmp_dir, 'x\n')

        parsed_file = parse_and_filter_file(path, prefix=path + 'X', cache_dir=self.tmp_dir)

        assert parsed_file == path + 'X_parsed'

        os.unlink(path)
        os.unlink(parsed_file)

    def test_parse_and_filter_file_prefix_and_postfix_specified(self):
        ''' DUMPER '''
        path = make_temp_file(self.tmp_dir, 'x\n')

        parsed_file = parse_and_filter_file(path, prefix=path + 'X', postfix='Y', cache_dir=self.tmp_dir)

        assert parsed_file == path + 'X_Y'

        os.unlink(path)
        os.unlink(parsed_file)

    def test_gnu_sort_and_the_current_version_of_python_sort_strings_using_byte_value(self):
        ''' DUMPER '''
        unsorted_data_list = ['z\n', 'a\n', '\xc3\xb1\n']
        unsorted_data = ''.join(unsorted_data_list)
        sorted_data = ''.join(['a\n', 'z\n', '\xc3\xb1\n'])

        path = make_temp_file(self.tmp_dir, unsorted_data)
        sorted_file = gnu_sort(path, cache_dir=self.tmp_dir)

        assertion_msg = ('GNU Sort must sort comparing byte by byte (export '
                         'LC_ALL=C) to be faster and consistent with Python 2.')
        if PY3:
            with open(sorted_file, encoding='utf-8') as f:
                assert f.read() == sorted_data, assertion_msg
        else:
            with open(sorted_file) as f:
                assert f.read() == sorted_data, assertion_msg

        os.unlink(path)
        os.unlink(sorted_file)

        python_sort = ''.join(sorted(unsorted_data_list))
        assertion_msg = ('Current Python interpreter must sort strings '
                         'comparing byte by byte, it is important to use the '
                         'same ordering as the one used with GNU Sort. Note '
                         'Python 3 uses unicode by default.')
        assert python_sort == sorted_data, assertion_msg

    def test_gnu_sort_can_sort_by_field(self):
        ''' DUMPER '''
        unsorted_data = ''.join(['1,z\n', '2,a\n', '3,\xc3\xb1\n'])
        sorted_data = ''.join(['2,a\n', '1,z\n', '3,\xc3\xb1\n'])

        path = make_temp_file(self.tmp_dir, unsorted_data)
        sorted_file = gnu_sort(path, delimiter=',', fieldspec='2', cache_dir=self.tmp_dir)

        if PY3:
            with open(sorted_file, encoding='utf-8') as f:
                assert f.read() == sorted_data
        else:
            with open(sorted_file) as f:
                assert f.read() == sorted_data

        os.unlink(path)
        os.unlink(sorted_file)
