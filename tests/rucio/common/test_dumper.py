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

import bz2
import glob
import gzip
import json
import os
import tempfile
import uuid
from datetime import datetime
from io import StringIO
from unittest.mock import Mock, patch

import pytest
import requests

from rucio.common import config, dumper
from rucio.common.dumper import data_models
from rucio.common.dumper.consistency import Consistency, _try_to_advance, compare3, gnu_sort, min_value, parse_and_filter_file
from rucio.common.dumper.path_parsing import components, remove_prefix
from rucio.tests.common import make_temp_file, mock_open


class TestDumper:
    @pytest.mark.parametrize("code", [2, 3, 500])
    def test_error(self, code):
        with pytest.raises(SystemExit) as excinfo:
            dumper.error('message', code)
        assert excinfo.value.code == code

    @pytest.mark.parametrize("file_config_mock", [
        {"overrides": [('client', 'ca_cert', '/opt/rucio/etc/web/ca.crt')]},
    ], indirect=True)
    def test_cacert_config_exists(self, temp_config_file, file_config_mock):
        with patch('os.path.exists', Mock(return_value=True)):
            assert dumper.cacert_config(config, '.') == '/opt/rucio/etc/web/ca.crt'

    @pytest.mark.parametrize("file_config_mock", [
        {"overrides": [('client', 'ca_cert', '')]},
        {"overrides": [('client', '', '')]},
        {"overrides": [('', '', '')]}],
        ids=[
            "ca_cert_empty",
            "no_option",
            "no_section"
        ],
        indirect=True)
    def test_cacert_config_not_set(self, temp_config_file, file_config_mock):
        with patch('os.path.exists', Mock(return_value=True)):
            assert dumper.cacert_config(config, '.') is False

    def test_cacert_config_no_cfg_found(self):
        with patch('os.path.exists', Mock(return_value=True)):
            assert dumper.cacert_config(config, '.') is False

    @pytest.mark.parametrize("file_config_mock", [
        {"overrides": [('client', 'ca_cert', '/opt/rucio/etc/web/ca.crt')]},
    ], indirect=True)
    def test_cacert_config_set_but_does_not_exist(self, temp_config_file, file_config_mock):
        with patch('os.path.exists', Mock(return_value=False)):
            assert dumper.cacert_config(config, '.') is False

    def test_smart_open_plaintext(self, tmp_path):
        file_name = str(uuid.uuid4())
        full_path = tmp_path / file_name
        file_content = str(uuid.uuid4())
        full_path.write_text(file_content, encoding="utf-8")

        opened_file = dumper.smart_open(full_path)
        assert opened_file.name == str(full_path)
        assert opened_file.read() == file_content

    def test_smart_open_gzip(self, tmp_path):
        file_name = str(uuid.uuid4())
        full_path = tmp_path / file_name
        file_content_uncompressed = str(uuid.uuid4())
        file_content = gzip.compress(bytes(file_content_uncompressed, 'utf-8'))
        full_path.write_bytes(file_content)

        opened_file = dumper.smart_open(full_path)
        opened_file_content = opened_file.read()
        assert opened_file_content == file_content_uncompressed

    def test_smart_open_bz2(self, tmp_path):
        file_name = str(uuid.uuid4())
        full_path = tmp_path / file_name
        file_content_uncompressed = str(uuid.uuid4())
        compressor = bz2.BZ2Compressor()
        file_content = compressor.compress(str.encode(file_content_uncompressed)) + compressor.flush()
        full_path.write_bytes(file_content)

        opened_file = dumper.smart_open(full_path)
        assert opened_file.read() == file_content_uncompressed

    @pytest.mark.parametrize("in_string", [
        "2015-03-10 14:00:35",
        "2015-03-10T14:00:35.5",
        "2015-03-10T14:00:35.500",
    ], ids=[
        "seconds",
        "tenths",
        "milliseconds",
    ])
    def test_to_datetime(self, in_string):
        assert dumper.to_datetime(in_string) == datetime(2015, 3, 10, 14, 0, 35)

    def test_temp_file_with_final_name_creates_a_tmp_file_and_then_removes_it(self, tmp_path):
        final_name = tempfile.mktemp()
        with dumper.temp_file(tmp_path, final_name) as (_, temp_file_path):
            temp_file_path = os.path.join(tmp_path, temp_file_path)
            assert os.path.exists(temp_file_path)
            assert not os.path.exists(final_name)

        assert os.path.exists(final_name)
        assert not os.path.exists(temp_file_path)

    def test_temp_file_with_final_name_creates_a_tmp_file_and_keeps_it(self, tmp_path):
        with dumper.temp_file(tmp_path) as (_, temp_file_path):
            temp_file_path = os.path.join(tmp_path, temp_file_path)
            assert os.path.exists(temp_file_path)

        assert os.path.exists(temp_file_path)

    def test_temp_file_cleanup_on_exception(self, tmp_path):
        try:
            with dumper.temp_file(tmp_path) as (_, temp_file_path):
                tmp_path = os.path.join(tmp_path, temp_file_path)
                raise Exception
        except Exception:
            assert not os.path.exists(temp_file_path)

    def test_temp_file_cleanup_on_exception_with_final_name(self, tmp_path):
        final_name = tempfile.mktemp()
        try:
            with dumper.temp_file(tmp_path, final_name) as (_, temp_file_patb):
                temp_file_patb = os.path.join(tmp_path, temp_file_patb)
                raise Exception
        except Exception:
            assert not os.path.exists(temp_file_patb)
            assert not os.path.exists(final_name)

    def test_ddmendpoint_url_builds_url_from_ddmendpoint_preferred_protocol(self, rse_protocol):
        with patch('rucio.common.dumper.ddmendpoint_preferred_protocol', Mock(return_value=rse_protocol)):
            assert dumper.ddmendpoint_url('SOMEENDPOINT') == 'root://example.com:1094//defdatadisk/'

    def test_ddmendpoint_url_fails_on_unexistent_entry(self):
        with patch('rucio.common.dumper.ddmendpoint_preferred_protocol', Mock(side_effect=StopIteration())):
            with pytest.raises(StopIteration):
                dumper.ddmendpoint_url('SOMEENDPOINT')

    def test_http_download_to_file_without_session_uses_requests_get(self):
        with patch('requests.get') as mock_get:
            response = requests.Response()
            response.status_code = 200
            iter_content_mock = Mock()
            iter_content_mock.return_value = ['content']
            response.iter_content = iter_content_mock
            mock_get.return_value = response
            stringio = StringIO()

            dumper.http_download_to_file('http://example.com', stringio)

            stringio.seek(0)
            assert stringio.read() == 'content'

    def test_http_download_to_file_with_session(self):
        response = requests.Response()
        response.status_code = 200
        iter_content_mock = Mock()
        iter_content_mock.return_value = ['content']
        response.iter_content = iter_content_mock

        stringio = StringIO()
        session = requests.Session()
        session_get_mock = Mock()
        session_get_mock.return_value = response
        session.get = session_get_mock

        dumper.http_download_to_file('http://example.com', stringio, session)
        stringio.seek(0)
        assert stringio.read() == 'content'

    def test_http_download_to_file_throws_exception_on_error(self):
        response = requests.Response()
        response.status_code = 404
        iter_content_mock = Mock()
        iter_content_mock.return_value = ['content']
        response.iter_content = iter_content_mock

        stringio = StringIO()
        session = requests.Session()
        session_get_mock = Mock()
        session_get_mock.return_value = response
        session.get = session_get_mock

        with pytest.raises(dumper.HTTPDownloadFailed):
            dumper.http_download_to_file('http://example.com', stringio, session)

    def test_http_download_creates_file_with_content(self):
        response = requests.Response()
        response.status_code = 200
        iter_content_mock = Mock()
        iter_content_mock.return_value = ['abc']
        response.iter_content = iter_content_mock

        with patch('requests.get') as mock_get:
            stringio = StringIO()
            mock_get.return_value = response

            with mock_open(dumper, stringio):
                dumper.http_download('http://example.com', 'filename')

            stringio.seek(0)
            assert stringio.read() == 'abc'


class TestDumperDataModel:
    VALID_DUMP = '''\
CERN-PROD_DATADISK	data12_8TeV	AOD.04972924._000218.pool.root.1	1045a406	127508132	2015-03-10 14:00:24	data12_8TeV/5b/ea/AOD.04972924._000218.pool.root.1	2015-03-15 08:33:09
CERN-PROD_DATADISK	data12_8TeV	ESD.04972924._000218.pool.root.1	a6152bbc	2498690922	2015-03-10 14:00:24	 data12_8TeV/7a/a6/ESD.04972924._000218.pool.root.1	2015-03-10 14:00:35
'''
    VALID_DUMP_NO_EOL = '''\
CERN-PROD_DATADISK	data12_8TeV	AOD.04972924._000218.pool.root.1	1045a406	127508132	2015-03-10 14:00:24	data12_8TeV/5b/ea/AOD.04972924._000218.pool.root.1	2015-03-15 08:33:09
CERN-PROD_DATADISK	data12_8TeV	ESD.04972924._000218.pool.root.1	a6152bbc	2498690922	2015-03-10 14:00:24	 data12_8TeV/7a/a6/ESD.04972924._000218.pool.root.1	2015-03-10 14:00:35'''

    DATE_SECONDS = "2015-03-10 14:00:35"
    DATE_TENTHS = "2015-03-10T14:00:35.5"

    class _DataConcrete(data_models.DataModel):
        URI = 'data_concrete'
        SCHEMA = (
            ('a', str),
            ('b', str),
            ('c', str),
            ('d', str),
            ('e', int),
            ('f', dumper.to_datetime),
            ('g', str),
            ('h', dumper.to_datetime),
        )

    data_list = [
        'aa',
        'bb',
        'cc',
        'dd',
        '42',
        DATE_SECONDS,
        'ee',
        DATE_TENTHS,
    ]
    data_concrete = _DataConcrete(*data_list)

    def test_field_names(self):
        assert self._DataConcrete.get_fieldnames() == list('abcdefgh')

    def test_pprint(self):
        expected_format = ''.join([
            'a: aa\n',
            'b: bb\n',
            'c: cc\n',
            'd: dd\n',
            'e: 42\n',
            'f: 2015-03-10 14:00:35\n',
            'g: ee\n',
            'h: 2015-03-10 14:00:35\n',
        ])
        assert self.data_concrete.pprint() == expected_format

    def test_data_models_are_indexable(self):
        assert self.data_concrete[0] == 'aa'

    def test_csv_header(self):
        assert self._DataConcrete.csv_header() == 'a,b,c,d,e,f,g,h'

    def test_formated_fields(self):
        assert self.data_concrete.formated_fields(print_fields=('a', 'e')) == ['aa', '42']

    def test_csv(self):
        assert self.data_concrete.csv(fields=('a', 'e')) == 'aa,42'

    def test_csv_default_formatting(self):
        assert self.data_concrete.csv() == 'aa,bb,cc,dd,42,2015-03-10T14:00:35,ee,2015-03-10T14:00:35'

    def test_each(self):
        tsv_dump = ['\t'.join(self.data_list)]
        records = list(self._DataConcrete.each(tsv_dump))
        assert len(records) == 1
        assert records[0].a == 'aa'

    def test_each_with_filter(self):
        tsv_dump = ['\t'.join(self.data_list)]
        tsv_dump.append(tsv_dump[0].replace('aa', 'xx'))
        records = list(self._DataConcrete.each(tsv_dump, filter_=lambda x: x.a == 'xx'))
        assert len(records) == 1
        assert records[0].a == 'xx'

    def test_each_without_eol(self):
        dump_file = self.VALID_DUMP.splitlines(True)
        assert 2 == len(list(self._DataConcrete.each(dump_file)))

    def test_parse_line_valid_line(self):
        for line in self.VALID_DUMP.splitlines(True):
            self._DataConcrete.parse_line(line)

    def test_wrong_number_of_fields(self):
        with pytest.raises(TypeError):
            self._DataConcrete.parse_line('asdasd\taasdsa\n')

    def test_wrong_format_of_fields(self):
        with pytest.raises(ValueError):
            self._DataConcrete.parse_line('a\ta\ta\ta\ta\ta\ta\ta\n')

    @patch('requests.Session.get')
    @patch('requests.Session.head')
    def test_download_with_fixed_date(self, mock_request_head, mock_request_get, tmp_path):
        response = requests.Response()
        response.status_code = 200
        iter_content_mock = Mock()
        iter_content_mock.return_value = ['content']
        response.iter_content = iter_content_mock

        mock_request_get.return_value = response
        mock_request_head.return_value = response

        self._DataConcrete.download(
            'SOMEENDPOINT',
            date=datetime.strptime('01-01-2015', '%d-%m-%Y'),
            cache_dir=tmp_path,
        )
        downloaded = glob.glob(
            os.path.join(
                tmp_path,
                '_dataconcrete_SOMEENDPOINT_01-01-2015_*',
            )
        )
        assert len(downloaded) == 1
        with open(downloaded[0]) as fil:
            assert fil.read() == 'content'

    @patch('requests.Session.get')
    @patch('requests.Session.head')
    def test_download_empty_date(self, mock_request_head, mock_request_get, tmp_path):
        """ test_download_with_date_latest_should_make_a_head_query_with_empty_date_and_name_the_output_file_according_to_the_content_disposition_header """
        response = requests.Response()
        response.status_code = 200
        response.headers['content-disposition'] = 'filename=01-01-2015'
        iter_content_mock = Mock()
        iter_content_mock.return_value = ['content']
        response.iter_content = iter_content_mock

        mock_request_get.return_value = response
        mock_request_head.return_value = response

        self._DataConcrete.download(
            'SOMEENDPOINT',
            date='latest',
            cache_dir=tmp_path,
        )
        downloaded = glob.glob(
            os.path.join(
                tmp_path,
                '_dataconcrete_SOMEENDPOINT_01-01-2015_*',
            )
        )
        assert len(downloaded) == 1
        with open(downloaded[0]) as fil:
            assert fil.read() == 'content'

    @patch('requests.Session.get')
    @patch('requests.Session.head')
    def test_raises_exception(self, mock_request_head, mock_request_get, tmp_path):
        response = requests.Response()
        response.status_code = 500
        mock_request_get.return_value = response
        mock_request_head.return_value = response

        with pytest.raises(dumper.HTTPDownloadFailed):
            self._DataConcrete.download(
                'SOMEENDPOINT',
                date=datetime.strptime('01-01-2015', '%d-%m-%Y'),
                cache_dir=tmp_path,
            )


class TestDumperCompleteDataset:

    def test_creation_with_7_parameters(self):
        complete_dataset = data_models.CompleteDataset(
            'RSE',
            'scope',
            'name',
            'owner',
            '42',
            '2015-01-01 23:00:00',
            '2015-01-01 23:00:00',
        )
        assert complete_dataset.state is None

    def test_creation_with_8_parameters(self):
        complete_dataset = data_models.CompleteDataset(
            'RSE',
            'scope',
            'name',
            'owner',
            '42',
            '2015-01-01 23:00:00',
            '2015-01-01 23:00:00',
            'A',
        )
        assert complete_dataset.state == 'A'

    def test_empty_size_is_none(self):
        complete_dataset = data_models.CompleteDataset(
            'RSE',
            'scope',
            'name',
            'owner',
            '',
            '2015-01-01 23:00:00',
            '2015-01-01 23:00:00',
            'A',
        )
        assert complete_dataset.size is None


class TestDumperReplica:

    def test_replica_with_8_parameters(self):
        replica = data_models.Replica(
            'RSE',
            'scope',
            'name',
            'checksum',
            '42',
            '2015-01-01 23:00:00',
            'path',
            '2015-01-01 23:00:00',
        )
        assert replica.state == 'None'

    def test_replica_with_9_parameters(self):
        replica = data_models.Replica(
            'RSE',
            'scope',
            'name',
            'checksum',
            '42',
            '2015-01-01 23:00:00',
            'path',
            '2015-01-01 23:00:00',
            'A',
        )
        assert replica.state == 'A'


class TestDumperFilter:

    replica_1 = data_models.Replica(
        'RSE',
        'scope',
        'name',
        'checksum',
        '42',
        '2015-01-01 23:00:00',
        'path',
        '2015-01-01 23:00:00',
        'A',
    )
    replica_2 = data_models.Replica(
        'RSE',
        'scope',
        'name',
        'checksum',
        '42',
        '2015-01-01 23:00:00',
        'path',
        '2015-01-01 23:00:00',
        'U',
    )

    def test_simple_condition(self):
        filter_ = data_models.Filter('state=A', data_models.Replica)
        assert filter_.match(self.replica_1)
        assert not filter_.match(self.replica_2)

    def test_multiple_conditions(self):
        filter_ = data_models.Filter('size=42,state=A', data_models.Replica)
        assert filter_.match(self.replica_1)
        assert not filter_.match(self.replica_2)


class TestDumperPathParsing:
    @pytest.mark.parametrize("input_path, expected_output", [
        (['a', 'b', 'c', 'd', 'e', 'f'], ['e', 'f']),
        (['c', 'd', 'e', 'f'], ['e', 'f']),
        (['e', 'f', 'g'], ['e', 'f', 'g']),
        (['c', 'a', 'e', 'f'], ['c', 'a', 'e', 'f']),
        (['d', 'a', 'e'], ['a', 'e']),
        (['a', 'b', 'c', 'd'], []),
        (['a', 'b', 'c', 'd'], []),
    ], ids=[
        "full",
        "relative",
        "exclusive",
        "mixed",
        "mixed2",
        "prefix",
        "empty_path",
    ])
    def test_remove_prefix(self, input_path, expected_output):
        prefix = ['a', 'b', 'c', 'd']
        assert remove_prefix(prefix, input_path) == expected_output

    @pytest.mark.parametrize("expected_output", [
        ('rucio/group10/perf-jets/02/1a/group10.perf-jets.data12_8TeV.periodI.physics_HadDelayed.jmr.2015.01.29.v01.log.4770484.000565.log.tgz'),
        ('rucio/user/zxi/fd/73/user.zxi.361100.PowhegPythia8EvtGen.DAOD_TOPQ1.e3601_s2576_s2132_r6630_r6264_p2363.08-12-15.log.6249615.000015.log.tgz'),
        ('rucio/group/det-ibl/00/5d/group.det-ibl.6044653.BTAGSTREAM._000014.root'),
        ('SAM/testfile17-GET-ATLASSCRATCHDISK'),
    ], ids=[
        "normal_path",
        "user_path",
        "group_path",
        "sam_path",
    ])
    def test_real_sample(self, expected_output):
        prefix = components('/pnfs/grid.sara.nl/data/atlas/atlasscratchdisk/')
        input = prefix + components(expected_output)
        assert '/'.join(remove_prefix(prefix, input)) == expected_output

    def test_remove_prefix_empty_prefix(self):
        prefix = []
        path = ['a', 'b', 'c', 'd']
        assert remove_prefix(prefix, path) == path


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


class TestDumperConsistency:
    @patch('rucio.common.dumper.ddmendpoint_preferred_protocol')
    def test_consistency_manual_correct_file_default_args(self, mock_get, tmp_path, rse_protocol):
        rucio_dump = 'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.filename\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.filename\t2015-09-20 21:22:17\tA\n'
        storage_dump = 'user/someuser/aa/bb/user.someuser.filename\n'

        rrdf1 = make_temp_file(tmp_path, rucio_dump)
        rrdf2 = make_temp_file(tmp_path, rucio_dump)
        sdf = make_temp_file(tmp_path, storage_dump)

        mock_get.return_value = rse_protocol
        consistency = Consistency.dump(
            'consistency-manual',
            'MOCK_SCRATCHDISK',
            sdf,
            prev_date_fname=rrdf1,
            next_date_fname=rrdf2,
            cache_dir=tmp_path,
        )
        assert len(list(consistency)) == 0

    @patch('rucio.common.dumper.ddmendpoint_preferred_protocol')
    def test_consistency_manual_lost_file(self, mock_get, tmp_path, rse_protocol):
        rucio_dump = 'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.filename\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.filename\t2015-09-20 21:22:17\tA\n'
        rucio_dump += 'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.filename2\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.filename2\t2015-09-20 21:22:17\tA\n'
        storage_dump = 'user/someuser/aa/bb/user.someuser.filename\n'

        rrdf1 = make_temp_file(tmp_path, rucio_dump)
        rrdf2 = make_temp_file(tmp_path, rucio_dump)
        sdf = make_temp_file(tmp_path, storage_dump)

        mock_get.return_value = rse_protocol

        consistency = Consistency.dump(
            'consistency-manual',
            'MOCK_SCRATCHDISK',
            sdf,
            prev_date_fname=rrdf1,
            next_date_fname=rrdf2,
            cache_dir=tmp_path,
        )
        consistency = list(consistency)
        assert len(consistency) == 1
        assert consistency[0].apparent_status == 'LOST'
        assert consistency[0].path == 'user/someuser/aa/bb/user.someuser.filename2'

    @patch('rucio.common.dumper.ddmendpoint_preferred_protocol')
    def test_consistency_manual_transient_file_is_not_lost(self, mock_get, tmp_path, rse_protocol):
        rucio_dump = 'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.filename\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.filename\t2015-09-20 21:22:17\tA\n'
        rucio_dump_1 = rucio_dump + 'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.filename2\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.filename2\t2015-09-20 21:22:17\tU\n'
        rucio_dump_2 = rucio_dump + 'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.filename2\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.filename2\t2015-09-20 21:22:17\tA\n'
        storage_dump = 'user/someuser/aa/bb/user.someuser.filename\n'

        rrdf1 = make_temp_file(tmp_path, rucio_dump_1)
        rrdf2 = make_temp_file(tmp_path, rucio_dump_2)
        sdf = make_temp_file(tmp_path, storage_dump)

        mock_get.return_value = rse_protocol

        consistency = Consistency.dump(
            'consistency-manual',
            'MOCK_SCRATCHDISK',
            sdf,
            prev_date_fname=rrdf1,
            next_date_fname=rrdf2,
            cache_dir=tmp_path,
        )
        assert len(list(consistency)) == 0

    @patch('rucio.common.dumper.ddmendpoint_preferred_protocol')
    def test_consistency_manual_dark_file(self, mock_get, tmp_path, rse_protocol):
        rucio_dump = 'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.filename\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.filename\t2015-09-20 21:22:17\tA\n'
        storage_dump = 'user/someuser/aa/bb/user.someuser.filename\n'
        storage_dump += 'user/someuser/aa/bb/user.someuser.filename2\n'

        rrdf1 = make_temp_file(tmp_path, rucio_dump)
        rrdf2 = make_temp_file(tmp_path, rucio_dump)
        sdf = make_temp_file(tmp_path, storage_dump)

        mock_get.return_value = rse_protocol

        consistency = Consistency.dump(
            'consistency-manual',
            'MOCK_SCRATCHDISK',
            sdf,
            prev_date_fname=rrdf1,
            next_date_fname=rrdf2,
            cache_dir=tmp_path,
        )
        consistency = list(consistency)

        assert len(consistency) == 1
        assert consistency[0].apparent_status == 'DARK'
        assert consistency[0].path == 'user/someuser/aa/bb/user.someuser.filename2'

    @patch('rucio.common.dumper.ddmendpoint_preferred_protocol')
    def test_consistency_manual_multiple_slashes_in_storage_dump_do_not_generate_false_positive(self, mock_get, tmp_path, rse_protocol):
        rucio_dump = 'MOCK_SCRATCHDISK\tuser.someuser\tuser.someuser.filename\t19028d77\t189468\t2015-09-20 21:22:04\tuser/someuser/aa/bb/user.someuser.filename\t2015-09-20 21:22:17\tA\n'
        storage_dump = '/example.com:1094////defdatadisk/rucio//user/someuser/aa/bb/user.someuser.filename\n'

        rrdf1 = make_temp_file(tmp_path, rucio_dump)
        rrdf2 = make_temp_file(tmp_path, rucio_dump)
        sdf = make_temp_file(tmp_path, storage_dump)

        mock_get.return_value = rse_protocol

        consistency = Consistency.dump(
            'consistency-manual',
            'MOCK_SCRATCHDISK',
            sdf,
            prev_date_fname=rrdf1,
            next_date_fname=rrdf2,
            cache_dir=tmp_path,
        )
        consistency = list(consistency)
        assert len(consistency) == 0

    @patch('requests.Session.head', side_effect=mocked_requests)
    @patch('requests.Session.get', side_effect=mocked_requests)
    def test_consistency(self, mock_request_get, mock_request_head, tmp_path, rse_protocol):
        storage_dump = (
            '//defdatadisk/rucio/user/someuser/aa/bb/user.someuser.filename\n'
            '//defdatadisk/rucio/user/someuser/aa/bb/user.someuser.dark\n'
        )
        sd = make_temp_file(tmp_path, storage_dump)

        with patch('rucio.common.dumper.ddmendpoint_preferred_protocol', Mock(return_value=rse_protocol)):
            consistency = Consistency.dump('consistency',
                                           'MOCK_SCRATCHDISK',
                                           storage_dump=sd,
                                           prev_date=datetime(2015, 9, 29),
                                           next_date=datetime(2015, 10, 4),
                                           cache_dir=tmp_path)
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
        i = iter(['   abc  '])
        assert _try_to_advance(i) == 'abc'
        assert _try_to_advance(i) is None
        assert _try_to_advance(i, 42) == 42

    def test_compare3(self):
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
        sorted_rdd_1 = sorted(case_mixed_rrd_1, key=lambda s: s.split(',')[0])
        sorted_rdd_2 = sorted(case_mixed_rrd_2, key=lambda s: s.split(',')[0])
        sorted_sed = sorted(case_mixed_sed)

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

    def test_compare3_file_name_with_comma_in_storage_dump(self):
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

    def test_min_value_simple_strings(self):
        assert min_value('a', 'b', 'c') == 'a'

    def test_min_value_repeated_strings(self):
        assert min_value('b', 'a', 'a') == 'a'

    def test_min_value_parsing_the_strings_is_not_a_responsability_of_this_function(self):
        assert min_value('a,b', 'cab', 'b,a') == 'a,b'

    def test_parse_and_filter_file_default_parameters(self, tmp_path):
        fake_data = 'asd\nasda\n'
        path = make_temp_file(tmp_path, fake_data)

        parsed_file = parse_and_filter_file(path, cache_dir=tmp_path)
        with open(parsed_file) as f:
            data = f.read()

        assert fake_data.replace('\n', '\n\n') == data

        os.unlink(path)
        os.unlink(parsed_file)

    def test_parse_and_filter_file_parser_function(self, tmp_path):
        fake_data = 'asd\nasda\n'
        path = make_temp_file(tmp_path, fake_data)

        parsed_file = parse_and_filter_file(path, parser=str.strip, cache_dir=tmp_path)
        with open(parsed_file) as f:
            data = f.read()
        assert fake_data == data

        os.unlink(path)
        os.unlink(parsed_file)

    def test_parse_and_filter_file_filter_function(self, tmp_path):
        fake_data = 'asd\nasda\n'
        path = make_temp_file(tmp_path, fake_data)

        parsed_file = parse_and_filter_file(path, filter_=lambda s: s == 'asd\n', cache_dir=tmp_path)
        with open(parsed_file) as f:
            data = f.read()

        assert 'asd\n\n' == data

        os.unlink(path)
        os.unlink(parsed_file)

    def test_parse_and_filter_file_default_naming(self, tmp_path):
        path = make_temp_file(tmp_path, 'x\n')

        parsed_file = parse_and_filter_file(path, cache_dir=tmp_path)

        assert parsed_file == os.path.join(tmp_path, os.path.basename(path) + '_parsed')

        os.unlink(path)
        os.unlink(parsed_file)

    def test_parse_and_filter_file_prefix_specified(self, tmp_path):
        path = make_temp_file(tmp_path, 'x\n')

        parsed_file = parse_and_filter_file(path, prefix=path + 'X', cache_dir=tmp_path)

        assert parsed_file == path + 'X_parsed'

        os.unlink(path)
        os.unlink(parsed_file)

    def test_parse_and_filter_file_prefix_and_postfix_specified(self, tmp_path):
        path = make_temp_file(tmp_path, 'x\n')

        parsed_file = parse_and_filter_file(path, prefix=path + 'X', postfix='Y', cache_dir=tmp_path)

        assert parsed_file == path + 'X_Y'

        os.unlink(path)
        os.unlink(parsed_file)

    def test_gnu_sort_and_the_current_version_of_python_sort_strings_using_byte_value(self, tmp_path):
        unsorted_data_list = ['z\n', 'a\n', '\xc3\xb1\n']
        unsorted_data = ''.join(unsorted_data_list)
        sorted_data = ''.join(['a\n', 'z\n', '\xc3\xb1\n'])

        path = make_temp_file(tmp_path, unsorted_data)
        sorted_file = gnu_sort(path, cache_dir=tmp_path)

        assertion_msg = ('GNU Sort must sort comparing byte by byte (export '
                         'LC_ALL=C) to be faster and consistent with Python 2.')
        with open(sorted_file, encoding='utf-8') as f:
            assert f.read() == sorted_data, assertion_msg

        os.unlink(path)
        os.unlink(sorted_file)

        python_sort = ''.join(sorted(unsorted_data_list))
        assertion_msg = ('Current Python interpreter must sort strings '
                         'comparing byte by byte, it is important to use the '
                         'same ordering as the one used with GNU Sort. Note '
                         'Python 3 uses unicode by default.')
        assert python_sort == sorted_data, assertion_msg

    def test_gnu_sort_can_sort_by_field(self, tmp_path):
        unsorted_data = ''.join(['1,z\n', '2,a\n', '3,\xc3\xb1\n'])
        sorted_data = ''.join(['2,a\n', '1,z\n', '3,\xc3\xb1\n'])

        path = make_temp_file(tmp_path, unsorted_data)
        sorted_file = gnu_sort(path, delimiter=',', fieldspec='2', cache_dir=tmp_path)

        with open(sorted_file, encoding='utf-8') as f:
            assert f.read() == sorted_data

        os.unlink(path)
        os.unlink(sorted_file)
