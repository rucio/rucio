# -*- coding: utf-8 -*-
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
# - Fernando López <felopez@cern.ch>, 2015
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import glob
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime

import pytest
import requests

from rucio.common import dumper
from rucio.common.dumper import data_models

if sys.version_info >= (3, 3):
    from unittest import mock
else:
    import mock


def mocked_requests_head(*args, **kwargs):
    response = requests.Response()
    response.status_code = 200
    response._content = 'content'
    response.headers['content-disposition'] = 'filename=01-01-2015'
    response.iter_content = lambda _: [response._content]

    assert args[0] == 'https://rucio-hadoop.cern.ch/data_concrete?rse=SOMEENDPOINT'
    return response


class TestDataModel(unittest.TestCase):
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

    def setUp(self):
        self.data_list = [
            'aa',
            'bb',
            'cc',
            'dd',
            '42',
            self.DATE_SECONDS,
            'ee',
            self.DATE_TENTHS,
        ]
        self.data_concrete = self._DataConcrete(*self.data_list)
        self.tmp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)

    def test_field_names(self):
        """ test field names """
        assert self._DataConcrete.get_fieldnames() == list('abcdefgh')

    def test_pprint(self):
        """ Testint pprint """
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
        """ test data models are indexable """
        assert self.data_concrete[0] == 'aa'

    def test_csv_header(self):
        """ test csv header """
        assert self._DataConcrete.csv_header() == 'a,b,c,d,e,f,g,h'

    def test_formated_fields(self):
        """ test formated fields """
        assert self.data_concrete.formated_fields(print_fields=('a', 'e')) == ['aa', '42']

    def test_csv(self):
        """ test csv """
        assert self.data_concrete.csv(fields=('a', 'e')) == 'aa,42'

    def test_csv_default_formatting(self):
        """ test csv default formatting"""
        assert self.data_concrete.csv() == 'aa,bb,cc,dd,42,2015-03-10T14:00:35,ee,2015-03-10T14:00:35'

    def test_each(self):
        """ test each"""
        tsv_dump = ['\t'.join(self.data_list)]
        records = list(self._DataConcrete.each(tsv_dump))
        assert len(records) == 1
        assert records[0].a == 'aa'

    def test_each_with_filter(self):
        """ test each with filter"""
        tsv_dump = ['\t'.join(self.data_list)]
        tsv_dump.append(tsv_dump[0].replace('aa', 'xx'))
        records = list(self._DataConcrete.each(tsv_dump, filter_=lambda x: x.a == 'xx'))
        assert len(records) == 1
        assert records[0].a == 'xx'

    def test_each_without_eol(self):
        """ test each without eol """
        dump_file = self.VALID_DUMP.splitlines(True)
        assert 2 == len(list(self._DataConcrete.each(dump_file)))

    def test_parse_line_valid_line(self):
        """ test parse line valid line """
        for line in self.VALID_DUMP.splitlines(True):
            self._DataConcrete.parse_line(line)

    def test_wrong_number_of_fields(self):
        """ test wrong number of fields """
        with pytest.raises(TypeError):
            self._DataConcrete.parse_line('asdasd\taasdsa\n')

    def test_wrong_format_of_fields(self):
        """ test wrong format of fields """
        with pytest.raises(ValueError):
            self._DataConcrete.parse_line('a\ta\ta\ta\ta\ta\ta\ta\n')

    @mock.patch('requests.Session.get')
    @mock.patch('requests.Session.head')
    def test_download_with_fixed_date(self, mock_request_head, mock_request_get):
        """ test download with fixed date"""
        response = requests.Response()
        response.status_code = 200
        response._content = 'content'
        response.iter_content = lambda _: [response._content]
        mock_request_get.return_value = response
        mock_request_head.return_value = response

        self._DataConcrete.download(
            'SOMEENDPOINT',
            date=datetime.strptime('01-01-2015', '%d-%m-%Y'),
            cache_dir=self.tmp_dir,
        )
        downloaded = glob.glob(
            os.path.join(
                self.tmp_dir,
                '_dataconcrete_SOMEENDPOINT_01-01-2015_*',
            )
        )
        assert len(downloaded) == 1
        with open(downloaded[0]) as fil:
            assert fil.read() == 'content'

    @mock.patch('requests.Session.get')
    @mock.patch('requests.Session.head', side_effect=mocked_requests_head)
    def test_download_empty_date(self, mock_request_head, mock_request_get):
        """ test_download_with_date_latest_should_make_a_head_query_with_empty_date_and_name_the_output_file_according_to_the_content_disposition_header """
        response = requests.Response()
        response.status_code = 200
        response._content = 'content'
        response.headers['content-disposition'] = 'filename=01-01-2015'
        response.iter_content = lambda _: [response._content]

        mock_request_get.return_value = response

        self._DataConcrete.download(
            'SOMEENDPOINT',
            date='latest',
            cache_dir=self.tmp_dir,
        )
        downloaded = glob.glob(
            os.path.join(
                self.tmp_dir,
                '_dataconcrete_SOMEENDPOINT_01-01-2015_*',
            )
        )
        assert len(downloaded) == 1
        with open(downloaded[0]) as fil:
            assert fil.read() == 'content'

    @mock.patch('requests.Session.get')
    @mock.patch('requests.Session.head')
    def test_raises_exception(self, mock_session_head, mock_session_get):
        """ test raise exception """
        response = requests.Response()
        response.status_code = 500
        mock_session_get.return_value = response
        mock_session_head.return_value = response

        with pytest.raises(dumper.HTTPDownloadFailed):
            self._DataConcrete.download(
                'SOMEENDPOINT',
                date=datetime.strptime('01-01-2015', '%d-%m-%Y'),
                cache_dir=self.tmp_dir,
            )


class TestCompleteDataset(object):

    @staticmethod
    def test_creation_with_7_parameters():
        """ test ceation with 7 parameters """
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

    @staticmethod
    def test_creation_with_8_parameters():
        """ test creation with 8 parameters """
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

    @staticmethod
    def test_empty_size_is_():
        """ test empty size """
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
        assert complete_dataset.size is None  # pylint: disable=no-member


class TestReplica(object):

    @staticmethod
    def test_replica_with_8_parameters():
        """ test replica with 8 parameters """
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
        assert replica.state == 'None'  # pylint: disable=no-member

    @staticmethod
    def test_replica_with_9_parameters():
        """ test replica with 9 parameters """
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
        assert replica.state == 'A'  # pylint: disable=no-member


class TestFilter(unittest.TestCase):

    def setUp(self):
        self.replica_1 = data_models.Replica(
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
        self.replica_2 = data_models.Replica(
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
        """ test simple condition """
        filter_ = data_models.Filter('state=A', data_models.Replica)
        assert filter_.match(self.replica_1)
        assert not filter_.match(self.replica_2)

    def test_multiple_conditions(self):
        """ test multiple conditions """
        filter_ = data_models.Filter('size=42,state=A', data_models.Replica)
        assert filter_.match(self.replica_1)
        assert not filter_.match(self.replica_2)
