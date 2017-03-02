# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Fernando Lopez, <felopez@cern.ch>, 2015
# - Martin Barisits, <martin.barisits@cern.ch>, 2017

import glob
import shutil
import os
import tempfile
from datetime import datetime
import requests


from nose.tools import eq_
from nose.tools import ok_
from nose.tools import raises
from rucio.common import dumper
from rucio.common.dumper import data_models
from rucio.tests.common import stubbed


class TestDataModel(object):
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

    def teardown(self):
        shutil.rmtree(self.tmp_dir)

    def test_field_names(self):
        """ test field names """
        eq_(self._DataConcrete.get_fieldnames(), list('abcdefgh'))

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
        eq_(self.data_concrete.pprint(), expected_format, self.data_concrete.pprint())

    def test_data_models_are_indexable(self):
        """ test data models are indexable """
        eq_(self.data_concrete[0], 'aa')

    def test_csv_header(self):
        """ test csv header """
        eq_(self._DataConcrete.csv_header(), 'a,b,c,d,e,f,g,h')

    def test_formated_fields(self):
        """ test formated fields """
        eq_(self.data_concrete.formated_fields(print_fields=('a', 'e')), ['aa', '42'])

    def test_csv(self):
        """ test csv """
        eq_(self.data_concrete.csv(fields=('a', 'e')), 'aa,42')

    def test_csv_default_formatting(self):
        """ test csv default formatting"""
        eq_(
            self.data_concrete.csv(),
            'aa,bb,cc,dd,42,2015-03-10T14:00:35,ee,2015-03-10T14:00:35'
        )

    def test_each(self):
        """ test each"""
        tsv_dump = ['\t'.join(self.data_list)]
        records = list(self._DataConcrete.each(tsv_dump))
        eq_(len(records), 1)
        eq_(records[0].a, 'aa')

    def test_each_with_filter(self):
        """ test each with filter"""
        tsv_dump = ['\t'.join(self.data_list)]
        tsv_dump.append(tsv_dump[0].replace('aa', 'xx'))
        records = list(self._DataConcrete.each(tsv_dump, filter_=lambda x: x.a == 'xx'))
        eq_(len(records), 1)
        eq_(records[0].a, 'xx')

    def test_each_without_eol(self):
        """ test each without eol """
        dump_file = self.VALID_DUMP.splitlines(True)
        eq_(
            2,
            len(list(self._DataConcrete.each(dump_file))),
        )

    def test_parse_line_valid_line(self):
        """ test parse line valid line """
        for line in self.VALID_DUMP.splitlines(True):
            self._DataConcrete.parse_line(line)

    @raises(TypeError)
    def test_wrong_number_of_fields(self):
        """ test wrong number of fields """
        self._DataConcrete.parse_line('asdasd\taasdsa\n')

    @raises(ValueError)
    def test_wrong_format_of_fields(self):
        """ test wrong format of fields """
        self._DataConcrete.parse_line('a\ta\ta\ta\ta\ta\ta\ta\n')

    def test_download_with_fixed_date(self):
        """ test download with fixed date"""
        response = requests.Response()
        response.status_code = 200
        response._content = 'content'
        response.iter_content = lambda _: [response._content]

        with stubbed(requests.Session.get, lambda _, __: response):
            with stubbed(requests.Session.head, lambda _, __: response):
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
        eq_(len(downloaded), 1)
        with open(downloaded[0]) as fil:
            eq_(fil.read(), 'content')

    def test_download_empty_date(self):
        """ test_download_with_date_latest_should_make_a_head_query_with_empty_date_and_name_the_output_file_according_to_the_content_disposition_header """
        response = requests.Response()
        response.status_code = 200
        response._content = 'content'
        response.headers['content-disposition'] = 'filename=01-01-2015'
        response.iter_content = lambda _: [response._content]

        def fake_head(slf, url):
            """ fake head method """
            eq_(
                url,
                'https://rucio-hadoop.cern.ch/data_concrete?rse=SOMEENDPOINT',
            )
            return response

        with stubbed(requests.Session.get, fake_head):
            with stubbed(requests.Session.head, lambda _, __: response):
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
        eq_(len(downloaded), 1)
        with open(downloaded[0]) as fil:
            eq_(fil.read(), 'content')

    @raises(dumper.HTTPDownloadFailed)
    def test_raises_exception(self):
        """ test raise exception """
        response = requests.Response()
        response.status_code = 500

        with stubbed(requests.Session.get, lambda _, __: response):
            with stubbed(requests.Session.head, lambda _, __: response):
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
        eq_(complete_dataset.state, 'A')

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
        eq_(replica.state, 'None')  # pylint: disable=no-member

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
        eq_(replica.state, 'A')  # pylint: disable=no-member


class TestFilter(object):
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
        ok_(filter_.match(self.replica_1))
        ok_(not filter_.match(self.replica_2))

    def test_multiple_conditions(self):
        """ test multiple conditions """
        filter_ = data_models.Filter('size=42,state=A', data_models.Replica)
        ok_(filter_.match(self.replica_1), self.replica_1.size)  # pylint: disable=no-member
        ok_(not filter_.match(self.replica_2), self.replica_2.size)  # pylint: disable=no-member
