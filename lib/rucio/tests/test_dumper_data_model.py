# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Fernando Lopez, <felopez@cern.ch>, 2015
from datetime import datetime
from nose.tools import eq_
from nose.tools import ok_
from nose.tools import raises
from rucio.common import dumper
from rucio.common.dumper import data_models
from rucio.tests.common import stubbed
import glob
import os
import requests
import shutil
import tempfile


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
        eq_(self._DataConcrete.get_fieldnames(), list('abcdefgh'))

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
        eq_(self.data_concrete.pprint(), expected_format, self.data_concrete.pprint())

    def test_data_models_are_indexable(self):
        eq_(self.data_concrete[0], 'aa')

    def test_csv_header(self):
        eq_(self._DataConcrete.csv_header(), 'a,b,c,d,e,f,g,h')

    def test_formated_fields(self):
        eq_(self.data_concrete.formated_fields(print_fields=('a', 'e')), ['aa', '42'])

    def test_csv(self):
        eq_(self.data_concrete.csv(fields=('a', 'e')), 'aa,42')

    def test_csv_default_formatting(self):
        eq_(
            self.data_concrete.csv(),
            'aa,bb,cc,dd,42,2015-03-10T14:00:35,ee,2015-03-10T14:00:35'
        )

    def test_each(self):
        tsv_dump = ['\t'.join(self.data_list)]
        records = list(self._DataConcrete.each(tsv_dump))
        eq_(len(records), 1)
        eq_(records[0].a, 'aa')

    def test_each_with_filter(self):
        tsv_dump = ['\t'.join(self.data_list)]
        tsv_dump.append(tsv_dump[0].replace('aa', 'xx'))
        records = list(self._DataConcrete.each(tsv_dump, filter_=lambda x: x.a == 'xx'))
        eq_(len(records), 1)
        eq_(records[0].a, 'xx')

    def test_each_iterates_tough_all_lines_even_without_eol(self):
        dump_file = self.VALID_DUMP.splitlines(True)
        eq_(
            2,
            len(list(self._DataConcrete.each(dump_file))),
        )

    def test_parse_line_valid_line(self):
        for line in self.VALID_DUMP.splitlines(True):
            self._DataConcrete.parse_line(line)

    @raises(TypeError)
    def test_parse_line_wrong_number_of_fields(self):
        self._DataConcrete.parse_line('asdasd\taasdsa\n')

    @raises(ValueError)
    def test_parse_line_wrong_format_of_fields(self):
        self._DataConcrete.parse_line('a\ta\ta\ta\ta\ta\ta\ta\n')

    def test_download_with_fixed_date(self):
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
        with open(downloaded[0]) as f:
            eq_(f.read(), 'content')

    def test_download_with_date_latest_should_make_a_head_query_with_empty_date_and_name_the_output_file_according_to_the_content_disposition_header(self):
        response = requests.Response()
        response.status_code = 200
        response._content = 'content'
        response.headers['content-disposition'] = 'filename=01-01-2015'
        response.iter_content = lambda _: [response._content]

        def fake_head(slf, url):
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
        with open(downloaded[0]) as f:
            eq_(f.read(), 'content')

    @raises(dumper.HTTPDownloadFailed)
    def test_download_error_raises_exception(self):
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
        eq_(complete_dataset.state, 'A')

    def test_empty_size_is_saved_as_none(self):
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


class TestReplica(object):
    def test_replica_creation_with_8_parameters(self):
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
        eq_(replica.state, 'None')

    def test_replica_creation_with_9_parameters(self):
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
        eq_(replica.state, 'A')


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
        filter_ = data_models.Filter('state=A', data_models.Replica)
        ok_(filter_.match(self.replica_1))
        ok_(not filter_.match(self.replica_2))

    def test_multiple_conditions_are_evaluated_as_an_and_expresion(self):
        filter_ = data_models.Filter('size=42,state=A', data_models.Replica)
        ok_(filter_.match(self.replica_1), self.replica_1.size)
        ok_(not filter_.match(self.replica_2), self.replica_2.size)
