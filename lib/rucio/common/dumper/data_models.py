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
Download dumps via HTTP
"""

import collections
import datetime
import hashlib
import logging
import operator
import os
import re
from tabulate import tabulate

from rucio.common.dumper import DUMPS_CACHE_DIR
from rucio.common.dumper import HTTPDownloadFailed
from rucio.common.dumper import get_requests_session
from rucio.common.dumper import http_download_to_file
from rucio.common.dumper import smart_open
from rucio.common.dumper import temp_file
from rucio.common.dumper import to_datetime


class DataModel(object):
    """
    Data model for the dumps
    """

    BASE_URL = 'https://rucio-hadoop.cern.ch/'
    _FIELD_NAMES = None
    SCHEMA = []
    URI = None
    name = None

    def __init__(self, *args):
        if len(args) != len(self.SCHEMA):
            raise TypeError(
                'Wrong number of parameters (fields) to initalize {0} '
                'instance. {1} given, {2} expected:\n{3}'.format(
                    type(self).__name__,
                    len(args),
                    len(self.SCHEMA),
                    args,
                )
            )
        for (attr, parse), value in zip(self.SCHEMA, args):
            try:
                setattr(self, attr, parse(value))
            except ValueError as err:
                err.args = ('str parseable with {0} expected but got "{1}"'.format(
                    str(parse),
                    value,
                ),)
                raise err

        self.date = None

    @classmethod
    def get_fieldnames(cls):
        """
        Get the field names
        """
        if cls._FIELD_NAMES is None:
            cls._FIELD_NAMES = [name for name, _ in cls.SCHEMA]
        return cls._FIELD_NAMES

    def pprint(self):
        """
        Pretty print the dump
        """
        return ''.join(
            ['{0}: {1}\n'.format(attr, getattr(self, attr)) for attr, _ in self.SCHEMA]
        )

    def __getitem__(self, index):
        """
        Return the item
        """
        return getattr(self, self.SCHEMA[index][0])

    @classmethod
    def csv_header(cls, fields=None):
        """
        Add the CSV header if necessary
        """
        if fields is None:
            fields = (field for field, _ in cls.SCHEMA)
        return ','.join(fields)

    def formated_fields(self, print_fields=None):
        """
        Reformat the fields
        """
        if print_fields is None:
            print_fields = (field for field, _ in self.SCHEMA)

        fields = []
        for attr in print_fields:
            field = getattr(self, attr)
            if isinstance(field, datetime.datetime):
                field = field.isoformat()
            fields.append(str(field))
        return fields

    def csv(self, fields=None):
        """
        Generate a CSV line
        """
        return ','.join(self.formated_fields(fields))

    @classmethod
    def tabulate_from(cls, iter_, format_='simple', fields=None):
        return tabulate(
            (row.formated_fields(fields) for row in iter_),
            (t[0] for t in cls.SCHEMA),
            format_,
        )

    @classmethod
    def each(cls, file, rse=None, date=None, filter_=None):
        if filter_ is None:
            filter_ = lambda x: True  # NOQA
        for line in file:
            record = cls.parse_line(line, rse, date)
            if filter_(record):
                yield record

    @classmethod
    def parse_line(cls, line, rse=None, date=None):
        fields = (field.strip() for field in line.split('\t'))
        instance = cls(*fields)
        instance.rse = rse
        instance.date = date
        return instance

    @classmethod
    def download(cls, rse, date='latest', cache_dir=DUMPS_CACHE_DIR):
        """
        Downloads the requested dump and returns an open read-only mode file
        like object.
        """
        logger = logging.getLogger('auditor.data_models')
        requests_session = get_requests_session()
        if date == 'latest':
            url = ''.join((cls.BASE_URL, cls.URI, '?rse={0}'.format(rse)))
            request_headers = requests_session.head(url)
            for field in request_headers.headers['content-disposition'].split(';'):
                if field.startswith('filename='):
                    date = field.split('=')[1].split('_')[-1].split('.')[0]

        else:
            assert isinstance(date, datetime.datetime)
            date = date.strftime('%d-%m-%Y')  # pylint: disable=no-member
            url = ''.join((
                cls.BASE_URL,
                cls.URI,
                '?rse={0}&date={1}'.format(rse, date),
            ))

        if not os.path.isdir(cache_dir):
            os.mkdir(cache_dir)

        filename = '{0}_{1}_{2}_{3}'.format(
            cls.__name__.lower(),
            rse,
            date,
            hashlib.sha1(url.encode()).hexdigest()
        )
        filename = re.sub(r'\W', '-', filename)
        path = os.path.join(cache_dir, filename)

        if not os.path.exists(path):
            logger.debug('Trying to download: "%s"', url)
            response = requests_session.head(url)
            if response.status_code != 200:
                logger.error(
                    'Retrieving %s returned %d status code',
                    url,
                    response.status_code,
                )
                raise HTTPDownloadFailed('Downloading {0} dump'.format(cls.__name__), code=response.status_code)

            with temp_file(cache_dir, final_name=filename) as (tfile, _):
                http_download_to_file(url, tfile, session=requests_session)

        return path

    @classmethod
    def dump(cls, rse, date='latest', filter_=None):
        filename = cls.download(rse, date)

        # Should check errors, content size at least
        file = smart_open(filename)

        return cls.each(file, rse, date, filter_)


class Dataset(DataModel):
    URI = 'datasets_per_rse'
    SCHEMA = (
        ('rse', str),
        ('scope', str),
        ('name', str),
        ('size', int),
        ('creation_date', to_datetime),
        ('update_date', to_datetime),
        ('last_access', to_datetime),
        ('state', str),
    )


class CompleteDataset(DataModel):
    URI = 'consistency_datasets'
    SCHEMA = (
        ('rse', str),
        ('scope', str),
        ('name', str),
        ('owner', str),
        ('size', lambda s: int(s) if s != '' else None),
        ('creation_date', to_datetime),
        ('last_access', to_datetime),
    )

    def __init__(self, *args):
        logger = logging.getLogger('auditor.data_models')
        super(CompleteDataset, self).__init__(*args[0:7])
        if len(args) == 8:
            logger.warning('Extra parameter\nrse: %s\ndataset: %s\n', self.rse, self.name)
            self.state = args[7]
        else:
            self.state = None
        assert len(args) <= 8


class Replica(DataModel):
    URI = 'replica_dumps'
    SCHEMA = (
        ('rse', str),
        ('scope', str),
        ('name', str),
        ('checksum', str),
        ('size', int),
        ('creation_date', to_datetime),
        ('path', str),
        ('update_date', to_datetime),
        ('state', str),
    )

    def __init__(self, *args):
        logger = logging.getLogger('auditor.data_models')
        if len(args) == 8:
            args = list(args)
            args.append(None)

        super(Replica, self).__init__(*args)

        if len(args) == 8:
            logger.warning('Missing parameter\nrse: %s\ndataset: %s\n', self.rse, self.name)
        assert len(args) <= 9


class Filter(object):
    _Condition = collections.namedtuple('_Condition', ('comparator', 'attribute', 'expected'))

    def __init__(self, filter_str, record_class):
        '''
        Filter objects allow to match a DataModel subclass instance against
        one or more conditions.

        For the moment only equality conditions are implemented.

        :param filter_str: One or multiple comma separated conditions.
        :param record_class: DataModel subclass (used to check if the
        conditions use valid fields).

        Examples:
        available = Filter('state=A', Replica)
        available.match(replica)

        test_scope_avail = Filter('scope=test,state=A', Replica)
        test_scope_avail.match(replica)
        '''
        self.conditions = []
        for expr in filter_str.split(','):
            key, expected = expr.split('=')
            # Better checks required
            assert key in record_class.get_fieldnames()
            parser = list(filter(lambda t: t[0] == key, record_class.SCHEMA))[0][1]
            self.conditions.append(self._Condition(
                comparator=operator.eq,
                attribute=key,
                expected=parser(expected),
            ))

    def match(self, record):
        '''
        :param record: DataModel subclass instance.
        :returns: True if record matches all the conditions in this filter,
        else returns False.
        '''
        for cond in self.conditions:
            val = cond.comparator(
                getattr(record, cond.attribute),
                cond.expected,
            )

            if not val:
                return False

        return True
