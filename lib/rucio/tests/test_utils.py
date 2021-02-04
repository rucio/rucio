# -*- coding: utf-8 -*-
# Copyright 2017-2021 CERN
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
# - Frank Berghaus <frank.berghaus@cern.ch>, 2017-2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Martin Barisits <martin.barisits@cern.ch>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021

import datetime
import logging
import tempfile
import unittest
from re import match

import pytest

from rucio.common.exception import InvalidType
from rucio.common.utils import md5, adler32, parse_did_filter_from_string
from rucio.common.logging import formatted_logger


class TestUtils(unittest.TestCase):
    """UTILS (COMMON): test utilisty functions"""

    def setUp(self):
        """set up test fixtures"""
        self.temp_file_1 = tempfile.NamedTemporaryFile()
        self.temp_file_1.write('hello test\n'.encode())
        self.temp_file_1.seek(0)

    def tearDown(self):
        """tear down test fixtures"""
        self.temp_file_1.close()

    def test_utils_md5(self):
        """(COMMON/UTILS): test calculating MD5 of a file"""
        ret = md5(self.temp_file_1.name)
        assert isinstance(ret, str), "Object returned by utils.md5 is not a string"
        assert match('[a-fA-F0-9]{32}', ret) is not None, "String returned by utils.md5 is not a md5 hex digest"
        assert ret == '31d50dd6285b9ff9f8611d0762265d04', "Hex digest returned by utils.md5 is the MD5 checksum"

        with pytest.raises(Exception, match='FATAL - could not get MD5 checksum of file no_file - \\[Errno 2\\] No such file or directory: \'no_file\''):
            md5('no_file')

    def test_utils_adler32(self):
        """(COMMON/UTILS): test calculating Adler32 of a file"""
        ret = adler32(self.temp_file_1.name)
        assert isinstance(ret, str)
        assert match('[a-fA-F0-9]', ret) is not None
        assert ret == '198d03ff'

        with pytest.raises(Exception, match='FATAL - could not get Adler32 checksum of file no_file - \\[Errno 2\\] No such file or directory: \'no_file\''):
            adler32('no_file')

    def test_parse_did_filter_string(self):
        """(COMMON/UTILS): test parsing of did filter string"""
        test_cases = [{
            'input': 'type=all,length=3,length>4,length>=6,length<=7,  test=b, created_after=1900-01-01T00:00:00.000Z',
            'expected_filter': {'length': 3, 'length.gt': 4, 'length.gte': 6, 'length.lte': 7, 'test': 'b', 'created_after': datetime.datetime.strptime('1900-01-01T00:00:00.000Z', '%Y-%m-%dT%H:%M:%S.%fZ')},
            'expected_type': 'all'
        }, {
            'input': 'type=FILE',
            'expected_filter': {},
            'expected_type': 'file'
        }, {
            'input': '',
            'expected_filter': {},
            'expected_type': 'collection'
        }]

        for test_case in test_cases:
            filters, type = parse_did_filter_from_string(test_case['input'])
            assert test_case['expected_filter'] == filters
            assert test_case['expected_type'] == type

        with pytest.raises(InvalidType):
            input = 'type=g'
            parse_did_filter_from_string(input)


def test_formatted_logger():
    result = None

    def log_func(level, msg, *args, **kwargs):
        nonlocal result
        result = (level, msg)

    new_log_func = formatted_logger(log_func, "a %s c")

    new_log_func(logging.INFO, "b")
    assert result == (logging.INFO, "a b c")
