''' Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Frank Berghaus, <frank.berghaus@cern.ch>, 2018
 - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018

 PY3K COMPATIBLE
'''

import unittest
import tempfile

from nose.tools import assert_raises, assert_equal, assert_is_instance, assert_is_not_none
from re import match
from rucio.common.exception import InvalidType
from rucio.common.utils import md5, adler32, parse_did_filter_from_string


class TestUtils(unittest.TestCase):
    """UTILS (COMMON): test utilisty functions"""

    def setUp(self):
        """set up test fixtures"""
        self.temp_file_1 = tempfile.NamedTemporaryFile()
        self.temp_file_1.write('hello test\n')
        self.temp_file_1.seek(0)

    def tearDown(self):
        """tear down test fixtures"""
        self.temp_file_1.close()

    def test_utils_md5(self):
        """(COMMON/UTILS): test calculating MD5 of a file"""
        ret = md5(self.temp_file_1.name)
        assert_is_instance(ret, str, msg="Object returned by utils.md5 is not a string")
        assert_is_not_none(match('[a-fA-F0-9]{32}', ret), msg="String returned by utils.md5 is not a md5 hex digest")
        assert_equal(ret, '31d50dd6285b9ff9f8611d0762265d04',
                     msg="Hex digest returned by utils.md5 is the MD5 checksum")

        with assert_raises(Exception) as e:
            md5('no_file')
        assert_equal('FATAL - could not get MD5 checksum of file no_file - [Errno 2] No such file or directory: \'no_file\'', e.exception.message)

    def test_utils_adler32(self):
        """(COMMON/UTILS): test calculating Adler32 of a file"""
        ret = adler32(self.temp_file_1.name)
        assert_is_instance(ret, str)
        assert_is_not_none(match('[a-fA-F0-9]', ret))
        assert_equal(ret, '198d03ff')

        with assert_raises(Exception) as e:
            adler32('no_file')
        assert_equal('FATAL - could not get Adler32 checksum of file no_file - [Errno 2] No such file or directory: \'no_file\'', e.exception.message)

    def test_parse_did_filter_string(self):
        """(COMMON/UTILS): test parsing of did filter string"""
        test_cases = [{
            'input': 'type=all,length=3,length>4,length>=6,length<=7,  test=b',
            'expected_filter': {'length': 3, 'length.gt': 4, 'length.gte': 6, 'length.lte': 7, 'test': 'b'},
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
            assert_equal(test_case['expected_filter'], filters)
            assert_equal(test_case['expected_type'], type)

        with assert_raises(InvalidType):
            input = 'type=g'
            parse_did_filter_from_string(input)
