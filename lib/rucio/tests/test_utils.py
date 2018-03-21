''' Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Frank Berghaus, <frank.berghaus@cern.ch>, 2018
'''

import unittest
import tempfile

from nose.tools import assert_equal, assert_is_instance, assert_is_not_none
from re import match
from rucio.common.utils import md5


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
