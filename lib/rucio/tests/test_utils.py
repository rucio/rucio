''' Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Frank Berghaus, <frank.berghaus@cern.ch>, 2017
'''

import os
import unittest

from nose.tools import assert_equal, assert_is_instance
from rucio.common.utils import md5


class TestUtils(unittest.TestCase):
    """UTILS (COMMON): test utilisty functions"""

    _test_fn = 'testutils.fix'

    def setUp(self):
        "set up test fixtures"
        print('creating:', self._test_fn)
        with open(self._test_fn, 'w') as f:
            f.write('hello test')

    def tearDown(self):
        "tear down test fixtures"
        print('deleting:', self._test_fn)
        os.remove(self._test_fn)

    def test_util_md5(self):
        """(COMMON/UTILS): test calculating MD5 of a file"""
        ret = md5(self._test_fn)
        assert_is_instance(ret, str)
        assert_equal(len(ret), 32)
