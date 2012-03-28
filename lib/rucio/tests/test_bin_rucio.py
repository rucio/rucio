# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

from paste.fixture import TestApp
from nose.tools import *

from rucio import version
from rucio.tests.utils import execute


class TestBinRucio():

    def setUp(self):
        # setup http
        pass

    def tearDown(self):
        # teardown http
        pass

    def test_rucio_version(self):
        cmd = 'bin/rucio --version'
        exitcode, out, err = execute(cmd)
        assert_equal(err, 'rucio %s\n' % version.version_string())
