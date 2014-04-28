# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

from nose.tools import assert_equal, assert_in, assert_is_instance, assert_true

from rucio.client.configclient import ConfigClient
from rucio.common.utils import generate_uuid


class TestConfigClients:

    @classmethod
    def setupClass(self):
        self.c = ConfigClient()
        self.test_section_1 = str(generate_uuid())
        self.test_section_2 = str(generate_uuid())
        self.test_option_s = 'string'
        self.test_option_b = 'bool'
        self.test_option_i = 'int'
        self.test_option_f = 'float'
        self.test_option_sv = 'iddqd'
        self.test_option_bv = 'True'
        self.test_option_iv = '543210'
        self.test_option_fv = '3.1415'
        self.c.set_config_option(self.test_section_1, self.test_option_s, self.test_option_sv)
        self.c.set_config_option(self.test_section_1, self.test_option_b, self.test_option_bv)
        self.c.set_config_option(self.test_section_2, self.test_option_i, self.test_option_iv)
        self.c.set_config_option(self.test_section_2, self.test_option_f, self.test_option_fv)

    @classmethod
    def tearDownClass(self):
        self.c.delete_config_option(self.test_section_1, self.test_option_s)
        self.c.delete_config_option(self.test_section_1, self.test_option_b)
        self.c.delete_config_option(self.test_section_2, self.test_option_i)
        self.c.delete_config_option(self.test_section_2, self.test_option_f)

    def test_get_config_all(self):
        """ CONFIG (CLIENT): Retrieve configuration values and check for correctness """
        tmp = self.c.get_config(None, None)
        assert_is_instance(tmp, dict)
        assert_in(self.test_section_1, tmp.keys())
        assert_in(self.test_option_s, tmp[self.test_section_1])
        assert_in(self.test_option_b, tmp[self.test_section_1])
        assert_equal(self.test_option_sv, tmp[self.test_section_1][self.test_option_s])
        assert_true(tmp[self.test_section_1][self.test_option_b])
        assert_in(self.test_option_i, tmp[self.test_section_2])
        assert_in(self.test_option_f, tmp[self.test_section_2])
        assert_equal(543210, tmp[self.test_section_2][self.test_option_i])
        assert_equal(3.1415, tmp[self.test_section_2][self.test_option_f])

    def test_get_config_section(self):
        """ CONFIG (CLIENT): Retrieve configuration section only """
        tmp = self.c.get_config(self.test_section_1, None)
        assert_is_instance(tmp, dict)
        assert_in(self.test_option_s, tmp.keys())
        assert_in(self.test_option_b, tmp.keys())

    def test_get_config_section_option(self):
        """ CONFIG (CLIENT): Retrieve configuration option only """
        tmp = self.c.get_config(self.test_section_1, self.test_option_s)
        assert_equal(tmp, self.test_option_sv)
