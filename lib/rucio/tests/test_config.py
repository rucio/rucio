# -*- coding: utf-8 -*-
# Copyright 2014-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import unittest

import pytest

import rucio.core.config as config_core
from rucio.client.configclient import ConfigClient
from rucio.common import exception
from rucio.common.utils import generate_uuid


class TestConfigCore:

    def test_get_config_sections(self):
        """ CONFIG (CORE): Retreive configuration section only """
        expected_sections = [str(generate_uuid()), str(generate_uuid())]
        for section in expected_sections:
            config_core.set(section, str(generate_uuid()), str(generate_uuid()))
        sections = config_core.sections(use_cache=False)
        for section in expected_sections:
            assert section in sections

    def test_get_and_set_section_option(self):
        """ CONFIG (CORE): Retreive configuration option only """
        # get and set
        section = str(generate_uuid())
        option = str(generate_uuid())
        expected_value = str(generate_uuid())
        config_core.set(section=section, option=option, value=expected_value)
        value = config_core.get(section, option, use_cache=False)
        assert value == expected_value

        # default value
        section = str(generate_uuid())
        config_core.set(section=section, option=str(generate_uuid()), value=str(generate_uuid()))
        default_value = 'default'
        value = config_core.get(section, 'new_option', default=default_value, use_cache=False)
        assert value == default_value

        # key with space character
        section = str(generate_uuid() + ' ')
        option = str(generate_uuid() + ' ')
        expected_value = str(generate_uuid())
        config_core.set(section=section, option=option, value=expected_value)
        value = config_core.get(section, option, use_cache=False)
        assert value == expected_value


@pytest.mark.xfail(reason='ConfigClient bug https://github.com/rucio/rucio/issues/3916')
def test_config_section_contextless():
    config = ConfigClient()
    test_section_1 = generate_uuid()
    test_section_2 = generate_uuid()
    config.set_config_option(test_section_1, 'a', 'b')
    config.set_config_option(test_section_2, 'c', 'd')

    value = config.get_config(None, None)

    assert isinstance(value, dict)
    assert list(value.keys()) == [test_section_1, test_section_2]


class TestConfigClients(unittest.TestCase):

    def setUp(self):
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

    def tearDown(self):
        self.c = None

    @pytest.mark.xfail(reason='ConfigClient bug https://github.com/rucio/rucio/issues/3916')
    def test_get_config_all(self):
        """ CONFIG (CLIENT): Retrieve configuration values and check for correctness """
        tmp = self.c.get_config(None, None)
        assert isinstance(tmp, dict)
        assert self.test_section_1 in tmp.keys()
        assert self.test_option_s in tmp[self.test_section_1]
        assert self.test_option_b in tmp[self.test_section_1]
        assert self.test_option_sv == tmp[self.test_section_1][self.test_option_s]
        assert tmp[self.test_section_1][self.test_option_b]
        assert self.test_option_i in tmp[self.test_section_2]
        assert self.test_option_f in tmp[self.test_section_2]
        assert 543210 == tmp[self.test_section_2][self.test_option_i]
        assert 3.1415 == tmp[self.test_section_2][self.test_option_f]

    def test_get_config_section(self):
        """ CONFIG (CLIENT): Retrieve configuration section only """
        tmp = self.c.get_config(self.test_section_1, None)
        assert isinstance(tmp, dict)
        assert self.test_option_s in tmp.keys()
        assert self.test_option_b in tmp.keys()

    def test_get_config_section_option(self):
        """ CONFIG (CLIENT): Retrieve configuration option only """
        tmp = self.c.get_config(self.test_section_1, self.test_option_s)
        assert tmp == self.test_option_sv

        with pytest.raises(exception.ConfigNotFound):
            self.c.get_config(self.test_section_1, 'no_option')
