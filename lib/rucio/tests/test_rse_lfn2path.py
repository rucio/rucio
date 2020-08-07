# Copyright 2018-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Brian Bockelman <bbockelm@cse.unl.edu>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
#
# PY3K COMPATIBLE

import unittest

from rucio.common import config
from rucio.rse.protocols.protocol import RSEDeterministicTranslation

try:
    # PY2
    from ConfigParser import NoOptionError, NoSectionError
except ImportError:
    # PY3
    from configparser import NoOptionError, NoSectionError


class TestDeterministicTranslation(unittest.TestCase):
    """
    Verify the deterministic translator.
    """

    def setUp(self):
        """LFN2PFN: Creating RSEDeterministicTranslation instance"""
        self.rse = 'Mock'
        self.rse_attributes = {"rse": "Mock"}
        self.protocol_attributes = {"protocol": "test"}
        self.create_translator()

    def create_translator(self):
        """Create a new RSEDeterministicTranslation for use with tests."""
        self.translator = RSEDeterministicTranslation(self.rse, self.rse_attributes, self.protocol_attributes)

    def test_hash(self):
        """LFN2PFN: Translate to path using a hash (Success)"""
        self.rse_attributes['lfn2pfn_algorithm'] = 'hash'
        self.create_translator()
        assert self.translator.path("foo", "bar") == "foo/4e/99/bar"

    def test_default_hash(self):
        """LFN2PFN: Translate to path using default algorithm (Success)"""
        assert self.translator.path("foo", "bar") == "foo/4e/99/bar"

    def test_identity(self):
        """LFN2PFN: Translate to path using identity (Success)"""
        self.rse_attributes['lfn2pfn_algorithm'] = 'identity'
        self.create_translator()
        assert self.translator.path("foo", "bar") == "foo/bar"

    def test_user_scope(self):
        """LFN2PFN: Test special user scope rules (Success)"""
        assert self.translator.path("user.foo", "bar") == "user/foo/13/7f/bar"

    def test_register_func(self):
        """LFN2PFN: Verify we can register a custom function (Success)"""
        def static_register_test1(scope, name, rse, rse_attrs, proto_attrs):
            """Test function for registering LFN2PATH functions."""
            del scope
            del name
            del rse
            del rse_attrs
            del proto_attrs
            return "static_register_value1"

        def static_register_test2(scope, name, rse, rse_attrs, proto_attrs):
            """Second test function for registering LFN2PATH functions."""
            del scope
            del name
            del rse
            del rse_attrs
            del proto_attrs
            return "static_register_value2"

        RSEDeterministicTranslation.register(static_register_test1)
        RSEDeterministicTranslation.register(static_register_test2, name="static_register_custom_name")
        self.rse_attributes['lfn2pfn_algorithm'] = 'static_register_test1'
        self.create_translator()
        assert self.translator.path("foo", "bar") == "static_register_value1"
        self.rse_attributes['lfn2pfn_algorithm'] = 'static_register_custom_name'
        self.create_translator()
        assert self.translator.path("foo", "bar") == "static_register_value2"

    def test_attr_mapping(self):
        """LFN2PFN: Verify we can map using rse and attrs (Successs)"""
        def rse_algorithm(scope, name, rse, rse_attrs, proto_attrs):
            """Test LFN2PATH function for exercising the different RSE/proto attrs."""
            tier = rse_attrs.get("tier", "T1")
            scheme = proto_attrs.get("scheme", "http")
            return "%s://%s_%s/%s/%s" % (scheme, tier, rse, scope, name)
        RSEDeterministicTranslation.register(rse_algorithm)
        self.rse_attributes['lfn2pfn_algorithm'] = 'rse_algorithm'
        self.create_translator()
        assert self.translator.path("foo", "bar") == "http://T1_Mock/foo/bar"
        self.rse_attributes['tier'] = 'T2'
        self.create_translator()
        assert self.translator.path("foo", "bar") == "http://T2_Mock/foo/bar"
        self.protocol_attributes['scheme'] = 'https'
        self.create_translator()
        assert self.translator.path("foo", "bar") == "https://T2_Mock/foo/bar"
        self.protocol_attributes['scheme'] = 'srm'
        self.create_translator()
        assert self.translator.path("foo", "bar") == "srm://T2_Mock/foo/bar"

    def test_module_load(self):
        """LFN2PFN: Test ability to provide LFN2PFN functions via module (Success)"""
        if not config.config_has_section('policy'):
            config.config_add_section('policy')
        config.config_set('policy', 'lfn2pfn_module', 'rucio.tests.lfn2pfn_module_test')
        RSEDeterministicTranslation._module_init_()  # pylint: disable=protected-access
        self.rse_attributes['lfn2pfn_algorithm'] = 'lfn2pfn_module_algorithm'
        self.create_translator()
        assert self.translator.path("foo", "bar") == "lfn2pfn_module_algorithm_value"

    def test_config_default_override(self):
        """LFN2PFN: Test override of default LFN2PFN algorithm via config (Success)"""
        if not config.config_has_section('policy'):
            config.config_add_section('policy')
        try:
            orig_value = config.config_get('policy', 'lfn2pfn_algorithm_default')
        except (NoOptionError, NoSectionError):
            orig_value = None

        def static_test(scope, name, rse, rse_attrs, proto_attrs):
            """Static test function for config override."""
            del scope
            del name
            del rse
            del rse_attrs
            del proto_attrs
            return "static_test_value"

        RSEDeterministicTranslation.register(static_test)
        try:
            config.config_set('policy', 'lfn2pfn_algorithm_default', 'static_test')
            RSEDeterministicTranslation._module_init_()  # pylint: disable=protected-access
            assert self.translator.path("foo", "bar") == "static_test_value"
        finally:
            if orig_value is None:
                config.config_remove_option('policy', 'lfn2pfn_algorithm_default')
            else:
                config.config_set('policy', 'lfn2pfn_algorithm_default', orig_value)
            RSEDeterministicTranslation._module_init_()  # pylint: disable=protected-access

    def test_supports(self):  # pylint: disable=no-self-use
        """LFN2PFN: See if the static `supports` method works"""

        def static_test(scope, name, rse, rse_attrs, proto_attrs):
            """Static test function for testing supports."""
            del scope
            del name
            del rse
            del rse_attrs
            del proto_attrs
            return "static_test_value"

        assert not RSEDeterministicTranslation.supports("static_supports")
        RSEDeterministicTranslation.register(static_test, "static_supports")
        assert RSEDeterministicTranslation.supports("static_supports")
