''' Copyright European Organization for Nuclear Research (CERN)
 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Brian Bockelman, <bbockelm@cse.unl.edu>, 2019
'''

from ConfigParser import NoOptionError

from nose.tools import assert_equal

from rucio.rse.protocols.protocol import RSEDeterministicTranslation
from rucio.common import config

class TestDeterministicTranslation(object):
    """
    Verify the deterministic translator.
    """

    def setup(self):
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
        assert_equal(self.translator.path("foo", "bar"), "foo/4e/99/bar")

    def test_default_hash(self):
        """LFN2PFN: Translate to path using default algorithm (Success)"""
        assert_equal(self.translator.path("foo", "bar"), "foo/4e/99/bar")

    def test_identity(self):
        """LFN2PFN: Translate to path using identity (Success)"""
        self.rse_attributes['lfn2pfn_algorithm'] = 'identity'
        self.create_translator()
        assert_equal(self.translator.path("foo", "bar"), "foo/bar")

    def test_user_scope(self):
        """LFN2PFN: Test special user scope rules (Success)"""
        assert_equal(self.translator.path("user.foo", "bar"), "user/foo/13/7f/bar")

    def test_register_func(self):
        """LFN2PFN: Verify we can register a custom function (Success)"""
        def static_register_test1(scope, name, rse, rse_attrs, proto_attrs):
            return "static_register_value1"
        def static_register_test2(scope, name, rse, rse_attrs, proto_attrs):
            return "static_register_value2"
        RSEDeterministicTranslation.register(static_register_test1)
        RSEDeterministicTranslation.register(static_register_test2, name="static_register_custom_name")
        self.rse_attributes['lfn2pfn_algorithm'] = 'static_register_test1'
        self.create_translator()
        assert_equal(self.translator.path("foo", "bar"), "static_register_value1")
        self.rse_attributes['lfn2pfn_algorithm'] = 'static_register_custom_name'
        self.create_translator()
        assert_equal(self.translator.path("foo", "bar"), "static_register_value2")

    def test_register_func(self):
        """LFN2PFN: Verify we can map using rse and attrs (Successs)"""
        def rse_algorithm(scope, name, rse, rse_attrs, proto_attrs):
            tier = rse_attrs.get("tier", "T1")
            scheme = proto_attrs.get("scheme", "http")
            return "%s://%s_%s/%s/%s" % (scheme, tier, rse, scope, name)
        RSEDeterministicTranslation.register(rse_algorithm)
        self.rse_attributes['lfn2pfn_algorithm'] = 'rse_algorithm'
        self.create_translator()
        assert_equal(self.translator.path("foo", "bar"), "http://T1_Mock/foo/bar")
        self.rse_attributes['tier'] = 'T2'
        self.create_translator()
        assert_equal(self.translator.path("foo", "bar"), "http://T2_Mock/foo/bar")
        self.protocol_attributes['scheme'] = 'https'
        self.create_translator()
        assert_equal(self.translator.path("foo", "bar"), "https://T2_Mock/foo/bar")
        self.protocol_attributes['scheme'] = 'srm'
        self.create_translator()
        assert_equal(self.translator.path("foo", "bar"), "srm://T2_Mock/foo/bar")

    def test_module_load(self):
        """LFN2PFN: Test ability to provide LFN2PFN functions via module (Success)"""
        config.config_set('policy', 'lfn2pfn_module', 'rucio.tests.lfn2pfn_module_test')
        RSEDeterministicTranslation._module_init_()
        self.rse_attributes['lfn2pfn_algorithm'] = 'lfn2pfn_module_algorithm'
        self.create_translator()
        assert_equal(self.translator.path("foo", "bar"), "lfn2pfn_module_algorithm_value")

    def test_config_default_override(self):
        """LFN2PFN: Test override of default LFN2PFN algorithm via config (Success)"""
        try:
            orig_value = config.config_get('policy', 'lfn2pfn_algorithm_default')
        except NoOptionError:
            orig_value = None
        def static_test(scope, name, rse, rse_attrs, proto_attrs):
            return "static_test_value"
        RSEDeterministicTranslation.register(static_test)
        try:
            config.config_set('policy', 'lfn2pfn_algorithm_default', 'static_test')
            RSEDeterministicTranslation._module_init_()
            assert_equal(self.translator.path("foo", "bar"), "static_test_value")
        finally:
            if orig_value is None:
                config.config_remove_option('policy', 'lfn2pfn_algorithm_default')
            else:
                config.config_set('policy', 'lfn2pfn_algorithm_default', orig_value)
            RSEDeterministicTranslation._module_init_()
