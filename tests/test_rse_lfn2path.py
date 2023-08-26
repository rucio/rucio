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

import copy
import os

import pytest

from rucio.common import config
from rucio.rse.protocols.protocol import RSEDeterministicTranslation

from configparser import NoOptionError, NoSectionError


@pytest.mark.noparallel(reason='uses pre-defined RSE, changes global configuration value')
class TestDeterministicTranslation:
    """
    Verify the deterministic translator.
    """

    rse = 'Mock'
    protocol_attributes = {"protocol": "test"}

    def test_hash(self):
        """LFN2PFN: Translate to path using a hash (Success)"""
        translator = RSEDeterministicTranslation(
            rse=self.rse,
            rse_attributes={
                'rse': self.rse,
                'lfn2pfn_algorithm': 'hash',
            },
            protocol_attributes=self.protocol_attributes,
        )
        assert translator.path("foo", "bar") == "foo/4e/99/bar"

    @pytest.mark.skipif(os.environ.get('POLICY') != 'atlas', reason='Test ATLAS hash convention')
    def test_default_hash(self):
        """LFN2PFN: Translate to path using default algorithm (Success)"""
        translator = RSEDeterministicTranslation(
            rse=self.rse,
            rse_attributes={
                'rse': self.rse,
            },
            protocol_attributes=self.protocol_attributes,
        )
        assert translator.path("foo", "bar") == "foo/4e/99/bar"

    def test_identity(self):
        """LFN2PFN: Translate to path using identity (Success)"""
        translator = RSEDeterministicTranslation(
            rse=self.rse,
            rse_attributes={
                'rse': self.rse,
                'lfn2pfn_algorithm': 'identity',
            },
            protocol_attributes=self.protocol_attributes,
        )
        assert translator.path("foo", "bar") == "foo/bar"

    @pytest.mark.skipif(os.environ.get('POLICY') != 'atlas', reason='Test ATLAS hash convention')
    def test_user_scope(self):
        """LFN2PFN: Test special user scope rules (Success)"""
        translator = RSEDeterministicTranslation(
            rse=self.rse,
            rse_attributes={
                'rse': self.rse,
            },
            protocol_attributes=self.protocol_attributes,
        )
        assert translator.path("user.foo", "bar") == "user/foo/13/7f/bar"

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

        translator = RSEDeterministicTranslation(
            rse=self.rse,
            rse_attributes={
                'rse': self.rse,
                'lfn2pfn_algorithm': 'static_register_test1',
            },
            protocol_attributes=self.protocol_attributes,
        )
        assert translator.path("foo", "bar") == "static_register_value1"

        translator = RSEDeterministicTranslation(
            rse=self.rse,
            rse_attributes={
                'rse': self.rse,
                'lfn2pfn_algorithm': 'static_register_custom_name',
            },
            protocol_attributes=self.protocol_attributes,
        )
        assert translator.path("foo", "bar") == "static_register_value2"

    def test_attr_mapping(self):
        """LFN2PFN: Verify we can map using rse and attrs (Successs)"""
        def rse_algorithm(scope, name, rse, rse_attrs, proto_attrs):
            """Test LFN2PATH function for exercising the different RSE/proto attrs."""
            tier = rse_attrs.get("tier", "T1")
            scheme = proto_attrs.get("scheme", "http")
            return "%s://%s_%s/%s/%s" % (scheme, tier, rse, scope, name)
        RSEDeterministicTranslation.register(rse_algorithm)

        rse_attributes = {
            'lfn2pfn_algorithm': 'rse_algorithm',
            'rse': self.rse
        }
        protocol_attributes = copy.copy(self.protocol_attributes)
        translator = RSEDeterministicTranslation(self.rse, rse_attributes, protocol_attributes)
        assert translator.path("foo", "bar") == "http://T1_Mock/foo/bar"

        rse_attributes['tier'] = 'T2'
        translator = RSEDeterministicTranslation(self.rse, rse_attributes, protocol_attributes)
        assert translator.path("foo", "bar") == "http://T2_Mock/foo/bar"

        protocol_attributes['scheme'] = 'https'
        translator = RSEDeterministicTranslation(self.rse, rse_attributes, protocol_attributes)
        assert translator.path("foo", "bar") == "https://T2_Mock/foo/bar"

        protocol_attributes['scheme'] = 'srm'
        translator = RSEDeterministicTranslation(self.rse, rse_attributes, protocol_attributes)
        assert translator.path("foo", "bar") == "srm://T2_Mock/foo/bar"

    def test_module_load(self):
        """LFN2PFN: Test ability to provide LFN2PFN functions via module (Success)"""
        if not config.config_has_section('policy'):
            config.config_add_section('policy')
        config.config_set('policy', 'lfn2pfn_module', 'tests.lfn2pfn_module_test')
        RSEDeterministicTranslation._module_init_()  # pylint: disable=protected-access
        translator = RSEDeterministicTranslation(
            rse=self.rse,
            rse_attributes={
                'lfn2pfn_algorithm': 'lfn2pfn_module_algorithm',
                'rse': self.rse,
            },
            protocol_attributes=self.protocol_attributes,
        )
        assert translator.path("foo", "bar") == "lfn2pfn_module_algorithm_value"

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
            translator = RSEDeterministicTranslation(
                rse=self.rse,
                rse_attributes={'rse': self.rse},
                protocol_attributes=self.protocol_attributes,
            )
            assert translator.path("foo", "bar") == "static_test_value"
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
