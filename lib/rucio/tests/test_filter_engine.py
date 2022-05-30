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

import operator
from datetime import datetime, timedelta
import unittest

from rucio.common.exception import DuplicateCriteriaInDIDFilter
from rucio.common.config import config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core.did import add_did
from rucio.core.did_meta_plugins import set_metadata
from rucio.db.sqla import models
from rucio.db.sqla.session import read_session
from rucio.db.sqla.util import json_implemented
from rucio.core.did_meta_plugins.filter_engine import FilterEngine
from rucio.tests.common_server import get_vo


class TestFilterEngineDummy(unittest.TestCase):
    def test_InputSanitisation(self):
        filters = FilterEngine('  TestKeyword1  =  True  ,  TestKeyword2   =   0; 1 < TestKeyword4 <= 2', strict_coerce=False).filters
        filters_expected = [[('TestKeyword1', operator.eq, 1),
                             ('TestKeyword2', operator.eq, 0)],
                            [('TestKeyword4', operator.gt, 1),
                            ('TestKeyword4', operator.le, 2)]]
        self.assertEqual(filters, filters_expected)

        with self.assertRaises(ValueError):
            FilterEngine('did_type >= 1', strict_coerce=False)

        with self.assertRaises(ValueError):
            FilterEngine('name >= 1', strict_coerce=False)

        with self.assertRaises(ValueError):
            FilterEngine('length >= test', strict_coerce=False)

        with self.assertRaises(ValueError):
            FilterEngine('name >= *', strict_coerce=False)

    def test_OperatorsEqualNotEqual(self):
        self.assertTrue(FilterEngine('True = True', strict_coerce=False).evaluate())
        self.assertTrue(FilterEngine('True != False', strict_coerce=False).evaluate())

    def test_OneSidedInequality(self):
        self.assertTrue(FilterEngine('1 < 2', strict_coerce=False).evaluate())
        self.assertFalse(FilterEngine('1 > 2', strict_coerce=False).evaluate())
        self.assertTrue(FilterEngine('1 <= 1', strict_coerce=False).evaluate())
        self.assertTrue(FilterEngine('1 >= 1', strict_coerce=False).evaluate())

    def test_CompoundInequality(self):
        self.assertTrue(FilterEngine('3 > 2 > 1', strict_coerce=False).evaluate())
        self.assertFalse(FilterEngine('1 > 2 > 3', strict_coerce=False).evaluate())
        with self.assertRaises(DuplicateCriteriaInDIDFilter):
            FilterEngine('1 < 2 > 3', strict_coerce=False)
        with self.assertRaises(DuplicateCriteriaInDIDFilter):
            FilterEngine('1 < 2 > 3', strict_coerce=False)

    def test_AndGroups(self):
        self.assertTrue(FilterEngine('True = True, False = False', strict_coerce=False).evaluate())
        self.assertFalse(FilterEngine('True = True, False = True', strict_coerce=False).evaluate())
        self.assertTrue(FilterEngine('3 > 2, 2 > 1', strict_coerce=False).evaluate())
        self.assertFalse(FilterEngine('1 > 2, 2 > 1', strict_coerce=False).evaluate())
        self.assertFalse(FilterEngine('1 > 2, 2 > 3', strict_coerce=False).evaluate())
        self.assertFalse(FilterEngine('1 > 2, 4 > 3 > 2', strict_coerce=False).evaluate())

    def test_OrGroups(self):
        self.assertTrue(FilterEngine('True = True; True = True', strict_coerce=False).evaluate())
        self.assertTrue(FilterEngine('True = True; True = False', strict_coerce=False).evaluate())
        self.assertFalse(FilterEngine('True = False; False = True', strict_coerce=False).evaluate())
        self.assertTrue(FilterEngine('3 > 2; 2 > 1', strict_coerce=False).evaluate())
        self.assertTrue(FilterEngine('1 > 2; 2 > 1', strict_coerce=False).evaluate())
        self.assertFalse(FilterEngine('1 > 2; 2 > 3', strict_coerce=False).evaluate())
        self.assertTrue(FilterEngine('1 > 2; 4 > 3 > 2', strict_coerce=False).evaluate())

    def test_AndOrGroups(self):
        self.assertTrue(FilterEngine('1 > 2, 4 > 3 > 2; True=True', strict_coerce=False).evaluate())
        self.assertFalse(FilterEngine('1 > 2, 4 > 3 > 2; True=False', strict_coerce=False).evaluate())

    def test_BackwardsCompatibilityCreatedAfter(self):
        test_expressions = {
            "created_after=1900-01-01 00:00:00": [[('created_at', operator.ge, datetime(1900, 1, 1, 0, 0))]],
            "created_after=1900-01-01T00:00:00": [[('created_at', operator.ge, datetime(1900, 1, 1, 0, 0))]],
            "created_after=1900-01-01 00:00:00.000Z": [[('created_at', operator.ge, datetime(1900, 1, 1, 0, 0))]],
            "created_after=1900-01-01T00:00:00.000Z": [[('created_at', operator.ge, datetime(1900, 1, 1, 0, 0))]]
        }
        for input_datetime_expression, filters_expected in test_expressions.items():
            filters = FilterEngine(input_datetime_expression, strict_coerce=False).filters
            self.assertEqual(filters, filters_expected)

    def test_BackwardsCompatibilityCreatedBefore(self):
        test_expressions = {
            "created_before=1900-01-01 00:00:00": [[('created_at', operator.le, datetime(1900, 1, 1, 0, 0))]],
            "created_before=1900-01-01T00:00:00": [[('created_at', operator.le, datetime(1900, 1, 1, 0, 0))]],
            "created_before=1900-01-01 00:00:00.000Z": [[('created_at', operator.le, datetime(1900, 1, 1, 0, 0))]],
            "created_before=1900-01-01T00:00:00.000Z": [[('created_at', operator.le, datetime(1900, 1, 1, 0, 0))]]
        }
        for input_datetime_expression, filters_expected in test_expressions.items():
            filters = FilterEngine(input_datetime_expression, strict_coerce=False).filters
            self.assertEqual(filters, filters_expected)

    def test_BackwardsCompatibilityLength(self):
        test_expressions = {
            'length > 0': [[('length', operator.gt, 0)]],
            'length < 0': [[('length', operator.lt, 0)]],
            'length >= 0': [[('length', operator.ge, 0)]],
            'length <= 0': [[('length', operator.le, 0)]],
            'length == 0': [[('length', operator.eq, 0)]]
        }
        for input_length_expression, filters_expected in test_expressions.items():
            filters = FilterEngine(input_length_expression, strict_coerce=False).filters
            self.assertEqual(filters, filters_expected)

    def test_typecastString(self):
        test_expressions = {
            'testkeyint1 = 0': int,
            'testkeyfloat1 = 0.5': float,
            'testkeystr1 = test': str,
            'testbool1 = false': bool,
            'testbool2 = False': bool,
            'testbool3 = FALSE': bool,
            'testbool4 = true': bool,
            'testbool5 = True': bool,
            'testbool6 = TRUE': bool,
            'testkeydate1 = 1900-01-01 00:00:00': datetime,
            'testkeydate2 = 1900-01-01 00:00:00.000Z': datetime,
            'testkeydate3 = 1900-01-01T00:00:00': datetime,
            'testkeydate4 = 1900-01-01T00:00:00.000Z': datetime
        }
        for input_length_expression, type_expected in test_expressions.items():
            filters = FilterEngine(input_length_expression, strict_coerce=False).filters
            self.assertIsInstance(filters[0][0][2], type_expected)


class TestFilterEngineReal(unittest.TestCase):
    def setUp(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': get_vo()}
        else:
            self.vo = {}
        self.tmp_scope = InternalScope('mock', **self.vo)
        self.root = InternalAccount('root', **self.vo)

    def _create_tmp_DID(self, type='DATASET'):
        did_name = 'fe_test_did_%s' % generate_uuid()
        add_did(scope=self.tmp_scope, name=did_name, did_type='DATASET', account=self.root)
        return did_name

    @read_session
    def test_OperatorsEqualNotEqual(self, session=None):
        # Plugin: DID
        #
        did_name1 = self._create_tmp_DID()
        did_name2 = self._create_tmp_DID()
        did_name3 = self._create_tmp_DID()
        set_metadata(scope=self.tmp_scope, name=did_name1, key='run_number', value=1)
        set_metadata(scope=self.tmp_scope, name=did_name2, key='run_number', value=2)

        dids = []
        q = FilterEngine('run_number=1', model_class=models.DataIdentifier).create_sqla_query(
            additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 1)

        dids = []
        q = FilterEngine('run_number!=1', model_class=models.DataIdentifier).create_sqla_query(
            additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 2)     # 1, 3 (NULL counted in not equals)

        # Plugin: JSON
        #
        if json_implemented(session=session):
            did_name1 = self._create_tmp_DID()
            did_name2 = self._create_tmp_DID()
            did_name3 = self._create_tmp_DID()
            set_metadata(scope=self.tmp_scope, name=did_name1, key='testkeyint1', value=1)
            set_metadata(scope=self.tmp_scope, name=did_name2, key='testkeyint2', value=2)
            set_metadata(scope=self.tmp_scope, name=did_name3, key='testkeyint3', value=2)

            dids = []
            q = FilterEngine('testkeyint1=1', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 1)

        if json_implemented(session=session):
            dids = []
            q = FilterEngine('testkeyint1!=1', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 0)

    @read_session
    def test_OneSidedInequality(self, session=None):
        # Plugin: DID
        #
        did_name = self._create_tmp_DID()
        set_metadata(scope=self.tmp_scope, name=did_name, key='run_number', value=1)

        dids = []
        q = FilterEngine('run_number > 0', model_class=models.DataIdentifier).create_sqla_query(
            additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

        dids = []
        q = FilterEngine('run_number < 2', model_class=models.DataIdentifier).create_sqla_query(
            additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

        dids = []
        q = FilterEngine('run_number < 0', model_class=models.DataIdentifier).create_sqla_query(
            additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertNotEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

        dids = []
        q = FilterEngine('run_number > 2', model_class=models.DataIdentifier).create_sqla_query(
            additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertNotEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

        # Plugin: JSON
        #
        if json_implemented(session=session):
            did_name = self._create_tmp_DID()
            set_metadata(scope=self.tmp_scope, name=did_name, key='testkeyint1', value=1)

            dids = []
            q = FilterEngine('testkeyint1 > 0', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

            dids = []
            q = FilterEngine('testkeyint1 < 2', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

            dids = []
            q = FilterEngine('testkeyint1 < 0', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertNotEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

            dids = []
            q = FilterEngine('testkeyint1 > 2', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertNotEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

    @read_session
    def test_CompoundInequality(self, session=None):
        # Plugin: DID
        #
        did_name = self._create_tmp_DID()
        set_metadata(scope=self.tmp_scope, name=did_name, key='run_number', value=1)

        dids = []
        q = FilterEngine('0 < run_number < 2', model_class=models.DataIdentifier).create_sqla_query(
            additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

        dids = []
        q = FilterEngine('0 < run_number <= 1', model_class=models.DataIdentifier).create_sqla_query(
            additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

        dids = []
        q = FilterEngine('0 <= run_number < 1', model_class=models.DataIdentifier).create_sqla_query(
            additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertNotEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

        # Plugin: JSON
        #
        if json_implemented(session=session):
            did_name = self._create_tmp_DID()
            set_metadata(scope=self.tmp_scope, name=did_name, key='testkeyint1', value=1)

            dids = []
            q = FilterEngine('0 < testkeyint1 < 2', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

            dids = []
            q = FilterEngine('0 < testkeyint1 <= 1', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

            dids = []
            q = FilterEngine('0 <= testkeyint1 < 1', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertNotEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

    @read_session
    def test_AndGroups(self, session=None):
        # Plugin: DID
        #
        did_name1 = self._create_tmp_DID()
        did_name2 = self._create_tmp_DID()
        did_name3 = self._create_tmp_DID()
        set_metadata(scope=self.tmp_scope, name=did_name1, key='run_number', value='1')
        set_metadata(scope=self.tmp_scope, name=did_name2, key='project', value="test")
        set_metadata(scope=self.tmp_scope, name=did_name3, key='run_number', value='1')
        set_metadata(scope=self.tmp_scope, name=did_name3, key='project', value="test")

        dids = []
        q = FilterEngine('run_number = 1, project = test', model_class=models.DataIdentifier).create_sqla_query(
            additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 1)     # 3

        dids = []
        q = FilterEngine('run_number = 1, project != test', model_class=models.DataIdentifier).create_sqla_query(
            additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 1)     # 1

        # Plugin: JSON
        #
        if json_implemented(session=session):
            did_name1 = self._create_tmp_DID()
            did_name2 = self._create_tmp_DID()
            did_name3 = self._create_tmp_DID()
            set_metadata(scope=self.tmp_scope, name=did_name1, key='testkeyint1', value='1')
            set_metadata(scope=self.tmp_scope, name=did_name2, key='testkeystr1', value="test")
            set_metadata(scope=self.tmp_scope, name=did_name3, key='testkeyint1', value='1')
            set_metadata(scope=self.tmp_scope, name=did_name3, key='testkeystr1', value="test")

            dids = []
            q = FilterEngine('testkeyint1 = 1, testkeystr1 = test', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 1)     # 3

            dids = []
            q = FilterEngine('testkeyint1 = 1, testkeystr1 != test', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 0)

    @read_session
    def test_OrGroups(self, session=None):
        # Plugin: DID
        #
        did_name1 = self._create_tmp_DID()
        did_name2 = self._create_tmp_DID()
        did_name3 = self._create_tmp_DID()
        set_metadata(scope=self.tmp_scope, name=did_name1, key='run_number', value='1')
        set_metadata(scope=self.tmp_scope, name=did_name2, key='project', value="test")
        set_metadata(scope=self.tmp_scope, name=did_name3, key='run_number', value='1')
        set_metadata(scope=self.tmp_scope, name=did_name3, key='project', value="test")

        dids = []
        q = FilterEngine('run_number = 1; project = test', model_class=models.DataIdentifier).create_sqla_query(
            additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 3)     # 1, 2, 3

        dids = []
        q = FilterEngine('run_number = 1; project != test', model_class=models.DataIdentifier).create_sqla_query(
            additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 2)     # 1, 3

        dids = []
        q = FilterEngine('run_number = 0; run_number = 1', model_class=models.DataIdentifier).create_sqla_query(
            additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 2)     # 1, 3

        dids = []
        q = FilterEngine('run_number = 0; run_number = 3', model_class=models.DataIdentifier).create_sqla_query(
            additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 0)

        dids = []
        q = FilterEngine('name = {}; name = {}; name = {}'.format(did_name1, did_name2, did_name3), model_class=models.DataIdentifier).create_sqla_query(
            additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 3)     # 1, 2, 3

        # Plugin: JSON
        #
        if json_implemented(session=session):
            did_name1 = self._create_tmp_DID()
            did_name2 = self._create_tmp_DID()
            did_name3 = self._create_tmp_DID()
            set_metadata(scope=self.tmp_scope, name=did_name1, key='testkeyint1', value='1')
            set_metadata(scope=self.tmp_scope, name=did_name2, key='testkeystr1', value="test")
            set_metadata(scope=self.tmp_scope, name=did_name3, key='testkeyint1', value='1')
            set_metadata(scope=self.tmp_scope, name=did_name3, key='testkeystr1', value="test")

            dids = []
            q = FilterEngine('testkeyint1 = 1; testkeystr1 = test', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 3)     # 1, 2, 3

            dids = []
            q = FilterEngine('testkeyint1 = 1; testkeystr1 != test', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 2)     # 1, 3

            dids = []
            q = FilterEngine('testkeyint1 = 0; testkeyint1 = 1', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 2)     # 1, 3

            dids = []
            q = FilterEngine('testkeyint1 = 0; testkeyint1 = 3', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 0)

            dids = []
            q = FilterEngine('name = {}; name = {}; name = {}'.format(did_name1, did_name2, did_name3), model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 3)     # 1, 2, 3

    @read_session
    def test_AndOrGroups(self, session=None):
        # Plugin: DID
        #
        did_name1 = self._create_tmp_DID()
        did_name2 = self._create_tmp_DID()
        did_name3 = self._create_tmp_DID()
        set_metadata(scope=self.tmp_scope, name=did_name1, key='run_number', value='1')
        set_metadata(scope=self.tmp_scope, name=did_name2, key='project', value="test")
        set_metadata(scope=self.tmp_scope, name=did_name3, key='run_number', value='1')
        set_metadata(scope=self.tmp_scope, name=did_name3, key='project', value="test")

        dids = []
        q = FilterEngine('run_number = 1, project != test; project = test', model_class=models.DataIdentifier).create_sqla_query(additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 3)     # 1, 2, 3

        dids = []
        q = FilterEngine('run_number = 1, project = test; run_number != 1', model_class=models.DataIdentifier).create_sqla_query(additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 2)     # 2, 3

        # Plugin: JSON
        #
        if json_implemented(session=session):
            did_name1 = self._create_tmp_DID()
            did_name2 = self._create_tmp_DID()
            did_name3 = self._create_tmp_DID()
            set_metadata(scope=self.tmp_scope, name=did_name1, key='testkeyint1', value='1')
            set_metadata(scope=self.tmp_scope, name=did_name2, key='testkeystr1', value="test")
            set_metadata(scope=self.tmp_scope, name=did_name3, key='testkeyint1', value='1')
            set_metadata(scope=self.tmp_scope, name=did_name3, key='testkeystr1', value="test")

            dids = []
            q = FilterEngine('testkeyint1 = 1, testkeystr1 != test; testkeystr1 = test', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 2)     # 2, 3

            dids = []
            q = FilterEngine('testkeyint1 = 1, testkeystr1 = test; testkeyint1 != 1', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3), dids)).count(True), 1)     # 3

    @read_session
    def test_BackwardsCompatibilityCreatedAfter(self, session=None):
        before = datetime.strftime(datetime.now() - timedelta(seconds=1), "%Y-%m-%dT%H:%M:%S.%fZ")  # w/ -1s buffer
        did_name = self._create_tmp_DID()

        dids = []
        q = FilterEngine('created_after={}'.format(before), model_class=models.DataIdentifier).create_sqla_query(additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

    @read_session
    def test_BackwardsCompatibilityCreatedBefore(self, session=None):
        did_name = self._create_tmp_DID()
        after = datetime.strftime(datetime.now() + timedelta(seconds=1), "%Y-%m-%dT%H:%M:%S.%fZ")  # w/ +1s buffer

        dids = []
        q = FilterEngine('created_before={}'.format(after), model_class=models.DataIdentifier).create_sqla_query(additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

    @read_session
    def test_BackwardsCompatibilityLength(self, session=None):
        did_name = self._create_tmp_DID()
        set_metadata(scope=self.tmp_scope, name=did_name, key='length', value='10')

        dids = []
        q = FilterEngine('length >= 10', model_class=models.DataIdentifier).create_sqla_query(additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

        dids = []
        q = FilterEngine('length > 9', model_class=models.DataIdentifier).create_sqla_query(additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

        dids = []
        q = FilterEngine('length <= 10', model_class=models.DataIdentifier).create_sqla_query(additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

        dids = []
        q = FilterEngine('length < 11', model_class=models.DataIdentifier).create_sqla_query(additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name == did_name, dids)).count(True), 1)

    @read_session
    def test_Wildcards(self, session=None):
        # Plugin: DID
        #
        did_name1 = self._create_tmp_DID()
        did_name2 = self._create_tmp_DID()
        did_name3 = self._create_tmp_DID()
        did_name4 = self._create_tmp_DID()
        did_name5 = self._create_tmp_DID()
        set_metadata(scope=self.tmp_scope, name=did_name1, key='project', value="test1")
        set_metadata(scope=self.tmp_scope, name=did_name2, key='project', value="test2")
        set_metadata(scope=self.tmp_scope, name=did_name3, key='project', value="anothertest1")
        set_metadata(scope=self.tmp_scope, name=did_name4, key='project', value="anothertest2")

        dids = []
        q = FilterEngine('project = test*', model_class=models.DataIdentifier).create_sqla_query(additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3, did_name4, did_name5), dids)).count(True), 2)  # 1, 2

        dids = []
        q = FilterEngine('project = *test*', model_class=models.DataIdentifier).create_sqla_query(additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3, did_name4, did_name5), dids)).count(True), 4)  # 1, 2, 3, 4

        dids = []
        q = FilterEngine('project != *anothertest*', model_class=models.DataIdentifier).create_sqla_query(additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3, did_name4, did_name5), dids)).count(True), 3)  # 3, 4, 5 (NULL counted in not equals)

        dids = []
        q = FilterEngine('project != *test*', model_class=models.DataIdentifier).create_sqla_query(additional_model_attributes=[models.DataIdentifier.name])
        dids += [did for did in q.yield_per(5)]
        dids = set(dids)
        self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3, did_name4, did_name5), dids)).count(True), 1)  # 5 (NULL counted in not equals)

        # Plugin: JSON
        #
        if json_implemented(session=session):
            did_name1 = self._create_tmp_DID()
            did_name2 = self._create_tmp_DID()
            did_name3 = self._create_tmp_DID()
            did_name4 = self._create_tmp_DID()
            did_name5 = self._create_tmp_DID()
            set_metadata(scope=self.tmp_scope, name=did_name1, key='testkeystr1', value="test1")
            set_metadata(scope=self.tmp_scope, name=did_name2, key='testkeystr1', value="test2")
            set_metadata(scope=self.tmp_scope, name=did_name3, key='testkeystr1', value="anothertest1")
            set_metadata(scope=self.tmp_scope, name=did_name4, key='testkeystr1', value="anothertest2")

            dids = []
            q = FilterEngine('testkeystr1 = test*', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3, did_name4, did_name5), dids)).count(True), 2)  # 1, 2

            dids = []
            q = FilterEngine('testkeystr1 = *test*', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                additional_model_attributes=[
                    models.DidMeta.scope,
                    models.DidMeta.name
                ],
                json_column=models.DidMeta.meta)
            dids += [did for did in q.yield_per(5)]
            dids = set(dids)
            self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3, did_name4, did_name5), dids)).count(True), 4)  # 1, 2, 3, 4

            if session.bind.dialect.name != 'oracle':
                dids = []
                q = FilterEngine('testkeystr1 != *anothertest*', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                    additional_model_attributes=[
                        models.DidMeta.scope,
                        models.DidMeta.name
                    ],
                    json_column=models.DidMeta.meta)
                dids += [did for did in q.yield_per(5)]
                dids = set(dids)
                self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3, did_name4, did_name5), dids)).count(True), 2)  # 3, 4

                dids = []
                q = FilterEngine('testkeystr1 != *test*', model_class=models.DidMeta, strict_coerce=False).create_sqla_query(
                    additional_model_attributes=[
                        models.DidMeta.scope,
                        models.DidMeta.name
                    ],
                    json_column=models.DidMeta.meta)
                dids += [did for did in q.yield_per(5)]
                dids = set(dids)
                self.assertEqual(list(map(lambda did: did.name in (did_name1, did_name2, did_name3, did_name4, did_name5), dids)).count(True), 0)


if __name__ == '__main__':
    unittest.main()
