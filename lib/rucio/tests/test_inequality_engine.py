# -*- coding: utf-8 -*-
# Copyright 2013-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Gabriele Gaetano Fronzé <gfronze@cern.ch>, 2020
#
# PY3K COMPATIBLE

import unittest
from rucio.common.config import config_get, config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core.did import add_did
from rucio.core.did_meta_plugins import set_metadata
from rucio.db.sqla.session import read_session
from rucio.core.did_meta_plugins.inequality_engine import DEFAULT_MODEL, OP, clear_double_spaces, translate, get_num_op, convert_ternary, expand_metadata, condition_split, flip_if_needed, inequality_engine


class TestClearDoubleSpaces(unittest.TestCase):

    def test_ClearDoubleSpaces(self):
        string = 'test string        contains    multiple           repeated spaces      '
        control = 'test string contains multiple repeated spaces'
        self.assertEqual(clear_double_spaces(string), control)


class TestTranslate(unittest.TestCase):

    def test_Translate(self):
        for translated_op in OP.keys():
            op_list = OP[translated_op]
            for op in op_list:
                string = 'A' + op + 'B'
                control = 'A' + translated_op + 'B'
                self.assertEqual(translate(string), control)


class TestGetNumOP(unittest.TestCase):

    def test_GetNumOP(self):
        string = "87 < test < 100"
        self.assertEqual(get_num_op(string), 2)

        string = "test == 100"
        self.assertEqual(get_num_op(string), 1)

        string = "87 <= test"
        self.assertEqual(get_num_op(string), 1)


class TestConvertTernary(unittest.TestCase):

    def test_ConvertTernary(self):
        string = "87 < test < 100"
        control = ["87 < test", "test < 100"]
        result = convert_ternary(string)

        for i, r in enumerate(result):
            self.assertEqual(r, control[i])

    def test_ConvertNonTernary(self):
        string = "87 < test"
        control = ["87 < test"]
        result = convert_ternary(string)

        for i, r in enumerate(result):
            self.assertEqual(r, control[i])

    def test_ConvertTernary2(self):
        string = "87 == test < 7"
        control = ["87 == test", "test < 7"]
        result = convert_ternary(string)

        for i, r in enumerate(result):
            self.assertEqual(r, control[i])

    def test_ConvertTernary3(self):
        string = "87 == test == 7"
        control = ["87 == test", "test == 7"]
        result = convert_ternary(string)

        for i, r in enumerate(result):
            self.assertEqual(r, control[i])


class TestExpandMetadata(unittest.TestCase):

    def test_ExpandMetadata(self):
        string = "87 < length"
        control = "87 < " + DEFAULT_MODEL + ".length"
        self.assertEqual(control, expand_metadata(string))

    def test_ExpandNoMetadata(self):
        string = "87 < doesnt_exist"
        self.assertEqual(string, expand_metadata(string))


class TestConditionSplit(unittest.TestCase):

    def test_ConditionSplit_A(self):
        string = "87 < length"
        control = ["87", "<", "length"]
        for i, w in enumerate(condition_split(string)):
            self.assertEqual(w, control[i])

    def test_ConditionSplit_B(self):
        string = "length >= 21"
        control = ["length", ">=", "21"]
        for i, w in enumerate(condition_split(string)):
            self.assertEqual(w, control[i])


class TestFlipIfNeeded(unittest.TestCase):

    def test_FlipIfNeeded_Needed(self):
        string = "87 < length"
        splitted = condition_split(string)
        splitted = flip_if_needed(splitted)
        control = ["length", ">", "87"]
        for i, w in enumerate(splitted):
            self.assertEqual(w, control[i])

    def test_FlipIfNeeded_NotNeeded(self):
        string = "length < 87"
        splitted = condition_split(string)
        splitted = flip_if_needed(splitted)
        control = ["length", "<", "87"]
        for i, w in enumerate(splitted):
            self.assertEqual(w, control[i])


class TestInequalityEngineOffline(unittest.TestCase):

    def test_Base(self):
        string = "True"
        self.assertTrue(inequality_engine(string).run())

        string = "False"
        self.assertFalse(inequality_engine(string).run())

        string = "2 < 8"
        self.assertTrue(inequality_engine(string).run())

        string = "2 > 8"
        self.assertFalse(inequality_engine(string).run())

    def test_AndGroups(self):
        string = "True, True"
        self.assertTrue(inequality_engine(string).run())

        string = "True, False"
        self.assertFalse(inequality_engine(string).run())

        string = "6 >= 6, True"
        self.assertTrue(inequality_engine(string).run())

        string = "5 > 2, 1200-10 < 1200"
        self.assertTrue(inequality_engine(string).run())

        string = "5 == 5, 1200-10 > 1200"
        self.assertFalse(inequality_engine(string).run())

        string = "5 = 5, 1200-10 > 1200"
        self.assertFalse(inequality_engine(string).run())

    def test_OrGroups(self):
        string = "True; True"
        self.assertTrue(inequality_engine(string).run())

        string = "True; False"
        self.assertTrue(inequality_engine(string).run())

        string = "False; False"
        self.assertFalse(inequality_engine(string).run())

        string = "100 >= 42; False"
        self.assertTrue(inequality_engine(string).run())

        string = "100 < 42; False"
        self.assertFalse(inequality_engine(string).run())

        string = "100 < 42; False; 7 > 8; 2**10 == 1024"
        self.assertTrue(inequality_engine(string).run())

    def test_RangeConversion(self):
        string = "2 < 10 < 100"
        self.assertTrue(inequality_engine(string).run())

        string = "20 > 10 < 100"
        self.assertTrue(inequality_engine(string).run())

        string = "2 < 100 <= 100"
        self.assertTrue(inequality_engine(string).run())

        string = "2 < 100 < 100"
        self.assertFalse(inequality_engine(string).run())

        string = "20 > 10 > 100"
        self.assertFalse(inequality_engine(string).run())

        string = "20 >= 20 >= 100"
        self.assertFalse(inequality_engine(string).run())

    def test_InequalityEngine(self):
        string = "True, True; True"
        self.assertTrue(inequality_engine(string).run())

        string = "True, False; True"
        self.assertTrue(inequality_engine(string).run())

        string = "False, False; True"
        self.assertTrue(inequality_engine(string).run())

        string = "False, False; False"
        self.assertFalse(inequality_engine(string).run())


class TestInequalityEngineOnline(unittest.TestCase):

    def setUp(self):
        if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
            self.vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        else:
            self.vo = {}
        self.tmp_scope = InternalScope('mock', **self.vo)
        self.root = InternalAccount('root', **self.vo)

    @read_session
    def test_InequalityEngineEqual(self, session=None):
        did_name = 'inequality_test_did_%s' % generate_uuid()
        add_did(scope=self.tmp_scope, name=did_name, type='DATASET', account=self.root)
        set_metadata(scope=self.tmp_scope, name=did_name, key='length', value='100')

        dids = []
        for q in inequality_engine("length == 100").createQueries():
            dids += [did for did in q.yield_per(5)]

        self.assertTrue(any(map(lambda did: did.name == did_name, dids)))

    @read_session
    def test_InequalityEngineRange(self, session=None):
        did_name = 'inequality_test_did_%s' % generate_uuid()
        add_did(scope=self.tmp_scope, name=did_name, type='DATASET', account=self.root)
        set_metadata(scope=self.tmp_scope, name=did_name, key='length', value='100')

        dids = []
        for q in inequality_engine("99 < length < 101").createQueries():
            dids += [did for did in q.yield_per(5)]

        self.assertTrue(any(map(lambda did: did.name == did_name, dids)))

    @read_session
    def test_InequalityEngineRangeEqual(self, session=None):
        did_name = 'inequality_test_did_%s' % generate_uuid()
        add_did(scope=self.tmp_scope, name=did_name, type='DATASET', account=self.root)
        set_metadata(scope=self.tmp_scope, name=did_name, key='length', value='100')

        dids = []
        for q in inequality_engine("100 <= length < 101").createQueries():
            dids += [did for did in q.yield_per(5)]

        self.assertTrue(any(map(lambda did: did.name == did_name, dids)))

    @read_session
    def test_InequalityEngineOR(self, session=None):
        did_name1 = 'inequality_test_did_%s' % generate_uuid()
        did_name2 = 'inequality_test_did_%s' % generate_uuid()
        add_did(scope=self.tmp_scope, name=did_name1, type='DATASET', account=self.root)
        set_metadata(scope=self.tmp_scope, name=did_name1, key='length', value='77')
        add_did(scope=self.tmp_scope, name=did_name2, type='DATASET', account=self.root)
        set_metadata(scope=self.tmp_scope, name=did_name2, key='length', value='7')

        dids = []
        for q in inequality_engine("length == 7; length == 77").createQueries():
            dids += [did for did in q.yield_per(5)]

        self.assertTrue(any(map(lambda did: did.name == did_name1, dids)))
        self.assertTrue(any(map(lambda did: did.name == did_name2, dids)))

    @read_session
    def test_InequalityEngineAND(self, session=None):
        did_name = 'inequality_test_did_%s' % generate_uuid()
        add_did(scope=self.tmp_scope, name=did_name, type='DATASET', account=self.root)
        set_metadata(scope=self.tmp_scope, name=did_name, key='length', value='88')
        set_metadata(scope=self.tmp_scope, name=did_name, key='run_number', value='42')

        dids = []
        for q in inequality_engine("length == 88, run_number == 42").createQueries():
            dids += [did for did in q.yield_per(5)]

        self.assertTrue(any(map(lambda did: did.name == did_name, dids)))


if __name__ == '__main__':
    unittest.main()
