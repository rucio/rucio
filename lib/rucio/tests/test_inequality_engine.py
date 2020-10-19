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
from rucio.core.did_meta_plugins.inequality_engine import *

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
                string = 'A'+op+'B'
                control = 'A'+translated_op+'B'
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

        for i,r in enumerate(result):
            self.assertEqual(r, control[i])

    def test_ConvertNonTernary(self):
        string = "87 < test"
        control = ["87 < test"]
        result = convert_ternary(string)

        for i,r in enumerate(result):
            self.assertEqual(r, control[i])

    def test_ConvertTernary2(self):
        string = "87 == test < 7"
        control = ["87 == test", "test < 7"]
        result = convert_ternary(string)

        for i,r in enumerate(result):
            self.assertEqual(r, control[i])

    def test_ConvertTernary3(self):
        string = "87 == test == 7"
        control = ["87 == test", "test == 7"]
        result = convert_ternary(string)

        for i,r in enumerate(result):
            self.assertEqual(r, control[i])


class TestExpandMetadata(unittest.TestCase):

    def test_ExpandMetadata(self):
        string = "87 < length"
        control = "87 < "+DEFAULT_MODEL+".length"
        self.assertEqual(control, expand_metadata(string))

    def test_ExpandNoMetadata(self):
        string = "87 < doesnt_exist"
        self.assertEqual(string, expand_metadata(string))


class TestGetDict(unittest.TestCase):

    def test_GetDict(self):
        string87 = "87 < "+DEFAULT_MODEL+".length"
        control = { 'model' : DEFAULT_MODEL, 'field' : 'length', 'op' : '>', 'value' : '87'}
        print(get_dict(string87))
        self.assertEqual(get_dict(string87), control)


class TestInequalityEngine(unittest.TestCase):

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


if __name__ == '__main__':
    unittest.main()