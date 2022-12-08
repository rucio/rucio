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

from random import choice
from string import ascii_uppercase, ascii_lowercase

import pytest

from rucio.common.exception import InvalidRSEExpression, RSEWriteBlocked
from rucio.core import rse
from rucio.core import rse_expression_parser


def attribute_name_generator(size=10):
    return ''.join(choice(ascii_uppercase)).join(choice(ascii_lowercase) for x in range(size - 1))


@pytest.mark.noparallel(reason='uses pre-defined RSE, test_all_rse fails when run in parallel')
class TestRSEExpressionParserCore:

    @classmethod
    @pytest.fixture(scope='class')
    def setup_test_env(cls, rse_factory_unittest, tag_factory_class):
        already_existing_rses = rse.list_rses()

        rse1, rse1_id = rse_factory_unittest.make_mock_rse()
        rse2, rse2_id = rse_factory_unittest.make_mock_rse()
        rse3, rse3_id = rse_factory_unittest.make_mock_rse()
        rse4, rse4_id = rse_factory_unittest.make_mock_rse()
        rse5, rse5_id = rse_factory_unittest.make_mock_rse()

        # Add Attributes
        attribute = attribute_name_generator()

        rse.add_rse_attribute(rse1_id, attribute, "at")
        rse.add_rse_attribute(rse2_id, attribute, "de")
        rse.add_rse_attribute(rse3_id, attribute, "fr")
        rse.add_rse_attribute(rse4_id, attribute, "uk")
        rse.add_rse_attribute(rse5_id, attribute, "us")

        # Add numeric Attributes
        attribute_numeric = attribute_name_generator()

        rse.add_rse_attribute(rse1_id, attribute_numeric, 10)
        rse.add_rse_attribute(rse2_id, attribute_numeric, 20)
        rse.add_rse_attribute(rse3_id, attribute_numeric, 30)
        rse.add_rse_attribute(rse4_id, attribute_numeric, 40)
        rse.add_rse_attribute(rse5_id, attribute_numeric, 50)

        # Add Tags
        tag1 = tag_factory_class.new_tag()
        tag2 = tag_factory_class.new_tag()
        rse.add_rse_attribute(rse1_id, tag1, True)
        rse.add_rse_attribute(rse2_id, tag1, True)
        rse.add_rse_attribute(rse3_id, tag1, True)
        rse.add_rse_attribute(rse4_id, tag2, True)
        rse.add_rse_attribute(rse5_id, tag2, True)

        return (rse1, rse1_id, rse2, rse2_id, rse3, rse3_id, rse4, rse4_id, rse5, rse5_id,
                attribute, attribute_numeric, tag1, tag2, already_existing_rses)

    @pytest.fixture(autouse=True)
    def setup_obj(self, setup_test_env, vo):
        self.filter = {'filter_': {'vo': vo}}
        (
            self.rse1, self.rse1_id, self.rse2, self.rse2_id, self.rse3, self.rse3_id, self.rse4, self.rse4_id, self.rse5, self.rse5_id,
            self.attribute, self.attribute_numeric, self.tag1, self.tag2, self.already_existing_rses,
        ) = setup_test_env

    def test_unconnected_operator(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test invalid rse expression: unconnected operator"""
        with pytest.raises(InvalidRSEExpression):
            rse_expression_parser.parse_expression("TEST_RSE1|", **self.filter)

    def test_wrong_parantheses(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test invalid rse expression: wrong parantheses """
        with pytest.raises(InvalidRSEExpression):
            rse_expression_parser.parse_expression("TEST_RSE1)", **self.filter)

    def test_unknown_rse(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test unknown RSE """
        with pytest.raises(InvalidRSEExpression):
            rse_expression_parser.parse_expression("TEST_RSE999", **self.filter)

    def test_simple_rse_reference(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test simple RSE reference """
        value = [t_rse['id'] for t_rse in rse_expression_parser.parse_expression(self.rse1, **self.filter)]
        assert value == [self.rse1_id]

    def test_attribute_reference(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test simple RSE attribute reference """
        value = [t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s=uk" % self.attribute, **self.filter)]
        assert value == [self.rse4_id]

    def test_all_rse(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test reference on all RSE """
        all_rses = rse.list_rses(filters=self.filter['filter_'])
        rse_expression_parser.REGION.invalidate()
        value = rse_expression_parser.parse_expression("*", **self.filter)
        for rse_ in self.already_existing_rses:
            if rse_ in all_rses:
                all_rses.remove(rse_)
            if rse_ in value:
                value.remove(rse_)
        value = sorted(value, key=lambda rse_: rse_['rse'])
        expected = sorted(all_rses, key=lambda rse_: rse_['rse'])
        assert len(value) == 5
        assert value == expected

    def test_tag_reference(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test simple RSE tag reference """
        value = sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression(self.tag1, **self.filter)])
        expected = sorted([self.rse1_id, self.rse2_id, self.rse3_id])
        assert value == expected

    def test_parantheses(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test parantheses """
        value = sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("(%s)" % self.tag1, **self.filter)])
        expected = sorted([self.rse1_id, self.rse2_id, self.rse3_id])
        assert value == expected

    def test_union(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test union operator """
        value = sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s|%s" % (self.tag1, self.tag2), **self.filter)])
        expected = sorted([self.rse1_id, self.rse2_id, self.rse3_id, self.rse4_id, self.rse5_id])
        assert value == expected

    def test_complement(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test complement operator """
        value = sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s\\%s" % (self.tag1, self.rse3), **self.filter)])
        expected = sorted([self.rse1_id, self.rse2_id])
        assert value == expected

    def test_intersect(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test intersect operator """
        value = [t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s&%s=uk" % (self.tag2, self.attribute), **self.filter)]
        assert value == [self.rse4_id]

    def test_order_of_operations(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test order of operations """
        value = sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s\\%s|%s=fr" % (self.tag1, self.rse3, self.attribute), **self.filter)])
        expected = sorted([self.rse1_id, self.rse2_id, self.rse3_id])
        assert value == expected
        value = sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s\\(%s|%s=fr)" % (self.tag1, self.rse3, self.attribute), **self.filter)])
        expected = sorted([self.rse1_id, self.rse2_id])
        assert value == expected

    def test_complicated_expression_1(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test some complicated expression 1"""
        value = sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("(%s|%s)\\%s|%s&%s" % (self.tag1, self.tag2, self.tag2, self.tag2, self.tag1), **self.filter)])
        expected = sorted([self.rse1_id, self.rse2_id, self.rse3_id])
        assert value == expected

    def test_complicated_expression_2(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test some complicated expression 2"""
        value = sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("(((((%s))))|%s=us)&%s|(%s=at|%s=de)" % (self.tag1, self.attribute, self.tag2, self.attribute, self.attribute), **self.filter)])
        expected = sorted([self.rse1_id, self.rse2_id, self.rse5_id])
        assert value == expected

    def test_complicated_expression_3(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test some complicated expression 3"""
        value = sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("(*)&%s=at" % self.attribute, **self.filter)])
        expected = sorted([self.rse1_id])
        assert value == expected

    def test_list_on_availability(self, rse_factory):
        """ RSE_EXPRESSION_PARSER (CORE) List rses based on availability filter"""
        rsewrite_name, rsewrite_id = rse_factory.make_mock_rse()
        rsenowrite_name, rsenowrite_id = rse_factory.make_mock_rse()

        attribute = attribute_name_generator()

        rse.add_rse_attribute(rsewrite_id, attribute, "de")
        rse.add_rse_attribute(rsenowrite_id, attribute, "de")

        rse.update_rse(rsewrite_id, {'availability_write': True})
        rse.update_rse(rsenowrite_id, {'availability_write': False})

        value = sorted([item['id'] for item in rse_expression_parser.parse_expression("%s=de" % attribute, **self.filter)])
        expected = sorted([rsewrite_id, rsenowrite_id])
        assert value == expected

        filters = self.filter
        filters['availability_write'] = True
        value = sorted([item['id'] for item in rse_expression_parser.parse_expression("%s=de" % attribute, filters)])
        expected = sorted([rsewrite_id])
        assert value == expected

        filters['availability_write'] = False
        pytest.raises(RSEWriteBlocked, rse_expression_parser.parse_expression, "%s=de" % attribute, filters)

    def test_numeric_operators(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test RSE attributes with numeric operations """
        value = [t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s<11" % self.attribute_numeric, **self.filter)]
        assert value == [self.rse1_id]
        pytest.raises(InvalidRSEExpression, rse_expression_parser.parse_expression, "%s<9" % self.attribute_numeric, **self.filter)
        value = sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s<21" % self.attribute_numeric, **self.filter)])
        expected = sorted([self.rse1_id, self.rse2_id])
        assert value == expected
        value = [t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s>49" % self.attribute_numeric, **self.filter)]
        assert value == [self.rse5_id]
        pytest.raises(InvalidRSEExpression, rse_expression_parser.parse_expression, "%s>51" % self.attribute_numeric, **self.filter)
        value = sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s>30" % self.attribute_numeric, **self.filter)])
        expected = sorted([self.rse4_id, self.rse5_id])
        assert value == expected


@pytest.mark.noparallel(reason='uses pre-defined RSE')
class TestRSEExpressionParserClient:

    @pytest.fixture(autouse=True)
    def setup_obj(self, rse_factory, tag_factory):
        self.rse1, self.rse1_id = rse_factory.make_mock_rse()
        self.rse2, self.rse2_id = rse_factory.make_mock_rse()
        self.rse3, self.rse3_id = rse_factory.make_mock_rse()
        self.rse4, self.rse4_id = rse_factory.make_mock_rse()
        self.rse5, self.rse5_id = rse_factory.make_mock_rse()

        # Add Attributes
        self.attribute = attribute_name_generator()

        rse.add_rse_attribute(self.rse1_id, self.attribute, "at")
        rse.add_rse_attribute(self.rse2_id, self.attribute, "de")
        rse.add_rse_attribute(self.rse3_id, self.attribute, "fr")
        rse.add_rse_attribute(self.rse4_id, self.attribute, "uk")
        rse.add_rse_attribute(self.rse5_id, self.attribute, "us")

        # Add Tags
        self.tag1 = tag_factory.new_tag()
        self.tag2 = tag_factory.new_tag()
        rse.add_rse_attribute(self.rse1_id, self.tag1, True)
        rse.add_rse_attribute(self.rse2_id, self.tag1, True)
        rse.add_rse_attribute(self.rse3_id, self.tag1, True)
        rse.add_rse_attribute(self.rse4_id, self.tag2, True)
        rse.add_rse_attribute(self.rse5_id, self.tag2, True)

    def test_complicated_expression(self, rse_client):
        """ RSE_EXPRESSION_PARSER (CLIENT) Test some complicated expression"""
        rses = sorted([item['rse'] for item in rse_client.list_rses("(((((%s))))|%s=us)&%s|(%s=at|%s=de)" % (self.tag1, self.attribute, self.tag2, self.attribute, self.attribute))])
        expected = sorted([self.rse1, self.rse2, self.rse5])
        assert rses == expected

    def test_complicated_expression_1(self, rse_client):
        """ RSE_EXPRESSION_PARSER (CORE) Test some complicated expression 1"""
        rses = sorted([item['rse'] for item in rse_client.list_rses("(%s|%s)\\%s|%s&%s" % (self.tag1, self.tag2, self.tag2, self.tag2, self.tag1))])
        expected = sorted([self.rse1, self.rse2, self.rse3])
        assert rses == expected
