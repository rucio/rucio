# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2013-2017
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2019

from random import choice
from string import ascii_uppercase, digits, ascii_lowercase

from nose.tools import assert_equal, raises, assert_raises

from rucio.core import rse
from rucio.core import rse_expression_parser
from rucio.client.rseclient import RSEClient
from rucio.common.exception import InvalidRSEExpression, RSEBlacklisted


def rse_name_generator(size=10):
    return 'MOCK_' + ''.join(choice(ascii_uppercase) for x in range(size))


def tag_generator(size_s=10, size_d=2):
    return ''.join(choice(ascii_uppercase) for x in range(size_s)).join(choice(digits) for x in range(size_d))


def attribute_name_generator(size=10):
    return ''.join(choice(ascii_uppercase)).join(choice(ascii_lowercase) for x in range(size - 1))


class TestRSEExpressionParserCore(object):

    def __init__(self):
        self.rse1 = rse_name_generator()
        self.rse2 = rse_name_generator()
        self.rse3 = rse_name_generator()
        self.rse4 = rse_name_generator()
        self.rse5 = rse_name_generator()

        self.rse1_id = rse.add_rse(self.rse1)
        self.rse2_id = rse.add_rse(self.rse2)
        self.rse3_id = rse.add_rse(self.rse3)
        self.rse4_id = rse.add_rse(self.rse4)
        self.rse5_id = rse.add_rse(self.rse5)

        # Add Attributes
        self.attribute = attribute_name_generator()

        rse.add_rse_attribute(self.rse1, self.attribute, "at")
        rse.add_rse_attribute(self.rse2, self.attribute, "de")
        rse.add_rse_attribute(self.rse3, self.attribute, "fr")
        rse.add_rse_attribute(self.rse4, self.attribute, "uk")
        rse.add_rse_attribute(self.rse5, self.attribute, "us")

        # Add numeric Attributes
        self.attribute_numeric = attribute_name_generator()

        rse.add_rse_attribute(self.rse1, self.attribute_numeric, 10)
        rse.add_rse_attribute(self.rse2, self.attribute_numeric, 20)
        rse.add_rse_attribute(self.rse3, self.attribute_numeric, 30)
        rse.add_rse_attribute(self.rse4, self.attribute_numeric, 40)
        rse.add_rse_attribute(self.rse5, self.attribute_numeric, 50)

        # Add Tags
        self.tag1 = tag_generator()
        self.tag2 = tag_generator()
        rse.add_rse_attribute(self.rse1, self.tag1, True)
        rse.add_rse_attribute(self.rse2, self.tag1, True)
        rse.add_rse_attribute(self.rse3, self.tag1, True)
        rse.add_rse_attribute(self.rse4, self.tag2, True)
        rse.add_rse_attribute(self.rse5, self.tag2, True)

    @raises(InvalidRSEExpression)
    def test_unconnected_operator(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test invalid rse expression: unconnected operator"""
        rse_expression_parser.parse_expression("TEST_RSE1|")

    @raises(InvalidRSEExpression)
    def test_wrong_parantheses(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test invalid rse expression: wrong parantheses """
        rse_expression_parser.parse_expression("TEST_RSE1)")

    @raises(InvalidRSEExpression)
    def test_unknown_rse(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test unknown RSE """
        rse_expression_parser.parse_expression("TEST_RSE999")

    def test_simple_rse_reference(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test simple RSE reference """
        assert_equal([t_rse['id'] for t_rse in rse_expression_parser.parse_expression(self.rse1)], [self.rse1_id])

    def test_attribute_reference(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test simple RSE attribute reference """
        assert_equal([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s=uk" % self.attribute)], [self.rse4_id])

    def test_all_rse(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test reference on all RSE """
        all_rses = rse.list_rses()
        assert_equal(sorted(rse_expression_parser.parse_expression("*")), sorted(all_rses))

    def test_tag_reference(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test simple RSE tag reference """
        assert_equal(sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression(self.tag1)]), sorted([self.rse1_id, self.rse2_id, self.rse3_id]))

    def test_parantheses(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test parantheses """
        assert_equal(sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("(%s)" % self.tag1)]), sorted([self.rse1_id, self.rse2_id, self.rse3_id]))

    def test_union(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test union operator """
        assert_equal(sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s|%s" % (self.tag1, self.tag2))]), sorted([self.rse1_id, self.rse2_id, self.rse3_id, self.rse4_id, self.rse5_id]))

    def test_complement(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test complement operator """
        assert_equal(sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s\\%s" % (self.tag1, self.rse3))]), sorted([self.rse1_id, self.rse2_id]))

    def test_intersect(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test intersect operator """
        assert_equal([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s&%s=uk" % (self.tag2, self.attribute))], [self.rse4_id])

    def test_order_of_operations(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test order of operations """
        assert_equal(sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s\\%s|%s=fr" % (self.tag1, self.rse3, self.attribute))]), sorted([self.rse1_id, self.rse2_id, self.rse3_id]))
        assert_equal(sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s\\(%s|%s=fr)" % (self.tag1, self.rse3, self.attribute))]), sorted([self.rse1_id, self.rse2_id]))

    def test_complicated_expression_1(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test some complicated expression 1"""
        assert_equal(sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("(%s|%s)\\%s|%s&%s" % (self.tag1, self.tag2, self.tag2, self.tag2, self.tag1))]), sorted([self.rse1_id, self.rse2_id, self.rse3_id]))

    def test_complicated_expression_2(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test some complicated expression 2"""
        assert_equal(sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("(((((%s))))|%s=us)&%s|(%s=at|%s=de)" %
                                                                                             (self.tag1, self.attribute, self.tag2, self.attribute, self.attribute))]), sorted([self.rse1_id, self.rse2_id, self.rse5_id]))

    def test_complicated_expression_3(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test some complicated expression 3"""
        assert_equal(sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("(*)&%s=at" % self.attribute)]), sorted([self.rse1_id]))

    @staticmethod
    def test_list_on_availability():
        """ RSE_EXPRESSION_PARSER (CORE) List rses based on availability filter"""
        rsewrite_name = rse_name_generator()
        rsenowrite_name = rse_name_generator()

        rsewrite_id = rse.add_rse(rsewrite_name)
        rsenowrite_id = rse.add_rse(rsenowrite_name)

        attribute = attribute_name_generator()

        rse.add_rse_attribute(rsewrite_name, attribute, "de")
        rse.add_rse_attribute(rsenowrite_name, attribute, "de")

        rse.update_rse(rsewrite_name, {'availability_write': True})
        rse.update_rse(rsenowrite_name, {'availability_write': False})

        assert_equal(sorted([item['id'] for item in rse_expression_parser.parse_expression("%s=de" % attribute)]),
                     sorted([rsewrite_id, rsenowrite_id]))

        assert_equal(sorted([item['id'] for item in rse_expression_parser.parse_expression("%s=de" % attribute, {'availability_write': True})]),
                     sorted([rsewrite_id]))

        assert_raises(RSEBlacklisted, rse_expression_parser.parse_expression, "%s=de" % attribute, {'availability_write': False})

    def test_numeric_operators(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test RSE attributes with numeric operations """
        assert_equal([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s<11" % self.attribute_numeric)], [self.rse1_id])
        assert_raises(InvalidRSEExpression, rse_expression_parser.parse_expression, "%s<9" % self.attribute_numeric)
        assert_equal(sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s<21" % self.attribute_numeric)]), sorted([self.rse1_id, self.rse2_id]))
        assert_equal([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s>49" % self.attribute_numeric)], [self.rse5_id])
        assert_raises(InvalidRSEExpression, rse_expression_parser.parse_expression, "%s>51" % self.attribute_numeric)
        assert_equal(sorted([t_rse['id'] for t_rse in rse_expression_parser.parse_expression("%s>30" % self.attribute_numeric)]), sorted([self.rse4_id, self.rse5_id]))


class TestRSEExpressionParserClient(object):

    def __init__(self):
        self.rse1 = rse_name_generator()
        self.rse2 = rse_name_generator()
        self.rse3 = rse_name_generator()
        self.rse4 = rse_name_generator()
        self.rse5 = rse_name_generator()

        self.rse1_id = rse.add_rse(self.rse1)
        self.rse2_id = rse.add_rse(self.rse2)
        self.rse3_id = rse.add_rse(self.rse3)
        self.rse4_id = rse.add_rse(self.rse4)
        self.rse5_id = rse.add_rse(self.rse5)

        # Add Attributes
        self.attribute = attribute_name_generator()

        rse.add_rse_attribute(self.rse1, self.attribute, "at")
        rse.add_rse_attribute(self.rse2, self.attribute, "de")
        rse.add_rse_attribute(self.rse3, self.attribute, "fr")
        rse.add_rse_attribute(self.rse4, self.attribute, "uk")
        rse.add_rse_attribute(self.rse5, self.attribute, "us")

        # Add Tags
        self.tag1 = tag_generator()
        self.tag2 = tag_generator()
        rse.add_rse_attribute(self.rse1, self.tag1, True)
        rse.add_rse_attribute(self.rse2, self.tag1, True)
        rse.add_rse_attribute(self.rse3, self.tag1, True)
        rse.add_rse_attribute(self.rse4, self.tag2, True)
        rse.add_rse_attribute(self.rse5, self.tag2, True)

        self.rse_client = RSEClient()

    def test_complicated_expression(self):
        """ RSE_EXPRESSION_PARSER (CLIENT) Test some complicated expression"""
        rses = [item['rse'] for item in self.rse_client.list_rses("(((((%s))))|%s=us)&%s|(%s=at|%s=de)" % (self.tag1, self.attribute, self.tag2, self.attribute, self.attribute))]
        assert_equal(sorted(rses), sorted([self.rse1, self.rse2, self.rse5]))

    def test_complicated_expression_1(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test some complicated expression 1"""
        rses = [item['rse'] for item in self.rse_client.list_rses("(%s|%s)\\%s|%s&%s" % (self.tag1, self.tag2, self.tag2, self.tag2, self.tag1))]
        assert_equal(sorted(rses), sorted([self.rse1, self.rse2, self.rse3]))
