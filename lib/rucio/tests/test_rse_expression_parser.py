# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2013

from nose.tools import assert_equal, raises
from rucio.core import rse
from rucio.core import rse_expression_parser
from rucio.common.exception import InvalidRSEExpression


class TestESEExpressionParserCore():

    @classmethod
    def setUpClass(cls):
        try:
            rse.add_rse("TEST_RSE1")
            rse.add_rse("TEST_RSE2")
            rse.add_rse("TEST_RSE3")
            rse.add_rse("TEST_RSE4")
            rse.add_rse("TEST_RSE5")

            #Add Attributes
            rse.add_rse_attribute("TEST_RSE1", "country", "at")
            rse.add_rse_attribute("TEST_RSE2", "country", "de")
            rse.add_rse_attribute("TEST_RSE3", "country", "fr")
            rse.add_rse_attribute("TEST_RSE4", "country", "uk")
            rse.add_rse_attribute("TEST_RSE5", "country", "us")

            #Add Tags
            rse.add_rse_attribute("TEST_RSE1", "T1", True)
            rse.add_rse_attribute("TEST_RSE2", "T1", True)
            rse.add_rse_attribute("TEST_RSE3", "T1", True)
            rse.add_rse_attribute("TEST_RSE4", "T2", True)
            rse.add_rse_attribute("TEST_RSE5", "T2", True)
        except:
            pass

    @raises(InvalidRSEExpression)
    def test_invalid_expression_unconnected_operator(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test invalid rse expression: unconnected operator"""
        rse_expression_parser.parse_expression("TEST_RSE1|")

    @raises(InvalidRSEExpression)
    def test_invalid_expression_wrong_parantheses(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test invalid rse expression: wrong parantheses """
        rse_expression_parser.parse_expression("TEST_RSE1)")

    def test_simple_rse_reference(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test simple RSE reference """
        assert_equal(rse_expression_parser.parse_expression("TEST_RSE1"), ['TEST_RSE1'])

    def test_attribute_reference(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test simple RSE attribute reference """
        assert_equal(rse_expression_parser.parse_expression("country=uk"), ['TEST_RSE4'])

    def test_tag_reference(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test simple RSE tag reference """
        assert_equal(sorted(rse_expression_parser.parse_expression("T1")), sorted(['TEST_RSE1', 'TEST_RSE2', 'TEST_RSE3']))

    def test_parantheses(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test parantheses """
        assert_equal(sorted(rse_expression_parser.parse_expression("(T1)")), sorted(['TEST_RSE1', 'TEST_RSE2', 'TEST_RSE3']))

    def test_union(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test union operator """
        assert_equal(sorted(rse_expression_parser.parse_expression("T1|T2")), sorted(['TEST_RSE1', 'TEST_RSE2', 'TEST_RSE3', 'TEST_RSE4', 'TEST_RSE5']))

    def test_complement(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test complement operator """
        assert_equal(sorted(rse_expression_parser.parse_expression("T1\\TEST_RSE3")), sorted(['TEST_RSE1', 'TEST_RSE2']))

    def test_intersect(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test intersect operator """
        assert_equal(rse_expression_parser.parse_expression("T2&country=uk"), ['TEST_RSE4'])

    def test_order_of_operations(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test order of operations """
        assert_equal(sorted(rse_expression_parser.parse_expression("T1\\TEST_RSE3|country=fr")), sorted(['TEST_RSE1', 'TEST_RSE2', 'TEST_RSE3']))
        assert_equal(sorted(rse_expression_parser.parse_expression("T1\\(TEST_RSE3|country=fr)")), sorted(['TEST_RSE1', 'TEST_RSE2']))

    def test_complicated_expression_1(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test some complicated expression """
        assert_equal(sorted(rse_expression_parser.parse_expression("(T1|T2)\\T2|T2&T1")), sorted(['TEST_RSE1', 'TEST_RSE2', 'TEST_RSE3']))

    def test_complicated_expression_2(self):
        """ RSE_EXPRESSION_PARSER (CORE) Test some complicated expression """
        assert_equal(sorted(rse_expression_parser.parse_expression("(((((T1))))|country=us)&T2|(country=at|country=de)")), sorted(['TEST_RSE1', 'TEST_RSE2', 'TEST_RSE5']))
