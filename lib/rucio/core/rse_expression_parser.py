# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2013-2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014

import abc
import random
import re
import string

from dogpile.cache import make_region
from dogpile.cache.api import NoValue

from rucio.common import schema
from rucio.common.exception import InvalidRSEExpression
from rucio.common.utils import my_key_generator
from rucio.core.rse import list_rses
from rucio.db.session import transactional_session


DEFAULT_RSE_ATTRIBUTE = schema.default_rse_attribute['pattern']
RSE_ATTRIBUTE = schema.rse_attribute['pattern']
PRIMITIVE = r'(\(*(%s|%s)\)*)' % (RSE_ATTRIBUTE, DEFAULT_RSE_ATTRIBUTE)

UNION = r'(\|%s)' % (PRIMITIVE)
INTERSECTION = r'(\&%s)' % (PRIMITIVE)
COMPLEMENT = r'(\\%s)' % (PRIMITIVE)

PATTERN = r'^%s(%s|%s|%s)*' % (PRIMITIVE, UNION, INTERSECTION, COMPLEMENT)


region = make_region(function_key_generator=my_key_generator).configure(
    'dogpile.cache.memory',
    expiration_time=3600)


@transactional_session
def parse_expression(expression, session):
    """
    Parse a RSE expression and return the list of RSE dictionaries.

    :param expression:  RSE expression, e.g: 'CERN|BNL'
    :param session:     Database session in use
    :return:            A list of rse_ids
    :raises:            InvalidRSEExpression, RSENotFound
    """
    result = region.get(expression)
    if type(result) is NoValue:
        # Evaluate the correctness of the parentheses
        parantheses_open_count = 0
        parantheses_close_count = 0
        for char in expression:
            if (char == '('):
                parantheses_open_count += 1
            elif (char == ')'):
                parantheses_close_count += 1
            if (parantheses_close_count > parantheses_open_count):
                raise InvalidRSEExpression('Problem with parantheses.')
        if (parantheses_open_count != parantheses_close_count):
            raise InvalidRSEExpression('Problem with parantheses.')

        # Check the expression pattern
        match = re.match(PATTERN, expression)
        if match is None:
            raise InvalidRSEExpression('Expression does not comply to RSE Expression syntax')
        else:
            if match.group() != expression:
                raise InvalidRSEExpression('Expression does not comply to RSE Expression syntax')
        result_tuple = __resolve_term_expression(expression)[0].resolve_elements(session=session)
        result = []
        for rse in list(result_tuple[0]):
            result.append(result_tuple[1][rse])
        random.shuffle(result)
        if not result:
            raise InvalidRSEExpression('RSE Expression resulted in an empty set.')
        region.set(expression, result)
    return result


def __resolve_term_expression(expression):
    """
    Resolves a Term Expression and returns an object of type BaseExpressionElement

    :param subexpression:  String of the term expression
    :returns:              Tuple of BaseExpressionElement, term Expression string
    """

    left_term = None
    operator = None
    original_expression = expression

    while(True):
        if len(expression) == 0:
            return (left_term, original_expression)
        elif expression[0] == "(":
            if (left_term is None):
                left_term, termexpression = __resolve_term_expression(__extract_term(expression))
                expression = expression[len(termexpression)+2:]
                continue
            else:
                right_term, termexpression = __resolve_term_expression(__extract_term(expression))
                expression = expression[len(termexpression)+2:]
                operator.set_left_term(left_term)
                operator.set_right_term(right_term)
                left_term = operator
                operator = None
                continue
        elif expression[0] == "\\":
            operator = ComplementOperator()
            expression = expression[1:]
            continue
        elif expression[0] == "&":
            operator = IntersectOperator()
            expression = expression[1:]
            continue
        elif expression[0] == "|":
            operator = UnionOperator()
            expression = expression[1:]
            continue
        else:
            if (left_term is None):
                left_term, primitiveexpression = __resolve_primitive_expression(expression)
                expression = expression[len(primitiveexpression):]
                continue
            else:
                right_term, primitiveexpression = __resolve_primitive_expression(expression)
                expression = expression[len(primitiveexpression):]
                operator.set_left_term(left_term)
                operator.set_right_term(right_term)
                left_term = operator
                operator = None
                continue


def __resolve_primitive_expression(expression):
    """
    Resolve a primitive expression and return a RSEAttribute object

    :param expression:  String of the expresssion
    :returns:           Tuple of RSEAttribute, primitive expression
    """
    primitiveexpression = re.match(PRIMITIVE, expression).group()
    keyvalue = string.split(primitiveexpression, "=")
    if len(keyvalue) == 2:
        return (RSEAttribute(keyvalue[0], keyvalue[1]), primitiveexpression)
    else:
        return (RSEAttribute(keyvalue[0]), primitiveexpression)


def __extract_term(expression):
    """
    Extract a term from an expression with parantheses

    :param expression:  The expression starting with a '('
    :return:            The extracted term string
    """
    open_parantheses = 0
    i = 0
    for char in expression:
        if (char == '('):
            open_parantheses += 1
        elif (char == ')'):
            open_parantheses -= 1
        if (open_parantheses == 0):
            return expression[1:i]
        i = i + 1
    raise SystemError('This point in the code should not be reachable')


class BaseExpressionElement:
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def resolve_elements(self, session):
        """
        Resolve the ExpressionElement and return a set of RSE ids

        :param session:  Database session in use
        :returns:        (Set of RSE ids, Dictionary of RSE dicts)
        :rtype:          (Set of Strings, Dictionary of RSE dicts organized by rse_id)
        """
        pass


class RSEAttribute(BaseExpressionElement):
    """
    Representation of an RSE Attribute
    """

    def __init__(self, key, value=True):
        """
        Creates an RSEAttribute representation
        """
        self.key = key
        self.value = value

    def resolve_elements(self, session):
        """
        Inherited from :py:func:`BaseExpressionElement.resolve_elements`
        """
        output = list_rses({self.key: self.value, 'availability_write': True}, session=session)
        if not output:
            return (set(), {})
        rse_dict = {}
        for rse in output:
            rse_dict[rse['id']] = rse
        return (set([rse['id'] for rse in output]), rse_dict)


class BaseRSEOperator(BaseExpressionElement):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def set_left_term(self, left_term):
        """
        Set the left site of the term

        :param left_term:  Left term
        """
        pass

    @abc.abstractmethod
    def set_right_term(self, right_term):
        """
        Set the right site of the term

        :param left_term:  Left term
        """
        pass


class ComplementOperator(BaseRSEOperator):
    """
    Representation of the complement operator
    """

    def __init__(self):
        """
        Create a ComplementOperator representation
        """

        self.left_term = None
        self.right_term = None

    def set_left_term(self, left_term):
        """
        Inherited from :py:func:`BaseRSEOperator.set_left_term`
        """
        self.left_term = left_term

    def set_right_term(self, right_term):
        """
        Inherited from :py:func:`BaseRSEOperator.set_right_term`
        """
        self.right_term = right_term

    def resolve_elements(self, session):
        """
        Inherited from :py:func:`BaseExpressionElement.resolve_elements`
        """
        left_term_tuple = self.left_term.resolve_elements(session=session)
        right_term_tuple = self.right_term.resolve_elements(session=session)
        return (left_term_tuple[0] - right_term_tuple[0], dict(left_term_tuple[1].items() + right_term_tuple[1].items()))


class UnionOperator(BaseRSEOperator):
    """
    Representation of the or operator
    """

    def __init__(self):
        """
        Create a UnionOperator representation
        """

        self.left_term = None
        self.right_term = None

    def set_left_term(self, left_term):
        """
        Inherited from :py:func:`BaseRSEOperator.set_left_term`
        """
        self.left_term = left_term

    def set_right_term(self, right_term):
        """
        Inherited from :py:func:`BaseRSEOperator.set_right_term`
        """
        self.right_term = right_term

    def resolve_elements(self, session):
        """
        Inherited from :py:func:`BaseExpressionElement.resolve_elements`
        """
        left_term_tuple = self.left_term.resolve_elements(session=session)
        right_term_tuple = self.right_term.resolve_elements(session=session)
        return (left_term_tuple[0] | right_term_tuple[0], dict(left_term_tuple[1].items() + right_term_tuple[1].items()))


class IntersectOperator(BaseRSEOperator):
    """
    Representation of the intersect operator
    """

    def __init__(self):
        """
        Create a IntersectOperator representation
        """

        self.left_term = None
        self.right_term = None

    def set_left_term(self, left_term):
        """
        Inherited from :py:func:`BaseRSEOperator.set_left_term`
        """
        self.left_term = left_term

    def set_right_term(self, right_term):
        """
        Inherited from :py:func:`BaseRSEOperator.set_right_term`
        """
        self.right_term = right_term

    def resolve_elements(self, session):
        """
        Inherited from :py:func:`BaseExpressionElement.resolve_elements`
        """
        left_term_tuple = self.left_term.resolve_elements(session=session)
        right_term_tuple = self.right_term.resolve_elements(session=session)
        return (left_term_tuple[0] & right_term_tuple[0], dict(left_term_tuple[1].items() + right_term_tuple[1].items()))
