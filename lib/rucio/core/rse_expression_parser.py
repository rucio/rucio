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

import abc
import re
from hashlib import sha256
from typing import TYPE_CHECKING

from dogpile.cache.api import NoValue

from rucio.common.cache import make_region_memcached
from rucio.common.exception import InvalidRSEExpression, RSEWriteBlocked
from rucio.core.rse import list_rses, get_rses_with_attribute, get_rse_attribute
from rucio.db.sqla.session import transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


DEFAULT_RSE_ATTRIBUTE = r'([A-Za-z0-9]+([_-][A-Za-z0-9]+)*)'
RSE_ATTRIBUTE = r'([A-Za-z0-9\._-]+[=<>][A-Za-z0-9_-]+)'
PRIMITIVE = r'(\(*(%s|%s|%s)\)*)' % (RSE_ATTRIBUTE, DEFAULT_RSE_ATTRIBUTE, r'\*')
UNION = r'(\|%s)' % (PRIMITIVE)
INTERSECTION = r'(\&%s)' % (PRIMITIVE)
COMPLEMENT = r'(\\%s)' % (PRIMITIVE)

PATTERN = r'^%s(%s|%s|%s)*' % (PRIMITIVE, UNION, INTERSECTION, COMPLEMENT)

REGION = make_region_memcached(expiration_time=600)


@transactional_session
def parse_expression(expression, filter_=None, *, session: "Session"):
    """
    Parse a RSE expression and return the list of RSE dictionaries.

    :param expression:    RSE expression, e.g: 'CERN|BNL'.
    :param filter_:       Availability filter (dictionary) used for the RSEs. e.g.: {'availability_write': True}
    :param session:       Database session in use.
    :returns:             A list of rse dictionaries.
    :raises:              InvalidRSEExpression, RSENotFound, RSEWriteBlocked
    """
    result = REGION.get(sha256(expression.encode()).hexdigest())
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
        # result_tuple = ([rse_ids], {rse_id: {rse_info}})
        result = []
        for rse in list(result_tuple[0]):
            result.append(result_tuple[1][rse])
        REGION.set(sha256(expression.encode()).hexdigest(), result)

    # Filter for VO
    vo_result = []
    if filter_ and filter_.get('vo'):
        filter_ = filter_.copy()  # Make a copy so we can pop('vo') without affecting the object `filter` outside this function
        vo = filter_.pop('vo')
        for rse in result:
            if rse.get('vo') == vo:
                vo_result.append(rse)
    else:
        vo_result = result

    if not vo_result:
        raise InvalidRSEExpression('RSE Expression resulted in an empty set.')

    # Filter
    final_result = []
    if filter_:
        for rse in vo_result:
            if filter_.get('availability_write', False):
                if rse.get('availability_write'):
                    final_result.append(rse)
        if not final_result:
            raise RSEWriteBlocked('RSE excluded; not available for writing.')
    else:
        final_result = vo_result

    # final_result = [{rse-info}]
    return final_result


def __resolve_term_expression(expression):
    """
    Resolves a Term Expression and returns an object of type BaseExpressionElement

    :param subexpression:  String of the term expression.
    :returns:              Tuple of BaseExpressionElement, term Expression string
    """

    left_term = None
    operator = None
    original_expression = expression

    while True:
        if len(expression) == 0:
            return (left_term, original_expression)
        elif expression[0] == "(":
            if left_term is None:
                left_term, termexpression = __resolve_term_expression(__extract_term(expression))
                expression = expression[len(termexpression) + 2:]
                continue
            else:
                right_term, termexpression = __resolve_term_expression(__extract_term(expression))
                expression = expression[len(termexpression) + 2:]
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

    :param expression:    String of the expresssion
    :returns:             Tuple of RSEAttribute, primitive expression
    """
    primitiveexpression = re.match(PRIMITIVE, expression).group()
    if ('=' in primitiveexpression):
        keyvalue = primitiveexpression.split("=")
        return (RSEAttributeEqualCheck(keyvalue[0], keyvalue[1]), primitiveexpression)
    elif ('<' in primitiveexpression):
        keyvalue = primitiveexpression.split("<")
        return (RSEAttributeSmallerCheck(keyvalue[0], keyvalue[1]), primitiveexpression)
    elif ('>' in primitiveexpression):
        keyvalue = primitiveexpression.split(">")
        return (RSEAttributeLargerCheck(keyvalue[0], keyvalue[1]), primitiveexpression)
    elif ('*' in primitiveexpression):
        return (RSEAll(), primitiveexpression)
    else:
        return (RSEAttributeEqualCheck(key=primitiveexpression), primitiveexpression)


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


class BaseExpressionElement(object, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def resolve_elements(self, session):
        """
        Resolve the ExpressionElement and return a set of RSE ids

        :param session:  Database session in use
        :returns:        (Set of RSE ids, Dictionary of RSE dicts)
        :rtype:          (Set of Strings, Dictionary of RSE dicts organized by rse_id)
        """
        pass


class RSEAll(BaseExpressionElement):
    """
    Representation of all RSEs
    """

    def resolve_elements(self, session):
        """
        Inherited from :py:func:`BaseExpressionElement.resolve_elements`
        """
        output = list_rses(session=session)
        if not output:
            return (set(), {})
        rse_dict = {}
        for rse in output:
            rse_dict[rse['id']] = rse
        return (set([rse['id'] for rse in output]), rse_dict)


class RSEAttributeEqualCheck(BaseExpressionElement):
    """
    Representation of an RSE Attribute with Equal Check
    """

    def __init__(self, key, value=True):
        """
        Creates an RSEAttribute representation

        :param key:           Key of the RSE Attribute.
        :param value:         Value of the RSE Attribute.
        """
        self.key = key
        self.value = value

    def resolve_elements(self, session):
        """
        Inherited from :py:func:`BaseExpressionElement.resolve_elements`
        """
        output = list_rses({self.key: self.value}, session=session)
        if not output:
            return (set(), {})
        rse_dict = {}
        for rse in output:
            rse_dict[rse['id']] = rse
        return (set([rse['id'] for rse in output]), rse_dict)


class RSEAttributeSmallerCheck(BaseExpressionElement):
    """
    Representation of an RSE Attribute with Smaller (<) Check
    """

    def __init__(self, key, value=True):
        """
        Creates an RSEAttribute representation

        :param key:           Key of the RSE Attribute.
        :param value:         Value of the RSE Attribute.
        """
        self.key = key
        self.value = value

    def resolve_elements(self, session):
        """
        Inherited from :py:func:`BaseExpressionElement.resolve_elements`
        """
        rse_list = get_rses_with_attribute(key=self.key, session=session)
        if not rse_list:
            return (set(), {})

        output = []
        rse_dict = {}
        for rse in rse_list:
            try:
                if float(get_rse_attribute(rse['id'], self.key, session=session)) < float(self.value):
                    rse_dict[rse['id']] = rse
                    output.append(rse['id'])
            except ValueError:
                continue
        return (set(output), rse_dict)


class RSEAttributeLargerCheck(BaseExpressionElement):
    """
    Representation of an RSE Attribute with Larger (>) Check
    """

    def __init__(self, key, value=True):
        """
        Creates an RSEAttribute representation

        :param key:           Key of the RSE Attribute.
        :param value:         Value of the RSE Attribute.
        """
        self.key = key
        self.value = value

    def resolve_elements(self, session):
        """
        Inherited from :py:func:`BaseExpressionElement.resolve_elements`
        """
        rse_list = get_rses_with_attribute(key=self.key, session=session)
        if not rse_list:
            return (set(), {})

        output = []
        rse_dict = {}
        for rse in rse_list:
            try:
                if float(get_rse_attribute(rse['id'], self.key, session=session)) > float(self.value):
                    rse_dict[rse['id']] = rse
                    output.append(rse['id'])
            except ValueError:
                continue
        return (set(output), rse_dict)


class BaseRSEOperator(BaseExpressionElement, metaclass=abc.ABCMeta):
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
        return (left_term_tuple[0] - right_term_tuple[0], dict(list(left_term_tuple[1].items()) + list(right_term_tuple[1].items())))


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
        return (left_term_tuple[0] | right_term_tuple[0], dict(list(left_term_tuple[1].items()) + list(right_term_tuple[1].items())))


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
        return (left_term_tuple[0] & right_term_tuple[0], dict(list(left_term_tuple[1].items()) + list(right_term_tuple[1].items())))
