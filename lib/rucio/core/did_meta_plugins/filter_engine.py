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
# - Rob Barnsley <rob.barnsley@skao.int>, 2021
#
# PY3K COMPATIBLE

import ast
import operator
from datetime import datetime
from importlib import import_module

import sqlalchemy
from rucio.common import exception
from rucio.common.utils import parse_did_filter_from_string_fe
from rucio.db.sqla.constants import DIDType
from rucio.db.sqla.session import read_session
from sqlalchemy import or_, and_

# lookup table converting keyword suffixes to pythonic operators.
operators_conversion_LUT = {
    "gte": operator.ge,
    "lte": operator.le,
    "lt": operator.lt,
    "gt": operator.gt,
    "ne": operator.ne,
    "": operator.eq
}
operators_conversion_LUT_inv = {op2: op1 for op1, op2 in operators_conversion_LUT.items()}

# understood date formats.
valid_date_formats = (
    '%Y-%m-%d %H:%M:%S',
    '%Y-%m-%dT%H:%M:%S',
    '%Y-%m-%d %H:%M:%S.%fZ',
    '%Y-%m-%dT%H:%M:%S.%fZ',
    '%a, %d %b %Y %H:%M:%S UTC'
)


class FilterEngine:
    """
    An engine to provide advanced filtering functionality to DID listing requests.
    """
    def __init__(self, filters, model_class=None, strict_coerce=True):
        if isinstance(filters, str):
            self._filters, _ = parse_did_filter_from_string_fe(filters, omit_name=True)
        elif isinstance(filters, dict):
            self._filters = [filters]
        elif isinstance(filters, list):
            self._filters = filters
        else:
            raise exception.DIDFilterSyntaxError("Input filters are of an unrecognised type.")

        self._make_input_backwards_compatible()
        self.mandatory_model_attributes = self._translate_filters(model_class=model_class, strict_coerce=strict_coerce)
        self._sanity_check_translated_filters()

    @property
    def filters(self):
        return self._filters

    @property
    def filters_pretty(self):
        """
        A (more) human readable format of <filters>.
        """
        filters = '\n'
        for or_group in self._filters:
            for and_group in or_group:
                key, oper, value = and_group
                if isinstance(key, sqlalchemy.orm.attributes.InstrumentedAttribute):
                    key = and_group[0].key
                if operators_conversion_LUT_inv[oper] == "":
                    oper = "eq"
                else:
                    oper = operators_conversion_LUT_inv[oper]
                if isinstance(value, sqlalchemy.orm.attributes.InstrumentedAttribute):
                    value = and_group[2].key
                elif isinstance(value, DIDType):
                    value = and_group[2].name
                filters = "{}{} {} {}".format(filters, key, oper, value)
                if and_group != or_group[-1]:
                    filters += ' AND '
            if or_group != self._filters[-1]:
                filters += ' OR\n'
        return filters

    def _sanity_check_translated_filters(self):
        """
        Perform a few sanity checks on translated filters.

        Checks the following are all true:
        1. 'did_type' filters use an equals operator,
        2. 'name' filters use an equality operator,
        3. 'length' filters are parsable as an int type,
        4. wildcard expressions use an equality operator,
        5. 'created_at' value adheres to one of the date formats <valid_date_formats>,
        6. there are no duplicate key+operator criteria.
        """
        for or_group in self._filters:
            or_group_test_duplicates = []
            for and_group in or_group:
                key, oper, value = and_group
                if key == 'did_type':   # (1)
                    if oper != operator.eq:
                        raise ValueError("Type operator must be equals.")
                if key == 'name':       # (2)
                    if oper not in (operator.eq, operator.ne):
                        raise ValueError("Name operator must be an equality operator.")
                if key == 'length':     # (3)
                    try:
                        int(value)
                    except ValueError:
                        raise ValueError('Length has to be an integer value.')

                if isinstance(value, str):  # (4)
                    if any([char in value for char in ['*', '%']]):
                        if oper not in [operator.eq, operator.ne]:
                            raise exception.DIDFilterSyntaxError("Wildcards can only be used with equality operators")

                if key == 'created_at':     # (5)
                    if not isinstance(value, datetime):
                        raise exception.DIDFilterSyntaxError("Couldn't parse date '{}'. Valid formats are: {}".format(value, valid_date_formats))

                or_group_test_duplicates.append((key, oper))
            if len(set(or_group_test_duplicates)) != len(or_group_test_duplicates):     # (6)
                raise exception.DuplicateCriteriaInDIDFilter()

    def _make_input_backwards_compatible(self):
        """
        Backwards compatibility for previous versions of filtering.

        Does the following:
        - converts "created_after" key to "created_at.gte"
        - converts "created_before" key to "created_at.lte"
        """
        for or_group in self._filters:
            if 'created_after' in or_group:
                or_group['created_at.gte'] = or_group.pop('created_after')
            elif 'created_before' in or_group:
                or_group['created_at.lte'] = or_group.pop('created_before')

    def _coerce_filter_word_to_model_attribute(self, word, model_class, strict=True):
        """
        Attempts to coerce a filter word to an attribute of a <model_class>.

        :param model_class: The word.
        :param model_class: The SQL model class.
        :returns: The coerced attribute if successful or the word if not.
        """
        if isinstance(word, str):
            if hasattr(model_class, word):
                return getattr(model_class, word)
            else:
                if strict:
                    raise exception.KeyNotFound("'{}' keyword could not be coerced to model class attribute. Attribute not found.".format(word))
        return word

    def _translate_filters(self, model_class, strict_coerce=True):
        """
        Reformats filters from:

        [{or_group_1:key_1.or_group_1:operator_1: or_group_1:value_1,
         {or_group_1:key_m.or_group_1:operator_m: or_group_1:value_m}
         ...
         {or_group_n:key_1.or_group_n:operator_1: or_group_n:value_1,
         {or_group_n:key_m.or_group_n:operator_m: or_group_n:value_m}
        ]

        to the format used by the engine:

        [[[or_group_1:key_1, or_group_1:operator_1, or_group_1:value_1],
          ...
          [or_group_1:key_m, or_group_1:operator_m, or_group_1:value_m]
         ],
         ...
         [[or_group_n:key_1, or_group_n:operator_1, or_group_n:value_1],
          ...
          [or_group_n:key_m, or_group_n:operator_m, or_group_n:value_m]
         ]
        ]

        replacing all filter operator suffixes with python equivalents using the LUT, <operators_conversion_LUT>, and
        coercing all filter words to their corresponding <model_class> attribute.

        Typecasting of values is also attempted.

        :params: model_class: The SQL model class.
        :params: strict_coerce: Enforce that keywords must be coercable to a model attribute.
        :returns: The set of mandatory model attributes to be used in the filter query.
        """
        if model_class:
            try:
                import_module(model_class.__module__)
            except ModuleNotFoundError:
                raise exception.MissingModuleException("Model class module not found.")

        mandatory_model_attributes = set()
        filters_translated = []
        for or_group in self._filters:
            and_group_parsed = []
            for key, value in or_group.items():
                # logic for key
                key_tokenised = key.split('.')
                if len(key_tokenised) == 1:       # no operator suffix found, assume eq
                    try:
                        key_no_suffix = ast.literal_eval(key)
                    except ValueError:
                        key_no_suffix = key
                    oper = ''
                elif len(key_tokenised) == 2:     # operator suffix found
                    try:
                        key_no_suffix = ast.literal_eval(key_tokenised[0])
                    except ValueError:
                        key_no_suffix = key_tokenised[0]
                    oper = key_tokenised[1]
                else:
                    raise exception.DIDFilterSyntaxError
                key_no_suffix = self._coerce_filter_word_to_model_attribute(key_no_suffix, model_class, strict=strict_coerce)
                if not isinstance(key_no_suffix, str):
                    mandatory_model_attributes.add(key_no_suffix)

                # logic for value
                if isinstance(value, str):
                    value = value.replace('true', 'True').replace('false', 'False')
                    for format in valid_date_formats:   # try parsing multiple date formats.
                        try:
                            value = datetime.strptime(value, format)
                            break
                        except ValueError:
                            continue
                    try:
                        value = ast.literal_eval(value)
                    except (ValueError, SyntaxError):
                        pass

                and_group_parsed.append(
                    (key_no_suffix, operators_conversion_LUT.get(oper), value))
            filters_translated.append(and_group_parsed)
        self._filters = filters_translated
        return list(mandatory_model_attributes)

    @read_session
    def create_sqla_query(self, session=None, additional_model_attributes=[], additional_filters={}):
        """
        Returns the database query that fully describes the filters.

        :param session: the database session.
        :param additional_model_attributes: additional model attributes to retrieve.
        :param additional_filters: additional filters to be applied to all clauses.
        :returns: list of database queries
        """
        all_model_attributes = set(self.mandatory_model_attributes + additional_model_attributes)

        # Add additional filters, applied as AND clauses to each OR group.
        for or_group in self._filters:
            for filter in additional_filters:
                or_group.append(list(filter))

        or_expressions = []
        for or_group in self._filters:
            and_expressions = []
            for and_group in or_group:
                key, oper, value = and_group
                if isinstance(value, str) and any([char in value for char in ['*', '%']]):  # wildcards
                    if value in ('*', '%', u'*', u'%'):                                     # match wildcard exactly == no filtering on key
                        continue
                    else:                                                                   # partial match with wildcard == like || notlike
                        if session.bind.dialect.name == 'postgresql':
                            if oper == operator.eq:
                                expression = key.like(value.replace('*', '%').replace('_', '\_'), escape='\\')     # NOQA: W605
                            elif oper == operator.ne:
                                expression = key.notlike(value.replace('*', '%').replace('_', '\_'), escape='\\')  # NOQA: W605
                        else:
                            if oper == operator.eq:
                                expression = key.like(value.replace('*', '%').replace('_', '\_'), escape='\\')     # NOQA: W605
                            elif oper == operator.ne:
                                expression = key.notlike(value.replace('*', '%').replace('_', '\_'), escape='\\')  # NOQA: W605
                else:
                    expression = oper(key, value)

                if oper == operator.ne:                                                     # set .ne operator to include NULLs.
                    expression = or_(expression, key.is_(None))

                and_expressions.append(expression)
            or_expressions.append(and_(*and_expressions))
        # raise ValueError(session.query(*all_model_attributes).filter(or_(*or_expressions)).statement.compile(
        #     compile_kwargs={"literal_binds": True}, dialect=sqlalchemy.dialects.postgresql.dialect()))    # debug
        return session.query(*all_model_attributes).filter(or_(*or_expressions))

    def evaluate(self):
        """
        Evaluates an expression and returns a boolean result.

        :returns: boolean output
        """
        or_group_evaluations = []
        for or_group in self._filters:
            and_group_evaluations = []
            for and_group in or_group:
                key, oper, value = and_group
                and_group_evaluations.append(oper(key, value))
            or_group_evaluations.append(all(and_group_evaluations))
        return any(or_group_evaluations)
