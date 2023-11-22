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

import ast
import fnmatch
import operator
from datetime import datetime, timedelta, date
from importlib import import_module
from typing import TYPE_CHECKING

import sqlalchemy
from sqlalchemy import cast, or_, and_
from sqlalchemy.sql.expression import text

from rucio.common import exception
from rucio.common.utils import parse_did_filter_from_string_fe
from rucio.db.sqla.constants import DIDType
from rucio.db.sqla.session import read_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


# lookup table converting keyword suffixes to pythonic operators.
OPERATORS_CONVERSION_LUT = {
    "gte": operator.ge,
    "lte": operator.le,
    "lt": operator.lt,
    "gt": operator.gt,
    "ne": operator.ne,
    "": operator.eq
}

# lookup table converting pythonic operators to oracle operators
ORACLE_OP_MAP = {
    operator.eq: "==",
    operator.ne: "<>",
    operator.gt: ">",
    operator.lt: "<",
    operator.ge: ">=",
    operator.le: "<="
}

# lookup table converting pythonic operators to postgres operators
POSTGRES_OP_MAP = {
    operator.eq: "=",
    operator.ne: "!=",
    operator.gt: ">",
    operator.lt: "<",
    operator.ge: ">=",
    operator.le: "<="
}

# understood date formats.
VALID_DATE_FORMATS = (
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

    def _coerce_filter_word_to_model_attribute(self, word, model_class, strict=True):
        """
        Attempts to coerce a filter word to an attribute of a <model_class>.

        :param model_class: The word.
        :param model_class: The SQL model class.
        :params: strict: Enforce that keywords must be coercable to a model attribute.
        :returns: The coerced attribute if successful or (if strict is False) the word if not.
        :raises: KeyNotFound
        """
        if isinstance(word, str):
            if hasattr(model_class, word):
                return getattr(model_class, word)
            else:
                if strict:
                    raise exception.KeyNotFound("'{}' keyword could not be coerced to model class attribute. Attribute not found.".format(word))
        return word

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

    def _sanity_check_translated_filters(self):
        """
        Perform a few sanity checks on translated filters.

        Checks the following are all true:
        1. 'did_type' filters use an equals operator,
        2. 'name' filters use an equality operator,
        3. 'length' filters are parsable as an int type,
        4. wildcard expressions use an equality operator,
        5. 'created_at' value adheres to one of the date formats <VALID_DATE_FORMATS>,
        6. there are no duplicate key+operator criteria.

        :raises: ValueError, DIDFilterSyntaxError, DuplicateCriteriaInDIDFilter
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
                        raise exception.DIDFilterSyntaxError("Couldn't parse date '{}'. Valid formats are: {}".format(value, VALID_DATE_FORMATS))

                or_group_test_duplicates.append((key, oper))
            if len(set(or_group_test_duplicates)) != len(or_group_test_duplicates):     # (6)
                raise exception.DuplicateCriteriaInDIDFilter()

    def _translate_filters(self, model_class, strict_coerce=True):
        """
        Reformats filters from:

        [{or_group_1->key_1.or_group_1->operator_1: or_group_1->value_1,
         {or_group_1->key_m.or_group_1->operator_m: or_group_1->value_m}
         ...
         {or_group_n->key_1.or_group_n->operator_1: or_group_n->value_1,
         {or_group_n->key_m.or_group_n->operator_m: or_group_n->value_m}
        ]

        to the format used by the engine:

        [[[or_group_1->key_1, or_group_1->operator_1, or_group_1->value_1],
          ...
          [or_group_1->key_m, or_group_1->operator_m, or_group_1->value_m]
         ],
         ...
         [[or_group_n->key_1, or_group_n->operator_1, or_group_n->value_1],
          ...
          [or_group_n->key_m, or_group_n->operator_m, or_group_n->value_m]
         ]
        ]

        replacing all filter operator suffixes with python equivalents using the LUT, <OPERATORS_CONVERSION_LUT>, and
        coercing all filter words to their corresponding <model_class> attribute.

        Typecasting of values is also attempted.

        :param model_class: The SQL model class.
        :param strict_coerce: Enforce that keywords must be coercable to a model attribute.
        :returns: The set of mandatory model attributes to be used in the filter query.
        :raises: MissingModuleException, DIDFilterSyntaxError
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
                # KEY
                # Separate key for key name and possible operator.
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

                # VALUE
                # Typecasting is required when the entry point is the CLI as values will always be string.
                if isinstance(value, str):
                    value = self._try_typecast_string(value)

                # Convert string operator to pythonic operator.
                and_group_parsed.append(
                    (key_no_suffix, OPERATORS_CONVERSION_LUT.get(oper), value))
            filters_translated.append(and_group_parsed)
        self._filters = filters_translated
        return list(mandatory_model_attributes)

    def _try_typecast_string(self, value):
        """
        Check if string can be typecasted to bool, datetime or float.

        :param value: The value to be typecasted.
        :returns: The typecasted value.
        """
        value = value.replace('true', 'True').replace('TRUE', 'True')
        value = value.replace('false', 'False').replace('FALSE', 'False')
        for format in VALID_DATE_FORMATS:       # try parsing multiple date formats.
            try:
                value = datetime.strptime(value, format)
            except ValueError:
                continue
            else:
                return value
        try:
            operators = ('+', '-', '*', '/')
            if not any(operator in value for operator in operators):    # fix for lax ast literal_eval in earlier python versions
                value = ast.literal_eval(value)                         # will catch float, int and bool
        except (ValueError, SyntaxError):
            pass
        return value

    def create_mongo_query(self, additional_filters={}):
        """
        Returns a single mongo query describing the filters expression.

        :param additional_filters: additional filters to be applied to all clauses.
        :returns: a mongo query string describing the filters expression.
        """
        # Add additional filters, applied as AND clauses to each OR group.
        for or_group in self._filters:
            for filter in additional_filters:
                or_group.append(list(filter))

        or_expressions = []
        for or_group in self._filters:
            and_expressions = []
            for and_group in or_group:
                key, oper, value = and_group
                if isinstance(value, str) and any([char in value for char in ['*', '%']]):   # wildcards
                    if value in ('*', '%', '*', '%'):                                        # match wildcard exactly == no filtering on key
                        continue
                    else:                                                                    # partial match with wildcard == like || notlike
                        if oper == operator.eq:
                            expression = {
                                key: {
                                    '$regex': fnmatch.translate(value)                       # translate partial wildcard expression to regex
                                }
                            }
                        elif oper == operator.ne:
                            expression = {
                                key: {
                                    '$not': {
                                        '$regex': fnmatch.translate(value)                  # translate partial wildcard expression to regex
                                    }
                                }
                            }
                else:
                    # mongodb operator keywords follow the same function names as operator package but prefixed with $
                    expression = {
                        key: {
                            '${}'.format(oper.__name__): value
                        }
                    }

                and_expressions.append(expression)
            if len(and_expressions) > 1:                            # $and key must have array as value...
                or_expressions.append({'$and': and_expressions})
            else:
                or_expressions.append(and_expressions[0])           # ...otherwise just use the first, and only, entry.
        if len(or_expressions) > 1:
            query_str = {'$or': or_expressions}                     # $or key must have array as value...
        else:
            query_str = or_expressions[0]                           # ...otherwise just use the first, and only, entry.

        return query_str

    def create_postgres_query(self, additional_filters={}, fixed_table_columns=('scope', 'name', 'vo'),
                              jsonb_column='data'):
        """
        Returns a single postgres query describing the filters expression.

        :param additional_filters: additional filters to be applied to all clauses.
        :param fixed_table_columns: the table columns
        :returns: a postgres query string describing the filters expression.
        """
        # Add additional filters, applied as AND clauses to each OR group.
        for or_group in self._filters:
            for _filter in additional_filters:
                or_group.append(list(_filter))

        or_expressions = []
        for or_group in self._filters:
            and_expressions = []
            for and_group in or_group:
                key, oper, value = and_group
                if key in fixed_table_columns:                                              # is this key filtering on a column or in the jsonb?
                    is_in_json_column = False
                else:
                    is_in_json_column = True
                if isinstance(value, str) and any([char in value for char in ['*', '%']]):  # wildcards
                    if value in ('*', '%', '*', '%'):                                       # match wildcard exactly == no filtering on key
                        continue
                    else:                                                                   # partial match with wildcard == like || notlike
                        if oper == operator.eq:
                            if is_in_json_column:
                                expression = "{}->>'{}' LIKE '{}' ".format(jsonb_column, key, value.replace('*', '%').replace('_', '\_'))       # NOQA: W605
                            else:
                                expression = "{} LIKE '{}' ".format(key, value.replace('*', '%').replace('_', '\_'))                            # NOQA: W605
                        elif oper == operator.ne:
                            if is_in_json_column:
                                expression = "{}->>'{}' NOT LIKE '{}' ".format(jsonb_column, key, value.replace('*', '%').replace('_', '\_'))   # NOQA: W605
                            else:
                                expression = "{} NOT LIKE '{}' ".format(key, value.replace('*', '%').replace('_', '\_'))                        # NOQA: W605
                else:
                    # Infer what type key should be cast to from typecasting the value in the expression.
                    try:
                        if isinstance(value, int):                                          # this could be bool or int (as bool subclass of int)
                            if isinstance(value, bool):
                                if is_in_json_column:
                                    expression = "({}->>'{}')::boolean {} {}".format(jsonb_column, key, POSTGRES_OP_MAP[oper], str(value).lower())
                                else:
                                    expression = "{}::boolean {} {}".format(key, POSTGRES_OP_MAP[oper], str(value).lower())
                            else:
                                # cast as float, not integer, to avoid potentially losing precision in key
                                if is_in_json_column:
                                    expression = "({}->>'{}')::float {} {}".format(jsonb_column, key, POSTGRES_OP_MAP[oper], value)
                                else:
                                    expression = "{}::float {} {}".format(key, POSTGRES_OP_MAP[oper], value)
                        elif isinstance(value, float):
                            if is_in_json_column:
                                expression = "({}->>'{}')::float {} {}".format(jsonb_column, key, POSTGRES_OP_MAP[oper], value)
                            else:
                                expression = "{}::float {} {}".format(key, POSTGRES_OP_MAP[oper], value)
                        elif isinstance(value, datetime):
                            if is_in_json_column:
                                expression = "({}->>'{}')::timestamp {} '{}'".format(jsonb_column, key, POSTGRES_OP_MAP[oper], value)
                            else:
                                expression = "{}::timestamp {} '{}'".format(key, POSTGRES_OP_MAP[oper], value)
                        else:
                            if is_in_json_column:
                                expression = "{}->>'{}' {} '{}'".format(jsonb_column, key, POSTGRES_OP_MAP[oper], value)
                            else:
                                expression = "{} {} '{}'".format(key, POSTGRES_OP_MAP[oper], value)
                    except Exception as e:
                        raise exception.FilterEngineGenericError(e)
                and_expressions.append(expression)
            or_expressions.append(' AND '.join(and_expressions))
        return ' OR '.join(or_expressions)

    @read_session
    def create_sqla_query(self, *, session: "Session", additional_model_attributes=[], additional_filters={}, json_column=None):
        """
        Returns a database query that fully describes the filters.

        The logic for construction of syntax describing a filter for key is dependent on whether the key has been previously coerced to a model attribute (i.e. key
        is a table column).

        :param session: The database session.
        :param additional_model_attributes: Additional model attributes to retrieve.
        :param additional_filters: Additional filters to be applied to all clauses.
        :param json_column: Column to be checked if filter key has not been coerced to a model attribute. Only valid if engine instantiated with strict_coerce=False.
        :returns: A database query.
        :raises: FilterEngineGenericError
        """
        all_model_attributes = set(self.mandatory_model_attributes + additional_model_attributes)

        # Add additional filters, applied as AND clauses to each OR group.
        for or_group in self._filters:
            for _filter in additional_filters:
                or_group.append(list(_filter))

        or_expressions = []
        for or_group in self._filters:
            and_expressions = []
            for and_group in or_group:
                key, oper, value = and_group
                if isinstance(key, sqlalchemy.orm.attributes.InstrumentedAttribute):                # -> this key filters on a table column.
                    if isinstance(value, str) and any([char in value for char in ['*', '%']]):      # wildcards
                        if value in ('*', '%', '*', '%'):                                           # match wildcard exactly == no filtering on key
                            continue
                        else:                                                                       # partial match with wildcard == like || notlike
                            if oper == operator.eq:
                                expression = key.like(value.replace('*', '%').replace('_', '\_'), escape='\\')     # NOQA: W605
                            elif oper == operator.ne:
                                expression = key.notlike(value.replace('*', '%').replace('_', '\_'), escape='\\')  # NOQA: W605
                    else:
                        expression = oper(key, value)
                    if oper == operator.ne:                                                         # set .ne operator to include NULLs.
                        expression = or_(expression, key.is_(None))
                elif json_column:                                                                   # -> this key filters on the content of a json column
                    if session.bind.dialect.name == 'oracle':
                        if isinstance(value, str) and any([char in value for char in ['*', '%']]):  # wildcards
                            if value in ('*', '%', '*', '%'):                                       # match wildcard exactly == no filtering on key
                                continue
                            else:                                                                   # partial match with wildcard == like || notlike
                                if oper == operator.eq:
                                    expression = text("json_exists({},'$?(@.{} like \"{}\")')".format(json_column.key, key, value.replace('*', '%')))
                                elif oper == operator.ne:
                                    raise exception.FilterEngineGenericError("Oracle implementation does not support this operator.")
                        else:
                            try:
                                if isinstance(value, (bool)):                                       # bool must be checked first (as bool subclass of int)
                                    expression = text("json_exists({},'$?(@.{}.boolean() {} \"{}\")')".format(json_column.key, key, ORACLE_OP_MAP[oper], value))
                                elif isinstance(value, (int, float)):
                                    expression = text("json_exists({},'$?(@.{} {} {})')".format(json_column.key, key, ORACLE_OP_MAP[oper], value))
                                else:
                                    expression = text("json_exists({},'$?(@.{} {} \"{}\")')".format(json_column.key, key, ORACLE_OP_MAP[oper], value))
                            except Exception as e:
                                raise exception.FilterEngineGenericError(e)
                    else:
                        if isinstance(value, str) and any([char in value for char in ['*', '%']]):  # wildcards
                            if value in ('*', '%', '*', '%'):                                       # match wildcard exactly == no filtering on key
                                continue
                            else:                                                                   # partial match with wildcard == like || notlike
                                if oper == operator.eq:
                                    expression = json_column[key].as_string().like(value.replace('*', '%').replace('_', '\_'), escape='\\')     # NOQA: W605
                                elif oper == operator.ne:
                                    expression = json_column[key].as_string().notlike(value.replace('*', '%').replace('_', '\_'), escape='\\')  # NOQA: W605
                        else:
                            # Infer what type key should be cast to from typecasting the value in the expression.
                            try:
                                if isinstance(value, int):                                          # this could be bool or int (as bool subclass of int)
                                    if isinstance(value, bool):
                                        expression = oper(json_column[key].as_boolean(), value)
                                    else:
                                        expression = oper(json_column[key].as_float(), value)       # cast as float, not integer, to avoid potentially losing precision in key
                                elif isinstance(value, float):
                                    expression = oper(json_column[key].as_float(), value)
                                elif isinstance(value, datetime):
                                    expression = oper(cast(cast(json_column[key], sqlalchemy.types.Text), sqlalchemy.types.DateTime), value)
                                else:
                                    expression = oper(json_column[key].as_string(), value)
                            except Exception as e:
                                raise exception.FilterEngineGenericError(e)
                else:
                    raise exception.FilterEngineGenericError("Requested filter on key without model attribute, but [json_column] not set.")

                and_expressions.append(expression)
            or_expressions.append(and_(*and_expressions))
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

    def print_filters(self):
        """
        A (more) human readable format of <filters>.
        """
        operators_conversion_LUT_inv = {op2: op1 for op1, op2 in OPERATORS_CONVERSION_LUT.items()}

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

    @staticmethod
    def print_query(statement, dialect=sqlalchemy.dialects.postgresql.dialect()):
        """
        Generates SQL expression from SQLA expression with parameters rendered inline.

        For debugging ONLY.

        :param dialect: the sql dialect.
        :returns: The query statement in the chosen dialect.
        """
        if isinstance(statement, sqlalchemy.orm.Query):
            if dialect is None:
                dialect = statement.session.bind.dialect
            statement = statement.statement
        elif dialect is None:
            dialect = statement.bind.dialect

        class LiteralCompiler(dialect.statement_compiler):
            def visit_bindparam(self, bindparam, within_columns_clause=False,
                                literal_binds=False, **kwargs):
                return self.render_literal_value(bindparam.value, bindparam.type)

            def render_array_value(self, val, item_type):
                if isinstance(val, list):
                    return "{%s}" % ",".join([self.render_array_value(x, item_type) for x in val])
                return self.render_literal_value(val, item_type)

            def render_literal_value(self, value, type_):
                if isinstance(value, int):
                    return str(value)
                elif isinstance(value, (str, date, datetime, timedelta)):
                    return "'%s'" % str(value).replace("'", "''")
                elif isinstance(value, list):
                    return "'{%s}'" % (",".join([self.render_array_value(x, type_.item_type) for x in value]))
                return super(LiteralCompiler, self).render_literal_value(value, type_)

        return LiteralCompiler(dialect, statement).process(statement)
