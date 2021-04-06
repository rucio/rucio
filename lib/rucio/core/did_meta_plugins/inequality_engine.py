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

import sys
import re
import datetime
from sqlalchemy import or_
from rucio.db.sqla.models import DataIdentifier
from rucio.db.sqla.session import read_session
from rucio.common.exception import KeyNotFound
from rucio.db.sqla.constants import DIDType
from rucio.common import exception

DEFAULT_MODEL = DataIdentifier.__name__

OP = {' == ': ['==', ' = ', ' eq ', ' -eq '], ' >= ': ['>=', ' ge ', ' -ge '], ' <= ': ['<=', ' le ', ' -le '], ' < ': [' < ', ' lt ', ' -lt '], ' > ': [' > ', ' gt ', ' -gt '], ' and ': ['&&', ' & ', ' and '], ' or ': ['||', ' | ', ' or ']}
VALID_OP = sum(OP.values(), [])
VALID_OP_NOSPACE = [op.replace(' ', '') for op in VALID_OP]
STD_OP = list(OP.keys())
STD_OP_NOSPACE = [op.strip(' ').rstrip(' ') for op in STD_OP]
OP_SPLIT_REGEX = '|'.join(map(re.escape, STD_OP))
RANGE_OP = [STD_OP[1], STD_OP[2], STD_OP[3], STD_OP[4]]
KEYWORDS = VALID_OP_NOSPACE + ["True", "False"]

INVERTED_STD_OP = {op: op for op in STD_OP_NOSPACE}
INVERTED_STD_OP['>'] = '<'
INVERTED_STD_OP['>='] = '<='
INVERTED_STD_OP['<'] = '>'
INVERTED_STD_OP['<='] = '>='

VALID_TYPES = ['all', 'collection', 'container', 'dataset', 'file']


def clear_double_spaces(input_string):
    """
    Clears a filter input string from double spaces

    :param input_string: The string defining the filter.

    :returns: reworked string
    """
    input_string = input_string.strip(' ').rstrip(' ')
    while '  ' in input_string:
        input_string = input_string.replace('  ', ' ')
    return input_string


def translate(input_string):
    """
    Replaces OP synonyms with standard python equivalents

    :param input_string: The string defining the filter.

    :returns: reworked string
    """
    for translated_op in STD_OP:
        op_list = OP[translated_op]
        for op in op_list:
            input_string = input_string.replace(op, translated_op)
    return input_string


def ingest_str(input_string):
    """
    Groups all the functions needed to make filter string acceptable.

    :param input_string: The string defining the filter.

    :returns: reworked string
    """
    return clear_double_spaces(translate(clear_double_spaces(input_string)))


def ingest_dict(input_dict):
    return ingest_str(str(input_dict).replace('{', '').replace('}', '').replace("'", '').replace(' :', ':').replace(': ', ' == '))


def ingest(input_data):
    input_data = str(input_data).strip(' ').rstrip(' ')
    input_string = ''
    if (not '{' == input_data[0]) and (not '}' == input_data[-1]):
        input_string = ingest_str(input_data)
    else:
        input_string = ingest_dict(input_data)
    return input_string


def get_num_op(input_string):
    """
    Counts the number of OP contained in the string defining the filter

    :param input_string: The string defining the filter.

    :returns: number of operators
    """
    return sum(input_string.count(op) for op in VALID_OP)


def convert_ternary(input_string):
    """
    Splits a single string defining a range-like filter (A < key < B) into the AND of two filters (A < key AND B > key).

    :param input_string: The string defining the filter.

    :returns: list of equivalent simpler filters
    """
    if get_num_op(input_string) == 2:
        splitted = input_string.split(' ')
        splitted.insert(2, splitted[2])
        return [' '.join(splitted[0:3]), ' '.join(splitted[3:])]
    else:
        return [input_string.strip(' ').rstrip(' ')]


def expand_metadata(input_string, model=DEFAULT_MODEL):
    """
    Attaches the metadata prefix to all keywords found in the string defining the filter to apply

    :param input_string: The string defining the filter.
    :param model: The string defining SQL model prefix to be prepended to keywords.

    :returns: reworked string with metadata prefixes
    """
    splitted = input_string.rstrip(' ').strip(' ').split(' ')
    model = model.rstrip('.')
    for i, p in enumerate(splitted):
        if hasattr(getattr(sys.modules[__name__], model), p):
            splitted[i] = model + '.' + p
        else:
            if p not in KEYWORDS:
                try:
                    float(eval(p))
                except:
                    pass
    return ' '.join(splitted)


def condition_split(condition):
    """
    Converts a string condition into a list in the form [key, standard op, value] for better addressing

    :param condition: The string defining the condition to apply

    :returns: a list in the form [key, op, value]
    """
    s = re.split(OP_SPLIT_REGEX, condition)
    for op in STD_OP_NOSPACE:
        if op in condition:
            if len(s) == 2:
                return [s[0], op, s[1]]
            else:
                raise Exception("Invalid condition {}".format(condition))
    raise Exception("Condition splitting failed! No standard operation detected.")


def flip_if_needed(listed_condition, model=DEFAULT_MODEL):
    """
    In case the condition list is in the form [value, op, key] it flis it into [key, inverted op, value]

    :param listed_condition: The condition already converted in list form.
    :param model: The string defining SQL model prefix to be prepended to keywords.

    :returns: reworked string with metadata prefixes
    """
    if len(listed_condition) == 3:
        if hasattr(getattr(sys.modules[__name__], model), listed_condition[2]):
            listed_condition.reverse()
            listed_condition[1] = INVERTED_STD_OP[listed_condition[1].replace(' ', '')]

    return listed_condition


def handle_created(condition):
    """
    Converts the input condition containing created_after or created_before in the equivalent condition based upon created_at

    :param condition: The string defining the condition to apply

    :returns: reworked condition based on created_at if needed, passthrough if not
    """
    if "created_after" in condition or "created_before" in condition:
        if '==' in condition:
            date_str = condition.replace(' ', '').split('==', 1)[1]
        elif '=' in condition:
            date_str = condition.replace(' ', '').split('=', 1)[1]
        if "created_after" in condition:
            return "created_at >= " + date_str
        elif "created_before" in condition:
            return "created_at <= " + date_str
    return condition


HANDLE_LENGTH_LUT = {".gte == ": " >= ",
                     ".gt == ": " > ",
                     ".lte == ": " <= ",
                     ".lt == ": " < ",
                     ".gte==": " >= ",
                     ".gt==": " > ",
                     ".lte==": " <= ",
                     ".lt==": " < ",
                     ".gte = ": " >= ",
                     ".gt = ": " > ",
                     ".lte = ": " <= ",
                     ".lt = ": " < ",
                     ".gte=": " >= ",
                     ".gt=": " > ",
                     ".lte=": " <= ",
                     ".lt=": " < "
                     }


def handle_length(condition):
    """
    Handles legacy length.gt, length.gte, etc. converting such conditions to use length and inequalities

    :param condition: The string defining the condition to apply

    :returns: reworked condition based on length if needed, passthrough if not
    """
    if "length" in condition:
        for key in HANDLE_LENGTH_LUT.keys():
            if key in condition:
                new_condition = condition.replace(key, HANDLE_LENGTH_LUT[key])
                return new_condition
    return condition


def retrocompatibility(condition):
    """
    Handles legacy conditions, passthrough if not needed

    :param condition: The string defining the condition to apply

    :returns: reworked condition if needed, passthrough if not
    """
    new_cond = handle_created(handle_length(condition))
    return new_cond


class inequality_engine:
    def __init__(self, input_data):
        """
        Organize the input string in sqlalchemy filters.
        Commas are interpreted as AND, semicolumns as OR between multiple filters.
        """
        input_string = ingest(str(input_data))

        or_groups = input_string.split(';')
        self.filters = []
        for og in or_groups:
            conditions = og.split(',')
            converted = []

            for cond in conditions:
                if not cond == '':
                    converted.extend(convert_ternary(expand_metadata(retrocompatibility(cond))))

            self.filters.append(converted)

        if not self.filters or self.filters == [['']]:
            raise ValueError("No filter defined. Aborting.")

        def get_query_columns(fil, model=DEFAULT_MODEL):
            """
            Returns the list of SQL columns needed by the filter.

            :param fil: The dictionary describing the filter.
            :param model: The string defining SQL model prefix to be prepended to keywords.

            :returns: list of columns' names
            """
            columns = []
            for f in fil:
                for word in f.split():
                    if hasattr(getattr(sys.modules[__name__], model), word):
                        columns.append(word)
            return columns

        self.needed_columns = [get_query_columns(fil) for fil in self.filters]

    def run(self):
        """
        Runs the filter and returns the boolean result. Used in tests.

        :returns: boolean output
        """
        return any(map(lambda and_group: all(map(lambda expr: eval(expr), and_group)), self.filters))

    @read_session
    def createQueries(self, session=None, model=DEFAULT_MODEL, query_master=None):
        """
        Returns the list of sqlalchemy queries describing the filter.

        :param session: The sqlalchemy read session.
        :param model: The string defining SQL model prefix to be prepended to keywords.

        :returns: list of sqlalchemy queries
        """
        queries = []
        for i, cols in enumerate(self.needed_columns):
            if not query_master:
                query = session.query(DataIdentifier.scope,
                                      DataIdentifier.name,
                                      DataIdentifier.did_type,
                                      DataIdentifier.bytes,
                                      *[eval(getattr(getattr(sys.modules[__name__], model), c)) for c in cols])
            else:
                query = query_master.add_columns(DataIdentifier.scope,
                                                 DataIdentifier.name,
                                                 DataIdentifier.did_type,
                                                 DataIdentifier.bytes,
                                                 *[eval(getattr(getattr(sys.modules[__name__], model), c)) for c in cols])
            for cond in self.filters[i]:
                if not cond == '':
                    s = flip_if_needed(condition_split(cond.replace(model + '.', '')))
                    k = s[0]
                    op = s[1]
                    v = s[2]

                    if k == 'type':
                        if v not in VALID_TYPES:
                            raise exception.UnsupportedOperation("Valid types are: %s" % str(VALID_TYPES))
                        v = v.lower()
                        if v == 'all':
                            query = query.filter(or_(DataIdentifier.did_type == DIDType.CONTAINER,
                                                     DataIdentifier.did_type == DIDType.DATASET,
                                                     DataIdentifier.did_type == DIDType.FILE))
                        elif v.lower() == 'collection':
                            query = query.filter(or_(DataIdentifier.did_type == DIDType.CONTAINER,
                                                     DataIdentifier.did_type == DIDType.DATASET))
                        elif v.lower() == 'container':
                            query = query.filter(DataIdentifier.did_type == DIDType.CONTAINER)
                        elif v.lower() == 'dataset':
                            query = query.filter(DataIdentifier.did_type == DIDType.DATASET)
                        elif v.lower() == 'file':
                            query = query.filter(DataIdentifier.did_type == DIDType.FILE)

                        continue

                    if ('*' in cond or '%' in cond) and (op == '=='):
                        if v in ('*', '%', u'*', u'%'):
                            continue
                        if session.bind.dialect.name == 'postgresql':
                            query = query.filter(getattr(getattr(sys.modules[__name__], model), k).
                                                 like(v.replace('*', '%').replace('_', '\_'), escape='\\'))  # NOQA: W605
                        else:
                            query = query.filter(getattr(getattr(sys.modules[__name__], model), k).
                                                 like(v.replace('*', '%').replace('_', '\_'), escape='\\'))  # NOQA: W605
                    else:
                        if hasattr(getattr(sys.modules[__name__], model), k):
                            if (op in STD_OP + STD_OP_NOSPACE):
                                if "created_at" == k:
                                    date = datetime.datetime.strptime(v, '%Y-%m-%dT%H:%M:%S.%fZ')
                                    if op == "<=":
                                        query = query.filter(DataIdentifier.created_at <= date)
                                    elif op == "<":
                                        query = query.filter(DataIdentifier.created_at < date)
                                    elif op == ">=":
                                        query = query.filter(DataIdentifier.created_at >= date)
                                    elif op == ">":
                                        query = query.filter(DataIdentifier.created_at > date)
                                    elif op == "==":
                                        query = query.filter(DataIdentifier.created_at == date)
                                else:
                                    if isinstance(v, str):
                                        v = "\'" + v + "\'"
                                        query = query.filter(eval(model + '.' + k + op + v))
                            else:
                                raise Exception("Comparison operator not supported.")
                        else:
                            raise KeyNotFound("key={}".format(k))
            queries.append(query)
        return queries
