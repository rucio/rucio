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
from rucio.db.sqla.models import DataIdentifier
from rucio.db.sqla.session import read_session
from rucio.common.exception import KeyNotFound

DEFAULT_MODEL = DataIdentifier.__name__

OP = {' == ': ['==', ' = ', ' eq ', ' -eq '], ' > ': [' > ', ' gt ', ' -gt '], ' >= ': ['>=', ' ge ', ' -ge '], ' < ': [' < ', ' lt ', ' -lt '], ' <= ': ['<=', ' le ', ' -le '], ' and ': ['&&', ' & ', ' and '], ' or ': ['||', ' | ', ' or ']}
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


def ingest(input_string):
    """
    Groups all the functions needed to make filter string acceptable.

    :param input_string: The string defining the filter.

    :returns: reworked string
    """
    return clear_double_spaces(translate(clear_double_spaces(input_string)))


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
    s = re.split(OP_SPLIT_REGEX, condition)
    for op in STD_OP_NOSPACE:
        if op in condition:
            return [s[0], op, s[1]]
    raise Exception("Condition splitting failed! No standard operation detected.")


def flip_if_needed(listed_condition, model=DEFAULT_MODEL):
    if len(listed_condition) == 3:
        if hasattr(getattr(sys.modules[__name__], model), listed_condition[2]):
            listed_condition.reverse()
            listed_condition[1] = INVERTED_STD_OP[listed_condition[1].replace(' ', '')]

    return listed_condition


class inequality_engine:
    def __init__(self, input_string):
        """
        Organize the input string in sqlalchemy filters.
        Commas are interpreted as AND, semicolumns as OR between multiple filters.
        """
        input_string = ingest(input_string)
        or_groups = input_string.split(';')
        self.filters = []
        for og in or_groups:
            conditions = og.split(',')
            converted = []

            for cond in conditions:
                converted.extend(convert_ternary(expand_metadata(cond)))

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
                query = session.query(DataIdentifier.scope, DataIdentifier.name, DataIdentifier.did_type, DataIdentifier.bytes, *[eval(getattr(getattr(sys.modules[__name__], model), c)) for c in cols])
            else:
                query = query_master.add_columns(DataIdentifier.scope, DataIdentifier.name, DataIdentifier.did_type, DataIdentifier.bytes, *[eval(getattr(getattr(sys.modules[__name__], model), c)) for c in cols])
            for cond in self.filters[i]:
                s = flip_if_needed(condition_split(cond.replace(model + '.', '')))
                k = s[0]
                op = s[1]
                v = s[2]
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
                            query = query.filter(eval(cond))
                        else:
                            raise Exception("Comparison operator not supported.")
                    else:
                        raise KeyNotFound("key={}".format(k))
            queries.append(query)
        return queries
