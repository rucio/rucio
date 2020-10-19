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
from rucio.db.sqla import models
from rucio.db.sqla.models import DataIdentifier

DEFAULT_MODEL = models.DataIdentifier.__name__

OP = {
        ' == ' : ['==', ' = ', ' eq ', ' -eq '],
        ' > ' : [' > ', ' gt ', ' -gt '],
        ' >= ' : ['>=', ' ge ', ' -ge '],
        ' < ' : [' < ', ' lt ', ' -lt '],
        ' <= ' : ['<=', ' le ', ' -le '],
        ' and ' : ['&&', ' & ', ' and '],
        ' or ' : ['||', ' | ', ' or '],
        }
VALID_OP = sum(OP.values(),[])
VALID_OP_NOSPACE = [ op.replace(' ','') for op in VALID_OP]
STD_OP = list(OP.keys())
RANGE_OP = [STD_OP[1], STD_OP[2], STD_OP[3], STD_OP[4]]
KEYWORDS = VALID_OP_NOSPACE+["True", "False"]

INVERTED_STD_OP = { op.strip(' ').rstrip(' ') : op.strip(' ').rstrip(' ') for op in STD_OP}
INVERTED_STD_OP['>'] = '<'
INVERTED_STD_OP['>='] = '<='
INVERTED_STD_OP['<'] = '>'
INVERTED_STD_OP['<='] = '>='


def clear_double_spaces(input_string : str) -> str:
    """
    Clears a filter input string from double spaces

    :param input_string: The string defining the filter.

    :returns: reworked string
    """
    input_string = input_string.strip().rstrip()
    while '  ' in input_string:
        input_string = input_string.replace('  ',' ')
    return input_string


def translate(input_string : str) -> str:
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


def ingest(input_string : str) -> str:
    """
    Groups all the functions needed to make filter string acceptable.

    :param input_string: The string defining the filter.

    :returns: reworked string
    """
    return clear_double_spaces(translate(clear_double_spaces(input_string)))


def get_num_op(input_string : str) -> list:
    """
    Counts the number of OP contained in the string defining the filter

    :param input_string: The string defining the filter.

    :returns: number of operators
    """
    return sum(input_string.count(op) for op in VALID_OP)


def convert_ternary(input_string : str) -> list:
    """
    Splits a single string defining a range-like filter (A < key < B) into the AND of two filters (A < key AND B > key).

    :param input_string: The string defining the filter.

    :returns: list of equivalent simpler filters
    """
    if get_num_op(input_string) == 2:
        l = input_string.split(' ')
        l.insert(2, l[2])
        return [' '.join(l[0:3]), ' '.join(l[3:])]
    else:
        return [input_string.strip(' ').rstrip(' ')]


def expand_metadata(input_string : str, model : str = DEFAULT_MODEL) -> list:
    """
    Attaches the metadata prefix to all keywords found in the string defining the filter to apply

    :param input_string: The string defining the filter.
    :param model: The string defining SQL model prefix to be prepended to keywords.

    :returns: reworked string with metadata prefixes
    """
    l = input_string.rstrip(' ').strip(' ').split(' ')
    model = model.rstrip('.')
    for i,p in enumerate(l):
        if hasattr(getattr(sys.modules[__name__], model), p):
            l[i] = model + '.' + p
        else:
            if not p in KEYWORDS:
                try:
                    float(eval(p))
                except:
                    pass
    return ' '.join(l)


def get_dict(input_string : str, model : str = DEFAULT_MODEL) -> list:
    """
    Returns sqlalchemy-compliant filters dictionary from the input string

    :param input_string: The string defining the filter.
    :param model: The string defining SQL model prefix to be prepended to keywords.

    :returns: reworked string
    """
    print(input_string)
    l = input_string.split(' ')
    print("len "+str(len(l)))
    if len(l) == 3:
        if model in l[0]:
            print('A')
            return {'model' : model.rstrip('.'), 'field' : l[0].replace(model,'').strip('.'), 'op' : l[1], 'value' : l[2]}
        elif model in l[2]:
            print('B')
            return {'model' : model.rstrip('.'), 'field' : l[2].replace(model,'').strip('.'), 'op' : INVERTED_STD_OP[str(l[1])], 'value' : l[0]}
    return {}


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

        def get_dicts(filters):
            """
            Returns the list of sqlalchemy-compliant dictionaries created from the filter string.

            :returns: list of sqlalchemy-compliant dictionaries
            """
            filter_dicts = []
            for fil in filters:
                dicts = []
                for cond in fil:
                    dicts.append(get_dict(cond))
                if dicts:
                    filter_dicts.append(dicts)
            return filter_dicts

        self.dicts = get_dicts(self.filters)

        def get_query_columns(fil : dict, model : str = DEFAULT_MODEL):
            """
            Returns the list of SQL columns needed by the filter.

            :param fil: The dictionary describing the filter.
            :param model: The string defining SQL model prefix to be prepended to keywords.

            :returns: list of columns' names
            """
            columns = []
            for cond in fil:
                if 'field' in cond:
                    if not (model+cond['field']) in columns:
                        columns.append(model+cond['field'])
            return columns

        self.needed_columns = [get_query_columns(fil) for fil in self.dicts]


    def run(self):
        """
        Runs the filter and returns the boolean result. Used in tests.

        :returns: boolean output
        """
        return any(map(lambda and_group: all(map(lambda expr: eval(expr), and_group)), self.filters))


    def createQuery(self, session, model = "models.DataIdentifier"):
        """
        Returns the list of sqlalchemy queries describing the filter.

        :param session: The sqlalchemy read session.
        :param model: The string defining SQL model prefix to be prepended to keywords.

        :returns: list of sqlalchemy queries
        """
        queries = []
        for i,col in enumerate(self.needed_columns):
            query = session.query(tuple(col))
            for cond in self.dicts[i]:
                query = query.filter(cond)
            queries.append(query)
        return queries
