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

'''
SQLAlchemy utilities

'''

from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql.expression import Executable, ClauseElement


class InsertFromSelect(Executable, ClauseElement):
    def __init__(self, insert_spec, select):
        self.insert_spec = insert_spec
        self.select = select


@compiles(InsertFromSelect)
def visit_insert_from_select(element, compiler, **kw):
    if type(element.insert_spec) == list:
        columns = []
        for column in element.insert_spec:
            if element.insert_spec[0].table != column.table:
                raise Exception("Insert columns must belong to the same table")
            columns.append(column.name)

        table = compiler.process(element.insert_spec[0].table, asfrom=True)
        columns = ", ".join(columns)

        sql = "INSERT INTO %s (%s) %s" % (table, columns, compiler.process(element.select))

    else:
        sql = "INSERT INTO %s %s" % (compiler.process(element.insert_spec, asfrom=True), compiler.process(element.select))

    return sql
