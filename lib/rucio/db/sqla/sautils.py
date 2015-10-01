#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013


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
