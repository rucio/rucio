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

from sqlalchemy.sql.expression import bindparam, text
from sqlalchemy.orm import Session
from typing import Optional
from sqlalchemy.sql.selectable import Select


def filter_thread_work(session, query, total_threads, thread_id, hash_variable=None):
    """ Filters a query to partition thread workloads based on the thread id and total number of threads """
    if thread_id is not None and total_threads is not None and (total_threads - 1) > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('thread_id', thread_id), bindparam('total_threads', total_threads - 1)]
            if not hash_variable:
                query = query.filter(text('ORA_HASH(id, :total_threads) = :thread_id').bindparams(*bindparams))
            else:
                query = query.filter(text('ORA_HASH(%s, :total_threads) = :thread_id' % (hash_variable)).bindparams(*bindparams))
        elif session.bind.dialect.name == 'mysql':
            if not hash_variable:
                query = query.filter(text('mod(md5(id), %s) = %s' % (total_threads, thread_id)))
            else:
                query = query.filter(text('mod(md5(%s), %s) = %s' % (hash_variable, total_threads, thread_id)))
        elif session.bind.dialect.name == 'postgresql':
            if not hash_variable:
                query = query.filter(text('mod(abs((\'x\'||md5(id::text))::bit(32)::bigint), %s) = %s' % (total_threads, thread_id)))
            else:
                query = query.filter(text('mod(abs((\'x\'||md5(%s::text))::bit(32)::bigint), %s) = %s' % (hash_variable, total_threads, thread_id)))
    return query


def filter_thread_work_where(session: "Session", stmt: "Select", total_threads: Optional[int], thread_id: Optional[int], hash_variable=None):
    """ Filters a stmt to partition thread workloads based on the thread id and total number of threads """

    if thread_id is None or total_threads is None or (total_threads - 1) <= 0:
        return stmt

    hash_var_expr = hash_variable if hash_variable else 'id'

    if session.bind.dialect.name == 'oracle':
        bindparams = [bindparam('thread_id', thread_id), bindparam('total_threads', total_threads - 1)]
        stmt = stmt.where(text('ORA_HASH(%s, :total_threads) = :thread_id' % (hash_var_expr)).bindparams(*bindparams))
    elif session.bind.dialect.name == 'mysql':
        stmt = stmt.where(text('mod(md5(%s), %s) = %s' % (hash_variable, total_threads, thread_id)))
    elif session.bind.dialect.name == 'postgresql':
        stmt = stmt.where(text('mod(abs((\'x\'||md5(%s::text))::bit(32)::bigint), %s) = %s' % (hash_variable, total_threads, thread_id)))
    return stmt
