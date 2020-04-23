# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

from sqlalchemy.sql.expression import bindparam, text


def filter_thread_work(session, query, total_threads, thread_id, hash_variable=None):
    """ Filters a query to partition thread workloads based on the thread id and total number of threads """
    if thread_id is not None and total_threads is not None and (total_threads - 1) > 0:
        if session.bind.dialect.name == 'oracle':
            bindparams = [bindparam('thread_id', thread_id), bindparam('total_threads', total_threads - 1)]
            if not hash_variable:
                query = query.filter(text('ORA_HASH(id, :total_threads) = :thread_id', bindparams=bindparams))
            else:
                query = query.filter(text('ORA_HASH(%s, :total_threads) = :thread_id' % (hash_variable), bindparams=bindparams))
        elif session.bind.dialect.name == 'mysql':
            if not hash_variable:
                query = query.filter(text('mod(md5(id), %s) = %s' % (total_threads, thread_id)))
            else:
                query = query.filter(text('mod(md5(%s), %s) = %s' % (hash_variable, total_threads, thread_id)))
        elif session.bind.dialect.name == 'postgresql':
            if not hash_variable:
                query = query.filter(text('mod(abs((\'x\'||md5(id::text))::bit(32)::int), %s) = %s' % (total_threads, thread_id)))
            else:
                query = query.filter(text('mod(abs((\'x\'||md5(%s::text))::bit(32)::int), %s) = %s' % (hash_variable, total_threads, thread_id)))
    return query
