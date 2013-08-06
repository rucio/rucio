# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2013

"""
Judge is a daemon to re-evaluate and execute replication rules.
"""

import threading
import time
import traceback

from datetime import datetime

from sqlalchemy.exc import DatabaseError

from rucio.common.exception import DatabaseException
from rucio.db import session as rucio_session
from rucio.db import models
from rucio.core.rule import re_evaluate_did, delete_rule
from rucio.core.monitor import record_gauge, record_counter

graceful_stop = threading.Event()


def re_evaluator(once=False, worker_number=1, total_workers=1):
    """
    Main loop to check the re-evaluation of dids.
    """

    print 're_evaluator: starting'

    print 're_evaluator: started'

    while not graceful_stop.is_set():
        try:
            # Select a bunch of dids for re evaluation for this worker
            session = rucio_session.get_session()
            none_value = None
            query = session.query(models.DataIdentifier.scope, models.DataIdentifier.name).\
                filter(models.DataIdentifier.rule_evaluation_required != none_value).\
                with_hint(models.DataIdentifier, "index(dids DIDS_RULE_EVALUATION_REQUIRED)", 'oracle').\
                order_by(models.DataIdentifier.rule_evaluation_required)

            if worker_number and total_workers:
                if session.bind.dialect.name == 'oracle':
                    query = query.filter('ORA_HASH(name, %s) = %s' % (total_workers-1, worker_number-1))
                elif session.bind.dialect.name == 'mysql':
                    query = query.filter('mod(md5(name), %s) = %s' % (total_workers-1, worker_number-1))
                elif session.bind.dialect.name == 'sqlite':
                    pass

            start = time.time()  # NOQA
            dids = query.limit(1000).all()
            session.commit()
            session.remove()
            #print 'Re-Evaluation index query time %f did-size=%d' % (time.time() - start, len(dids))

            if not dids and not once:
                print 're_evaluator[%s/%s] did not get any work' % (worker_number, total_workers)
                time.sleep(10)
            else:
                for scope, name in dids:
                    if graceful_stop.is_set():
                        break
                    try:
                        record_gauge('rule.judge.re_evaluate.threads.%d' % worker_number, 1)
                        re_evaluate_did(scope=scope, name=name, worker_number=worker_number, total_workers=total_workers)
                        record_gauge('rule.judge.re_evaluate.threads.%d' % worker_number, 0)
                    except (DatabaseException, DatabaseError), e:
                        record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                        print 're_evaluator[%s/%s]: Locks detected for %s:%s' % (worker_number, total_workers, scope, name)
        except Exception, e:
            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
            print traceback.format_exc()
        if once:
            return

    print 're_evaluator: graceful stop requested'
    record_gauge('rule.judge.re_evaluate.threads.%d' % worker_number, 0)

    print 're_evaluator: graceful stop done'


def rule_cleaner(once=False, worker_number=1, total_workers=1,):
    """
    Main loop to check for expired replication rules
    """

    print 'rule_cleaner: starting'

    print 'rule_cleaner: started'

    while not graceful_stop.is_set():
        try:
            # Select a bunch of rules for this worker to clean
            session = rucio_session.get_session()
            query = session.query(models.ReplicationRule.id).filter(models.ReplicationRule.expires_at < datetime.utcnow()).\
                with_hint(models.ReplicationRule, "index(rules RULES_EXPIRES_AT_IDX)", 'oracle').\
                order_by(models.ReplicationRule.expires_at)

            if worker_number and total_workers:
                if session.bind.dialect.name == 'oracle':
                    query = query.filter('ORA_HASH(name, %s) = %s' % (total_workers-1, worker_number-1))
                elif session.bind.dialect.name == 'mysql':
                    query = query.filter('mod(md5(name), %s) = %s' % (total_workers-1, worker_number-1))
                elif session.bind.dialect.name == 'sqlite':
                    pass

            start = time.time()
            rules = query.limit(1000).all()
            session.commit()
            session.remove()
            print 'rule_cleaner index query time %f rule-size=%d' % (time.time() - start, len(rules))

            if not rules and not once:
                print 'rule_cleaner[%s/%s] did not get any work' % (worker_number, total_workers)
                time.sleep(10)
            else:
                for rule_id in rules:
                    rule_id = rule_id[0]
                    if graceful_stop.is_set():
                        break
                    try:
                        record_gauge('rule.judge.cleaner.threads.%d' % worker_number, 1)
                        start = time.time()
                        delete_rule(rule_id=rule_id, lockmode='update_nowait')
                        print 'rule_cleaner[%s/%s]: deletion of %s took %f' % (worker_number, total_workers, rule_id, time.time() - start)
                        record_gauge('rule.judge.cleaner.threads.%d' % worker_number, 0)
                    except (DatabaseException, DatabaseError), e:
                        record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                        print 'rule_cleaner[%s/%s]: Locks detected for %s' % (worker_number, total_workers, id)
        except Exception, e:
            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
            print traceback.format_exc()
        if once:
            return

    print 'rule_cleaner: graceful stop requested'
    record_gauge('rule.judge.cleaner.threads.%d' % worker_number, 0)
    print 'rule_cleaner: graceful stop done'


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, re_evaluate_workers=1, cleaner_workers=1):
    """
    Starts up the Judge thread.
    """
    for i in xrange(1, 100):
        record_gauge('rule.judge.re_evaluate.threads.%d' % i, 0)
        record_gauge('rule.judge.cleaner.threads.%d' % i, 0)

    if once:
        print 'main: executing one iteration only'
        re_evaluator(once)
        rule_cleaner(once)
    else:
        print 'main: starting threads'
        threads = [threading.Thread(target=re_evaluator, kwargs={'worker_number': i, 'total_workers': re_evaluate_workers, 'once': once}) for i in xrange(1, re_evaluate_workers+1)]
        threads.extend([threading.Thread(target=rule_cleaner, kwargs={'worker_number': i, 'total_workers': cleaner_workers, 'once': once}) for i in xrange(1, cleaner_workers+1)])

        [t.start() for t in threads]
        print 'main: waiting for interrupts'
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
