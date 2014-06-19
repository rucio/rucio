# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2013

"""
Judge-Repairer is a daemon to repair stuck replication rules.
"""

import logging
import threading
import time
import traceback

from sqlalchemy.exc import DatabaseError
from sqlalchemy.sql.expression import bindparam
from sqlalchemy.sql.expression import text

from rucio.common.config import config_get
from rucio.common.exception import DatabaseException
from rucio.db import session as rucio_session
from rucio.db import models
from rucio.db.constants import RuleState
from rucio.core.rule import repair_rule
from rucio.core.monitor import record_gauge, record_counter

graceful_stop = threading.Event()

logging.basicConfig(filename='%s/%s.log' % (config_get('common', 'logdir'), __name__),
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


def rule_repairer(once=False, process=0, total_processes=1, thread=0, threads_per_process=1):
    """
    Main loop to check for STUCK replication rules
    """

    logging.info('rule_repairer: starting')

    logging.info('rule_repairer: started')

    while not graceful_stop.is_set():
        try:
            # Select a bunch of rules for this worker to repair
            session = rucio_session.get_session()
            query = session.query(models.ReplicationRule.id).filter(models.ReplicationRule.state == RuleState.STUCK).\
                with_hint(models.ReplicationRule, "index(rules RULES_STUCKSTATE_IDX)", 'oracle')
            #   order_by(models.ReplicationRule.expires_at)

            if total_processes*threads_per_process-1 > 0:
                if session.bind.dialect.name == 'oracle':
                    bindparams = [bindparam('worker_number', process*threads_per_process+thread),
                                  bindparam('total_workers', total_processes*threads_per_process-1)]
                    query = query.filter(text('ORA_HASH(name, :total_workers) = :worker_number', bindparams=bindparams))
                elif session.bind.dialect.name == 'mysql':
                    query = query.filter('mod(md5(name), %s) = %s' % (total_processes*threads_per_process-1, process*threads_per_process+thread))
                elif session.bind.dialect.name == 'sqlite':
                    pass

            start = time.time()
            rules = query.limit(1000).all()
            session.commit()
            session.remove()
            logging.debug('rule_repairer index query time %f rule-size=%d' % (time.time() - start, len(rules)))

            if not rules and not once:
                logging.info('rule_repairer[%s/%s] did not get any work' % (process*threads_per_process+thread, total_processes*threads_per_process-1))
                time.sleep(10)
            else:
                record_gauge('rule.judge.repairer.threads.%d' % (process*threads_per_process+thread), 1)
                for rule_id in rules:
                    rule_id = rule_id[0]
                    logging.info(logging.debug('rule_repairer[%s/%s]: Repairing rule %s' % (process*threads_per_process+thread, total_processes*threads_per_process-1, rule_id)))
                    if graceful_stop.is_set():
                        break
                    try:
                        start = time.time()
                        repair_rule(rule_id=rule_id)
                        logging.debug('rule_repairer[%s/%s]: repairing of %s took %f' % (process*threads_per_process+thread, total_processes*threads_per_process-1, rule_id, time.time() - start))
                    except (DatabaseException, DatabaseError), e:
                        record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                        logging.warning('rule_repairer[%s/%s]: Locks detected for %s' % (process*threads_per_process+thread, total_processes*threads_per_process-1, rule_id))
                record_gauge('rule.judge.repairer.threads.%d' % (process*threads_per_process+thread), 0)
        except Exception, e:
            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
            record_gauge('rule.judge.repairer.threads.%d' % (process*threads_per_process+thread), 0)
            logging.critical(traceback.format_exc())
        if once:
            return

    logging.info('rule_repairer: graceful stop requested')
    record_gauge('rule.judge.repairer.threads.%d' % (process*threads_per_process+thread), 0)
    logging.info('rule_repairer: graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, process=0, total_processes=1, threads_per_process=1):
    """
    Starts up the Judge-Repairer threads.
    """
    for i in xrange(process * threads_per_process, max(0, process * threads_per_process + threads_per_process - 1)):
        record_gauge('rule.judge.repairer.threads.%d' % i, 0)

    if once:
        logging.info('main: executing one iteration only')
        rule_repairer(once)
    else:
        logging.info('main: starting threads')
        threads = [threading.Thread(target=rule_repairer, kwargs={'process': process, 'total_processes': total_processes, 'once': once, 'thread': i, 'threads_per_process': threads_per_process}) for i in xrange(0, threads_per_process)]
        [t.start() for t in threads]
        logging.info('main: waiting for interrupts')
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
