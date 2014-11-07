# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2013-2014

"""
Judge-Repairer is a daemon to repair stuck replication rules.
"""

import logging
import threading
import time
import traceback

from datetime import datetime, timedelta
from re import match
from random import randint

from sqlalchemy.exc import DatabaseError

from rucio.common.config import config_get
from rucio.common.exception import DatabaseException
from rucio.core.rule import repair_rule, get_stuck_rules
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

    paused_rules = {}  # {rule_id: datetime}

    while not graceful_stop.is_set():
        try:
            # Select a bunch of rules for this worker to repair
            start = time.time()
            rules = get_stuck_rules(total_workers=total_processes*threads_per_process-1,
                                    worker_number=process*threads_per_process+thread,
                                    delta=-1 if once else 600)
            logging.debug('rule_repairer index query time %f fetch size is %d' % (time.time() - start, len(rules)))

            # Refresh paused rules
            for key in paused_rules:
                if datetime.utcnow() > paused_rules[key]:
                    del paused_rules[key]

            # Remove paused rules from result set
            rules = [rule for rule in rules if rule[0] not in paused_rules]

            if not rules and not once:
                logging.info('rule_repairer[%s/%s] did not get any work' % (process*threads_per_process+thread, total_processes*threads_per_process-1))
                time.sleep(10)
            else:
                record_gauge('rule.judge.repairer.threads.%d' % (process*threads_per_process+thread), 1)
                for rule_id in rules:
                    rule_id = rule_id[0]
                    logging.info('rule_repairer[%s/%s]: Repairing rule %s' % (process*threads_per_process+thread, total_processes*threads_per_process-1, rule_id))
                    if graceful_stop.is_set():
                        break
                    try:
                        start = time.time()
                        repair_rule(rule_id=rule_id)
                        logging.debug('rule_repairer[%s/%s]: repairing of %s took %f' % (process*threads_per_process+thread, total_processes*threads_per_process-1, rule_id, time.time() - start))
                    except (DatabaseException, DatabaseError), e:
                        if match('.*ORA-00054.*', str(e.args[0])):
                            paused_rules[rule_id] = datetime.utcnow() + timedelta(seconds=randint(60, 600))
                            logging.warning('rule_repairer[%s/%s]: Locks detected for %s' % (process*threads_per_process+thread, total_processes*threads_per_process-1, rule_id))
                            record_counter('rule.judge.exceptions.LocksDetected')
                        else:
                            logging.error(traceback.format_exc())
                            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)

                record_gauge('rule.judge.repairer.threads.%d' % (process*threads_per_process+thread), 0)
        except Exception, e:
            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
            record_gauge('rule.judge.repairer.threads.%d' % (process*threads_per_process+thread), 0)
            logging.critical(traceback.format_exc())
        if once:
            return
        else:
            time.sleep(30)

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
