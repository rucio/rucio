# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2013-2016
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2015

"""
Judge-Repairer is a daemon to repair stuck replication rules.
"""

import logging
import os
import socket
import threading
import time
import traceback

from copy import deepcopy
from datetime import datetime, timedelta
from re import match
from random import randint

from sqlalchemy.exc import DatabaseError

from rucio.common.config import config_get
from rucio.common.exception import DatabaseException
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.rule import repair_rule, get_stuck_rules
from rucio.core.monitor import record_counter

graceful_stop = threading.Event()

logging.basicConfig(filename='%s/%s.log' % (config_get('common', 'logdir'), __name__),
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


def rule_repairer(once=False):
    """
    Main loop to check for STUCK replication rules
    """

    hostname = socket.gethostname()
    pid = os.getpid()
    current_thread = threading.current_thread()

    paused_rules = {}  # {rule_id: datetime}

    # Make an initial heartbeat so that all judge-repairers have the correct worker number on the next try
    live(executable='rucio-judge-repairer', hostname=hostname, pid=pid, thread=current_thread, older_than=60 * 30)
    graceful_stop.wait(1)

    while not graceful_stop.is_set():
        try:
            # heartbeat
            heartbeat = live(executable='rucio-judge-repairer', hostname=hostname, pid=pid, thread=current_thread, older_than=60 * 30)

            start = time.time()

            # Refresh paused rules
            iter_paused_rules = deepcopy(paused_rules)
            for key in iter_paused_rules:
                if datetime.utcnow() > paused_rules[key]:
                    del paused_rules[key]

            # Select a bunch of rules for this worker to repair
            rules = get_stuck_rules(total_workers=heartbeat['nr_threads'] - 1,
                                    worker_number=heartbeat['assign_thread'],
                                    delta=-1 if once else 1800,
                                    limit=100,
                                    blacklisted_rules=[key for key in paused_rules])
            logging.debug('rule_repairer[%s/%s] index query time %f fetch size is %d' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, time.time() - start, len(rules)))

            if not rules and not once:
                logging.debug('rule_repairer[%s/%s] did not get any work (paused_rules=%s)' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, str(len(paused_rules))))
                graceful_stop.wait(60)
            else:
                for rule_id in rules:
                    rule_id = rule_id[0]
                    logging.info('rule_repairer[%s/%s]: Repairing rule %s' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, rule_id))
                    if graceful_stop.is_set():
                        break
                    try:
                        start = time.time()
                        repair_rule(rule_id=rule_id)
                        logging.debug('rule_repairer[%s/%s]: repairing of %s took %f' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, rule_id, time.time() - start))
                    except (DatabaseException, DatabaseError), e:
                        if match('.*ORA-00054.*', str(e.args[0])):
                            paused_rules[rule_id] = datetime.utcnow() + timedelta(seconds=randint(600, 2400))
                            logging.warning('rule_repairer[%s/%s]: Locks detected for %s' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, rule_id))
                            record_counter('rule.judge.exceptions.LocksDetected')
                        elif match('.*QueuePool.*', str(e.args[0])):
                            logging.warning(traceback.format_exc())
                            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                        elif match('.*ORA-03135.*', str(e.args[0])):
                            logging.warning(traceback.format_exc())
                            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                        else:
                            logging.error(traceback.format_exc())
                            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)

        except (DatabaseException, DatabaseError), e:
            if match('.*QueuePool.*', str(e.args[0])):
                logging.warning(traceback.format_exc())
                record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
            elif match('.*ORA-03135.*', str(e.args[0])):
                logging.warning(traceback.format_exc())
                record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
            else:
                logging.critical(traceback.format_exc())
                record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
        except Exception, e:
            logging.critical(traceback.format_exc())
            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
        if once:
            break

    die(executable='rucio-judge-repairer', hostname=hostname, pid=pid, thread=current_thread)


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, threads=1):
    """
    Starts up the Judge-Repairer threads.
    """

    hostname = socket.gethostname()
    sanity_check(executable='rucio-judge-repairer', hostname=hostname)

    if once:
        rule_repairer(once)
    else:
        logging.info('Repairer starting %s threads' % str(threads))
        threads = [threading.Thread(target=rule_repairer, kwargs={'once': once}) for i in xrange(0, threads)]
        [t.start() for t in threads]
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
