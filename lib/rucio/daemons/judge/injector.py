# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2015

"""
Judge-Injector is a daemon to asynchronously create replication rules
"""

import logging
import os
import socket
import sys
import threading
import time
import traceback

from copy import deepcopy
from datetime import datetime, timedelta
from re import match
from random import randint

from sqlalchemy.exc import DatabaseError

from rucio.common.config import config_get
from rucio.common.exception import DatabaseException, RuleNotFound, RSEBlacklisted, ReplicationRuleCreationTemporaryFailed
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.rule import inject_rule, get_injected_rules
from rucio.core.monitor import record_counter

graceful_stop = threading.Event()

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


def rule_injector(once=False):
    """
    Main loop to check for asynchronous creation of replication rules
    """

    hostname = socket.gethostname()
    pid = os.getpid()
    current_thread = threading.current_thread()

    paused_rules = {}  # {rule_id: datetime}

    # Make an initial heartbeat so that all judge-inectors have the correct worker number on the next try
    live(executable='rucio-judge-injector', hostname=hostname, pid=pid, thread=current_thread, older_than=2 * 60 * 60)
    graceful_stop.wait(1)

    while not graceful_stop.is_set():
        try:
            # heartbeat
            heartbeat = live(executable='rucio-judge-injector', hostname=hostname, pid=pid, thread=current_thread, older_than=2 * 60 * 60)

            start = time.time()
            rules = get_injected_rules(total_workers=heartbeat['nr_threads'] - 1,
                                       worker_number=heartbeat['assign_thread'],
                                       limit=10)
            logging.debug('rule_injector[%s/%s] index query time %f fetch size is %d' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, time.time() - start, len(rules)))

            # Refresh paused rules
            iter_paused_rules = deepcopy(paused_rules)
            for key in iter_paused_rules:
                if datetime.utcnow() > paused_rules[key]:
                    del paused_rules[key]

            # Remove paused rules from result set
            rules = [rule for rule in rules if rule[0] not in paused_rules]

            if not rules and not once:
                logging.debug('rule_injector[%s/%s] did not get any work' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1))
                graceful_stop.wait(60)
            else:
                for rule in rules:
                    rule_id = rule[0]
                    logging.info('rule_injector[%s/%s]: Injecting rule %s' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, rule_id))
                    if graceful_stop.is_set():
                        break
                    try:
                        start = time.time()
                        inject_rule(rule_id=rule_id)
                        logging.debug('rule_injector[%s/%s]: injection of %s took %f' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, rule_id, time.time() - start))
                    except (DatabaseException, DatabaseError), e:
                        if match('.*ORA-00054.*', str(e.args[0])):
                            paused_rules[rule_id] = datetime.utcnow() + timedelta(seconds=randint(60, 600))
                            record_counter('rule.judge.exceptions.LocksDetected')
                            logging.warning('rule_injector[%s/%s]: Locks detected for %s' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, rule_id))
                        elif match('.*QueuePool.*', str(e.args[0])):
                            logging.warning(traceback.format_exc())
                            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                        elif match('.*ORA-03135.*', str(e.args[0])):
                            logging.warning(traceback.format_exc())
                            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                        else:
                            logging.error(traceback.format_exc())
                            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                    except RSEBlacklisted, e:
                        paused_rules[rule_id] = datetime.utcnow() + timedelta(seconds=randint(60, 600))
                        logging.warning('rule_injector[%s/%s]: RSEBlacklisted for rule %s' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, rule_id))
                        record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                    except ReplicationRuleCreationTemporaryFailed, e:
                        paused_rules[rule_id] = datetime.utcnow() + timedelta(seconds=randint(60, 600))
                        logging.warning('rule_injector[%s/%s]: ReplicationRuleCreationTemporaryFailed for rule %s' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, rule_id))
                        record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                    except RuleNotFound, e:
                        pass
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

    die(executable='rucio-judge-injector', hostname=hostname, pid=pid, thread=current_thread)


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, threads=1):
    """
    Starts up the Judge-Injector threads.
    """

    hostname = socket.gethostname()
    sanity_check(executable='rucio-judge-injector', hostname=hostname)

    if once:
        rule_injector(once)
    else:
        logging.info('Injector starting %s threads' % str(threads))
        threads = [threading.Thread(target=rule_injector, kwargs={'once': once}) for i in xrange(0, threads)]
        [t.start() for t in threads]
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
