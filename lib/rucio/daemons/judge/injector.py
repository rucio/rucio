# -*- coding: utf-8 -*-
# Copyright 2015-2021 CERN
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
# - Martin Barisits <martin.barisits@cern.ch>, 2015-2021
# - Vincent Garonne <vincent.garonne@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020-2021
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Eric Vaandering <ewv@fnal.gov>, 2020

"""
Judge-Injector is a daemon to asynchronously create replication rules
"""

import logging
import os
import socket
import threading
import time
from copy import deepcopy
from datetime import datetime, timedelta
from random import randint
from re import match

from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common.logging import formatted_logger, setup_logging
from rucio.common.exception import (DatabaseException, RuleNotFound, RSEWriteBlocked,
                                    ReplicationRuleCreationTemporaryFailed, InsufficientAccountLimit)
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.monitor import record_counter
from rucio.core.rule import inject_rule, get_injected_rules, update_rule

graceful_stop = threading.Event()


def rule_injector(once=False):
    """
    Main loop to check for asynchronous creation of replication rules
    """

    hostname = socket.gethostname()
    pid = os.getpid()
    current_thread = threading.current_thread()

    paused_rules = {}  # {rule_id: datetime}

    # Make an initial heartbeat so that all judge-inectors have the correct worker number on the next try
    executable = 'judge-injector'
    heartbeat = live(executable=executable, hostname=hostname, pid=pid, thread=current_thread, older_than=2 * 60 * 60)
    prefix = 'judge-injector[%i/%i] ' % (heartbeat['assign_thread'], heartbeat['nr_threads'])
    logger = formatted_logger(logging.log, prefix + '%s')
    graceful_stop.wait(1)

    while not graceful_stop.is_set():
        try:
            # heartbeat
            heartbeat = live(executable=executable, hostname=hostname, pid=pid, thread=current_thread, older_than=2 * 60 * 60)
            prefix = 'judge-injector[%i/%i] ' % (heartbeat['assign_thread'], heartbeat['nr_threads'])
            logger = formatted_logger(logging.log, prefix + '%s')

            start = time.time()

            # Refresh paused rules
            iter_paused_rules = deepcopy(paused_rules)
            for key in iter_paused_rules:
                if datetime.utcnow() > paused_rules[key]:
                    del paused_rules[key]

            rules = get_injected_rules(total_workers=heartbeat['nr_threads'],
                                       worker_number=heartbeat['assign_thread'],
                                       limit=100,
                                       blocked_rules=[key for key in paused_rules])
            logger(logging.DEBUG, 'index query time %f fetch size is %d' % (time.time() - start, len(rules)))

            if not rules and not once:
                logger(logging.DEBUG, 'did not get any work (paused_rules=%s)' % str(len(paused_rules)))
                graceful_stop.wait(60)
            else:
                for rule in rules:
                    rule_id = rule[0]
                    logger(logging.INFO, 'Injecting rule %s' % rule_id)
                    if graceful_stop.is_set():
                        break
                    try:
                        start = time.time()
                        inject_rule(rule_id=rule_id, logger=logger)
                        logger(logging.DEBUG, 'injection of %s took %f' % (rule_id, time.time() - start))
                    except (DatabaseException, DatabaseError) as e:
                        if match('.*ORA-00054.*', str(e.args[0])):
                            paused_rules[rule_id] = datetime.utcnow() + timedelta(seconds=randint(60, 600))
                            record_counter('rule.judge.exceptions.LocksDetected')
                            logger(logging.WARNING, 'Locks detected for %s' % rule_id)
                        elif match('.*QueuePool.*', str(e.args[0])):
                            logger(logging.WARNING, 'DatabaseException', exc_info=True)
                            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                        elif match('.*ORA-03135.*', str(e.args[0])):
                            logger(logging.WARNING, 'DatabaseException', exc_info=True)
                            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                        else:
                            logger(logging.ERROR, 'DatabaseException', exc_info=True)
                            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                    except (RSEWriteBlocked) as e:
                        paused_rules[rule_id] = datetime.utcnow() + timedelta(seconds=randint(60, 600))
                        logger(logging.WARNING, 'RSEWriteBlocked for rule %s' % rule_id)
                        record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                    except ReplicationRuleCreationTemporaryFailed as e:
                        paused_rules[rule_id] = datetime.utcnow() + timedelta(seconds=randint(60, 600))
                        logger(logging.WARNING, 'ReplicationRuleCreationTemporaryFailed for rule %s' % rule_id)
                        record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                    except RuleNotFound:
                        pass
                    except InsufficientAccountLimit:
                        # A rule with InsufficientAccountLimit on injection hangs there potentially forever
                        # It should be marked as SUSPENDED
                        logger(logging.INFO, 'Marking rule %s as SUSPENDED due to InsufficientAccountLimit' % rule_id)
                        update_rule(rule_id=rule_id, options={'state': 'SUSPENDED'})

        except (DatabaseException, DatabaseError) as e:
            if match('.*QueuePool.*', str(e.args[0])):
                logger(logging.WARNING, 'DatabaseException', exc_info=True)
                record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
            elif match('.*ORA-03135.*', str(e.args[0])):
                logger(logging.WARNING, 'DatabaseException', exc_info=True)
                record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
            else:
                logger(logging.CRITICAL, 'DatabaseException', exc_info=True)
                record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
        except Exception as e:
            logger(logging.CRITICAL, 'Exception', exc_info=True)
            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
        if once:
            break

    die(executable=executable, hostname=hostname, pid=pid, thread=current_thread)


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, threads=1):
    """
    Starts up the Judge-Injector threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    executable = 'judge-injector'
    hostname = socket.gethostname()
    sanity_check(executable=executable, hostname=hostname)

    if once:
        rule_injector(once)
    else:
        logging.info('Injector starting %s threads' % str(threads))
        threads = [threading.Thread(target=rule_injector, kwargs={'once': once}) for i in range(0, threads)]
        [t.start() for t in threads]
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
