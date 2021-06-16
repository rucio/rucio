# -*- coding: utf-8 -*-
# Copyright 2013-2021 CERN
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
# - Martin Barisits <martin.barisits@cern.ch>, 2013-2021
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2015
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013
# - Vincent Garonne <vincent.garonne@cern.ch>, 2014-2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020-2021
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

"""
Judge-Cleaner is a daemon to clean expired replication rules.
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
from rucio.common import exception
from rucio.common.logging import formatted_logger, setup_logging
from rucio.common.exception import DatabaseException, UnsupportedOperation, RuleNotFound
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.monitor import record_counter
from rucio.core.rule import delete_rule, get_expired_rules
from rucio.db.sqla.util import get_db_time

graceful_stop = threading.Event()


def rule_cleaner(once=False):
    """
    Main loop to check for expired replication rules
    """

    hostname = socket.gethostname()
    pid = os.getpid()
    current_thread = threading.current_thread()

    paused_rules = {}  # {rule_id: datetime}

    # Make an initial heartbeat so that all judge-cleaners have the correct worker number on the next try
    executable = 'judge-cleaner'
    heartbeat = live(executable=executable, hostname=hostname, pid=pid, thread=current_thread)
    prefix = 'judge-cleaner[%i/%i] ' % (heartbeat['assign_thread'], heartbeat['nr_threads'])
    logger = formatted_logger(logging.log, prefix + '%s')
    graceful_stop.wait(1)

    while not graceful_stop.is_set():
        try:
            # heartbeat
            heartbeat = live(executable=executable, hostname=hostname, pid=pid, thread=current_thread)
            prefix = 'judge-cleaner[%i/%i] ' % (heartbeat['assign_thread'], heartbeat['nr_threads'])
            logger = formatted_logger(logging.log, prefix + '%s')

            start = time.time()

            # Refresh paused rules
            iter_paused_rules = deepcopy(paused_rules)
            for key in iter_paused_rules:
                if datetime.utcnow() > paused_rules[key]:
                    del paused_rules[key]

            rules = get_expired_rules(total_workers=heartbeat['nr_threads'],
                                      worker_number=heartbeat['assign_thread'],
                                      limit=200,
                                      blocked_rules=[key for key in paused_rules])
            logger(logging.DEBUG, 'index query time %f fetch size is %d' % (time.time() - start, len(rules)))

            if not rules and not once:
                logger(logging.DEBUG, 'did not get any work (paused_rules=%s)' % str(len(paused_rules)))
                graceful_stop.wait(60)
            else:
                for rule in rules:
                    rule_id = rule[0]
                    rule_expression = rule[1]
                    logger(logging.INFO, 'Deleting rule %s with expression %s' % (rule_id, rule_expression))
                    if graceful_stop.is_set():
                        break
                    try:
                        start = time.time()
                        delete_rule(rule_id=rule_id, nowait=True)
                        logger(logging.DEBUG, 'deletion of %s took %f' % (rule_id, time.time() - start))
                    except (DatabaseException, DatabaseError, UnsupportedOperation) as e:
                        if match('.*ORA-00054.*', str(e.args[0])):
                            paused_rules[rule_id] = datetime.utcnow() + timedelta(seconds=randint(600, 2400))
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
                    except RuleNotFound:
                        pass
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
            logger(logging.CRITICAL, 'DatabaseException', exc_info=True)
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
    Starts up the Judge-Clean threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    client_time, db_time = datetime.utcnow(), get_db_time()
    max_offset = timedelta(hours=1, seconds=10)
    if type(db_time) is datetime:
        if db_time - client_time > max_offset or client_time - db_time > max_offset:
            logging.critical('Offset between client and db time too big. Stopping Cleaner')
            return

    executable = 'judge-cleaner'
    hostname = socket.gethostname()
    sanity_check(executable=executable, hostname=hostname)

    if once:
        rule_cleaner(once)
    else:
        logging.info('Cleaner starting %s threads' % str(threads))
        threads = [threading.Thread(target=rule_cleaner, kwargs={'once': once}) for i in range(0, threads)]
        [t.start() for t in threads]
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
