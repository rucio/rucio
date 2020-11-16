# -*- coding: utf-8 -*-
# Copyright 2013-2020 CERN
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
# - Martin Barisits <martin.barisits@cern.ch>, 2013-2016
# - Vincent Garonne <vincent.garonne@cern.ch>, 2014-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2014-2015
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

"""
Judge-Repairer is a daemon to repair stuck replication rules.
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
from random import randint
from re import match

from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get
from rucio.common.exception import DatabaseException
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.monitor import record_counter
from rucio.core.rule import repair_rule, get_stuck_rules

graceful_stop = threading.Event()

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
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
    executable = 'judge-repairer'
    live(executable=executable, hostname=hostname, pid=pid, thread=current_thread, older_than=60 * 30)
    graceful_stop.wait(1)

    while not graceful_stop.is_set():
        try:
            # heartbeat
            heartbeat = live(executable=executable, hostname=hostname, pid=pid, thread=current_thread, older_than=60 * 30)

            start = time.time()

            # Refresh paused rules
            iter_paused_rules = deepcopy(paused_rules)
            for key in iter_paused_rules:
                if datetime.utcnow() > paused_rules[key]:
                    del paused_rules[key]

            # Select a bunch of rules for this worker to repair
            rules = get_stuck_rules(total_workers=heartbeat['nr_threads'],
                                    worker_number=heartbeat['assign_thread'],
                                    delta=-1 if once else 1800,
                                    limit=100,
                                    blacklisted_rules=[key for key in paused_rules])

            logging.debug('rule_repairer[%s/%s] index query time %f fetch size is %d' % (heartbeat['assign_thread'], heartbeat['nr_threads'], time.time() - start, len(rules)))

            if not rules and not once:
                logging.debug('rule_repairer[%s/%s] did not get any work (paused_rules=%s)' % (heartbeat['assign_thread'], heartbeat['nr_threads'], str(len(paused_rules))))
                graceful_stop.wait(60)
            else:
                for rule_id in rules:
                    rule_id = rule_id[0]
                    logging.info('rule_repairer[%s/%s]: Repairing rule %s' % (heartbeat['assign_thread'], heartbeat['nr_threads'], rule_id))
                    if graceful_stop.is_set():
                        break
                    try:
                        start = time.time()
                        repair_rule(rule_id=rule_id)
                        logging.debug('rule_repairer[%s/%s]: repairing of %s took %f' % (heartbeat['assign_thread'], heartbeat['nr_threads'], rule_id, time.time() - start))
                    except (DatabaseException, DatabaseError) as e:
                        if match('.*ORA-00054.*', str(e.args[0])):
                            paused_rules[rule_id] = datetime.utcnow() + timedelta(seconds=randint(600, 2400))
                            logging.warning('rule_repairer[%s/%s]: Locks detected for %s' % (heartbeat['assign_thread'], heartbeat['nr_threads'], rule_id))
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

        except (DatabaseException, DatabaseError) as e:
            if match('.*QueuePool.*', str(e.args[0])):
                logging.warning(traceback.format_exc())
                record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
            elif match('.*ORA-03135.*', str(e.args[0])):
                logging.warning(traceback.format_exc())
                record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
            else:
                logging.critical(traceback.format_exc())
                record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
        except Exception as e:
            logging.critical(traceback.format_exc())
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
    Starts up the Judge-Repairer threads.
    """
    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    executable = 'judge-repairer'
    hostname = socket.gethostname()
    sanity_check(executable=executable, hostname=hostname)

    if once:
        rule_repairer(once)
    else:
        logging.info('Repairer starting %s threads' % str(threads))
        threads = [threading.Thread(target=rule_repairer, kwargs={'once': once}) for i in range(0, threads)]
        [t.start() for t in threads]
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
