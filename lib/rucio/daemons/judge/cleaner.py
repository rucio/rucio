# Copyright 2013-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2015
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013
# - Vincent Garonne <vgaronne@gmail.com>, 2014-2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

"""
Judge-Cleaner is a daemon to clean expired replication rules.
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
from rucio.common.exception import DatabaseException, UnsupportedOperation, RuleNotFound
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.rule import delete_rule, get_expired_rules
from rucio.core.monitor import record_counter
from rucio.db.sqla.util import get_db_time

graceful_stop = threading.Event()

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


def rule_cleaner(once=False):
    """
    Main loop to check for expired replication rules
    """

    hostname = socket.gethostname()
    pid = os.getpid()
    current_thread = threading.current_thread()

    paused_rules = {}  # {rule_id: datetime}

    # Make an initial heartbeat so that all judge-cleaners have the correct worker number on the next try
    live(executable='rucio-judge-cleaner', hostname=hostname, pid=pid, thread=current_thread)
    graceful_stop.wait(1)

    while not graceful_stop.is_set():
        try:
            # heartbeat
            heartbeat = live(executable='rucio-judge-cleaner', hostname=hostname, pid=pid, thread=current_thread)

            start = time.time()

            # Refresh paused rules
            iter_paused_rules = deepcopy(paused_rules)
            for key in iter_paused_rules:
                if datetime.utcnow() > paused_rules[key]:
                    del paused_rules[key]

            rules = get_expired_rules(total_workers=heartbeat['nr_threads'] - 1,
                                      worker_number=heartbeat['assign_thread'],
                                      limit=200,
                                      blacklisted_rules=[key for key in paused_rules])
            logging.debug('rule_cleaner[%s/%s] index query time %f fetch size is %d' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, time.time() - start, len(rules)))

            if not rules and not once:
                logging.debug('rule_cleaner[%s/%s] did not get any work (paused_rules=%s)' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, str(len(paused_rules))))
                graceful_stop.wait(60)
            else:
                for rule in rules:
                    rule_id = rule[0]
                    rule_expression = rule[1]
                    logging.info('rule_cleaner[%s/%s]: Deleting rule %s with expression %s' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, rule_id, rule_expression))
                    if graceful_stop.is_set():
                        break
                    try:
                        start = time.time()
                        delete_rule(rule_id=rule_id, nowait=True)
                        logging.debug('rule_cleaner[%s/%s]: deletion of %s took %f' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, rule_id, time.time() - start))
                    except (DatabaseException, DatabaseError, UnsupportedOperation) as e:
                        if match('.*ORA-00054.*', str(e.args[0])):
                            paused_rules[rule_id] = datetime.utcnow() + timedelta(seconds=randint(600, 2400))
                            record_counter('rule.judge.exceptions.LocksDetected')
                            logging.warning('rule_cleaner[%s/%s]: Locks detected for %s' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, rule_id))
                        elif match('.*QueuePool.*', str(e.args[0])):
                            logging.warning(traceback.format_exc())
                            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                        elif match('.*ORA-03135.*', str(e.args[0])):
                            logging.warning(traceback.format_exc())
                            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                        else:
                            logging.error(traceback.format_exc())
                            record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                    except RuleNotFound as e:
                        pass
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

    die(executable='rucio-judge-cleaner', hostname=hostname, pid=pid, thread=current_thread)


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()


def run(once=False, threads=1):
    """
    Starts up the Judge-Clean threads.
    """
    client_time, db_time = datetime.utcnow(), get_db_time()
    max_offset = timedelta(hours=1, seconds=10)
    if type(db_time) is datetime:
        if db_time - client_time > max_offset or client_time - db_time > max_offset:
            logging.critical('Offset between client and db time too big. Stopping Cleaner')
            return

    hostname = socket.gethostname()
    sanity_check(executable='rucio-judge-cleaner', hostname=hostname)

    if once:
        rule_cleaner(once)
    else:
        logging.info('Cleaner starting %s threads' % str(threads))
        threads = [threading.Thread(target=rule_cleaner, kwargs={'once': once}) for i in range(0, threads)]
        [t.start() for t in threads]
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
