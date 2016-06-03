# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2013-2015
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2016

"""
Judge-Evaluator is a daemon to re-evaluate and execute replication rules.
"""

import logging
import os
import socket
import sys
import threading
import time
import traceback

from datetime import datetime, timedelta
from re import match
from random import randint

from sqlalchemy.exc import DatabaseError
from sqlalchemy.orm.exc import FlushError

from rucio.common.config import config_get
from rucio.common.exception import DatabaseException, DataIdentifierNotFound, ReplicationRuleCreationTemporaryFailed
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.rule import re_evaluate_did, get_updated_dids, delete_updated_did, delete_duplicate_updated_dids
from rucio.core.monitor import record_counter

graceful_stop = threading.Event()

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


def re_evaluator(once=False):
    """
    Main loop to check the re-evaluation of dids.
    """

    hostname = socket.gethostname()
    pid = os.getpid()
    current_thread = threading.current_thread()

    paused_dids = {}  # {(scope, name): datetime}

    # Make an initial heartbeat so that all judge-evaluators have the correct worker number on the next try
    live(executable='rucio-judge-evaluator', hostname=hostname, pid=pid, thread=current_thread, older_than=60 * 30)
    graceful_stop.wait(1)

    while not graceful_stop.is_set():
        try:
            # heartbeat
            heartbeat = live(executable='rucio-judge-evaluator', hostname=hostname, pid=pid, thread=current_thread, older_than=60 * 30)

            # Select a bunch of dids for re evaluation for this worker
            start = time.time()  # NOQA
            dids = get_updated_dids(total_workers=heartbeat['nr_threads'] - 1,
                                    worker_number=heartbeat['assign_thread'],
                                    limit=100)
            logging.debug('re_evaluator[%s/%s] index query time %f fetch size is %d' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, time.time() - start, len(dids)))

            # Refresh paused dids
            paused_dids = dict((k, v) for k, v in paused_dids.iteritems() if datetime.utcnow() > v)

            # Remove paused dids from result set
            dids = [did for did in dids if (did.scope, did.name) not in paused_dids]

            # If the list is empty, sent the worker to sleep
            if not dids and not once:
                logging.debug('re_evaluator[%s/%s] did not get any work' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1))
                graceful_stop.wait(30)
            else:
                done_dids = {}
                for did in dids:
                    if graceful_stop.is_set():
                        break

                    # Try to delete all duplicate dids
                    delete_duplicate_updated_dids(scope=did.scope, name=did.name, rule_evaluation_action=did.rule_evaluation_action, id=did.id)

                    # Check if this did has already been operated on
                    if '%s:%s' % (did.scope, did.name) in done_dids:
                        if did.rule_evaluation_action in done_dids['%s:%s' % (did.scope, did.name)]:
                            logging.debug('re_evaluator[%s/%s]: evaluation of %s:%s already done' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, did.scope, did.name))
                            continue
                    else:
                        done_dids['%s:%s' % (did.scope, did.name)] = []

                    try:
                        start_time = time.time()
                        re_evaluate_did(scope=did.scope, name=did.name, rule_evaluation_action=did.rule_evaluation_action)
                        logging.debug('re_evaluator[%s/%s]: evaluation of %s:%s took %f' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, did.scope, did.name, time.time() - start_time))
                        delete_updated_did(id=did.id, scope=did.scope, name=did.name)
                        done_dids['%s:%s' % (did.scope, did.name)].append(did.rule_evaluation_action)
                    except DataIdentifierNotFound, e:
                        delete_updated_did(id=did.id, scope=did.scope, name=did.name)
                    except (DatabaseException, DatabaseError), e:
                        if match('.*ORA-00054.*', str(e.args[0])):
                            paused_dids[(did.scope, did.name)] = datetime.utcnow() + timedelta(seconds=randint(60, 600))
                            logging.warning('re_evaluator[%s/%s]: Locks detected for %s:%s' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, did.scope, did.name))
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
                    except ReplicationRuleCreationTemporaryFailed, e:
                        record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                        logging.warning('re_evaluator[%s/%s]: Replica Creation temporary failed, retrying later for %s:%s' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, did.scope, did.name))
                    except FlushError, e:
                        record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                        logging.warning('re_evaluator[%s/%s]: Flush error for %s:%s' % (heartbeat['assign_thread'], heartbeat['nr_threads'] - 1, did.scope, did.name))
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

    die(executable='rucio-judge-evaluator', hostname=hostname, pid=pid, thread=current_thread)


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, threads=1):
    """
    Starts up the Judge-Eval threads.
    """

    hostname = socket.gethostname()
    sanity_check(executable='rucio-judge-evaluator', hostname=hostname)

    if once:
        re_evaluator(once)
    else:
        logging.info('Evaluator starting %s threads' % str(threads))
        threads = [threading.Thread(target=re_evaluator, kwargs={'once': once}) for i in xrange(0, threads)]
        [t.start() for t in threads]
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
