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
# - Martin Barisits <martin.barisits@cern.ch>, 2013-2020
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013
# - Vincent Garonne <vincent.garonne@cern.ch>, 2016-2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

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
from random import randint
from re import match

from six import iteritems
from sqlalchemy.exc import DatabaseError
from sqlalchemy.orm.exc import FlushError

import rucio.db.sqla.util
from rucio.common.config import config_get
from rucio.common.exception import DatabaseException, DataIdentifierNotFound, ReplicationRuleCreationTemporaryFailed
from rucio.common.types import InternalScope
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.monitor import record_counter
from rucio.core.rule import re_evaluate_did, get_updated_dids, delete_updated_did

graceful_stop = threading.Event()

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
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
    executable = 'judge-evaluator'
    live(executable=executable, hostname=hostname, pid=pid, thread=current_thread, older_than=60 * 30)
    graceful_stop.wait(1)

    while not graceful_stop.is_set():
        try:
            # heartbeat
            heartbeat = live(executable=executable, hostname=hostname, pid=pid, thread=current_thread, older_than=60 * 30)

            start = time.time()  # NOQA

            # Refresh paused dids
            paused_dids = dict((k, v) for k, v in iteritems(paused_dids) if datetime.utcnow() < v)

            # Select a bunch of dids for re evaluation for this worker
            dids = get_updated_dids(total_workers=heartbeat['nr_threads'],
                                    worker_number=heartbeat['assign_thread'],
                                    limit=100,
                                    blacklisted_dids=[(InternalScope(key[0], fromExternal=False), key[1]) for key in paused_dids])
            logging.debug('re_evaluator[%s/%s] index query time %f fetch size is %d (%d blacklisted)' % (heartbeat['assign_thread'],
                                                                                                         heartbeat['nr_threads'],
                                                                                                         time.time() - start,
                                                                                                         len(dids),
                                                                                                         len([(InternalScope(key[0], fromExternal=False), key[1]) for key in paused_dids])))

            # If the list is empty, sent the worker to sleep
            if not dids and not once:
                logging.debug('re_evaluator[%s/%s] did not get any work (paused_dids=%s)' % (heartbeat['assign_thread'], heartbeat['nr_threads'], str(len(paused_dids))))
                graceful_stop.wait(30)
            else:
                done_dids = {}
                for did in dids:
                    if graceful_stop.is_set():
                        break

                    # Check if this did has already been operated on
                    did_tag = '%s:%s' % (did.scope.internal, did.name)
                    if did_tag in done_dids:
                        if did.rule_evaluation_action in done_dids[did_tag]:
                            logging.debug('re_evaluator[%s/%s]: evaluation of %s:%s already done' % (heartbeat['assign_thread'], heartbeat['nr_threads'], did.scope, did.name))
                            delete_updated_did(id=did.id)
                            continue
                    else:
                        done_dids[did_tag] = []

                    # Jump paused dids
                    if (did.scope.internal, did.name) in paused_dids:
                        continue

                    try:
                        start_time = time.time()
                        re_evaluate_did(scope=did.scope, name=did.name, rule_evaluation_action=did.rule_evaluation_action)
                        logging.debug('re_evaluator[%s/%s]: evaluation of %s:%s took %f' % (heartbeat['assign_thread'], heartbeat['nr_threads'], did.scope, did.name, time.time() - start_time))
                        delete_updated_did(id=did.id)
                        done_dids[did_tag].append(did.rule_evaluation_action)
                    except DataIdentifierNotFound:
                        delete_updated_did(id=did.id)
                    except (DatabaseException, DatabaseError) as e:
                        if match('.*ORA-00054.*', str(e.args[0])):
                            paused_dids[(did.scope.internal, did.name)] = datetime.utcnow() + timedelta(seconds=randint(60, 600))
                            logging.warning('re_evaluator[%s/%s]: Locks detected for %s:%s' % (heartbeat['assign_thread'], heartbeat['nr_threads'], did.scope, did.name))
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
                    except ReplicationRuleCreationTemporaryFailed as e:
                        record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                        logging.warning('re_evaluator[%s/%s]: Replica Creation temporary failed, retrying later for %s:%s' % (heartbeat['assign_thread'], heartbeat['nr_threads'], did.scope, did.name))
                    except FlushError as e:
                        record_counter('rule.judge.exceptions.%s' % e.__class__.__name__)
                        logging.warning('re_evaluator[%s/%s]: Flush error for %s:%s' % (heartbeat['assign_thread'], heartbeat['nr_threads'], did.scope, did.name))
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
    Starts up the Judge-Eval threads.
    """
    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    executable = 'judge-evaluator'
    hostname = socket.gethostname()
    sanity_check(executable=executable, hostname=hostname)

    if once:
        re_evaluator(once)
    else:
        logging.info('Evaluator starting %s threads' % str(threads))
        threads = [threading.Thread(target=re_evaluator, kwargs={'once': once}) for i in range(0, threads)]
        [t.start() for t in threads]
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
