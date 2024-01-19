# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

"""
Judge-Evaluator is a daemon to re-evaluate and execute replication rules.
"""
import copy
import functools
import logging
import threading
import time
import traceback
from datetime import datetime, timedelta
from random import randint
from re import match
from typing import TYPE_CHECKING
from rucio.db.sqla.constants import ORACLE_CONNECTION_LOST_CONTACT_REGEX, ORACLE_RESOURCE_BUSY_REGEX, ORACLE_UNIQUE_CONSTRAINT_VIOLATED_REGEX

from sqlalchemy.exc import DatabaseError
from sqlalchemy.orm.exc import FlushError

import rucio.db.sqla.util
from rucio.common.exception import DatabaseException, DataIdentifierNotFound, ReplicationRuleCreationTemporaryFailed
from rucio.common.logging import setup_logging
from rucio.common.types import InternalScope
from rucio.core.monitor import MetricManager
from rucio.core.rule import re_evaluate_did, get_updated_dids, delete_updated_did
from rucio.daemons.common import run_daemon

if TYPE_CHECKING:
    from types import FrameType
    from typing import Optional

METRICS = MetricManager(module=__name__)
graceful_stop = threading.Event()
DAEMON_NAME = 'judge-evaluator'


def re_evaluator(once=False, sleep_time=30, did_limit=100):
    """
    Main loop to check the re-evaluation of dids.
    """

    paused_dids = {}  # {(scope, name): datetime}
    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable=DAEMON_NAME,
        partition_wait_time=1,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            did_limit=did_limit,
            paused_dids=paused_dids,
        )
    )


def run_once(paused_dids, did_limit, heartbeat_handler, **_kwargs):
    worker_number, total_workers, logger = heartbeat_handler.live()

    # heartbeat
    start = time.time()  # NOQA

    # Refresh paused dids
    iter_paused_dids = copy.copy(paused_dids)
    for key in iter_paused_dids:
        if datetime.utcnow() > paused_dids[key]:
            del paused_dids[key]

    # Select a bunch of dids for re evaluation for this worker
    dids = get_updated_dids(total_workers=total_workers,
                            worker_number=worker_number,
                            limit=did_limit,
                            blocked_dids=[(InternalScope(key[0], fromExternal=False), key[1]) for key in paused_dids])
    logger(logging.DEBUG, 'index query time %f fetch size is %d (%d blocked)', time.time() - start, len(dids),
           len([(InternalScope(key[0], fromExternal=False), key[1]) for key in paused_dids]))

    # If the list is empty, sent the worker to sleep
    if not dids:
        logger(logging.DEBUG, 'did not get any work (paused_dids=%s)', str(len(paused_dids)))
        return

    done_dids = {}
    for did in dids:
        _, _, logger = heartbeat_handler.live()
        if graceful_stop.is_set():
            break

        # Check if this did has already been operated on
        did_tag = '%s:%s' % (did.scope.internal, did.name)
        if did_tag in done_dids:
            if did.rule_evaluation_action in done_dids[did_tag]:
                logger(logging.DEBUG, 'evaluation of %s:%s already done', did.scope, did.name)
                delete_updated_did(id_=did.id)
                continue
        else:
            done_dids[did_tag] = []

        # Jump paused dids
        if (did.scope.internal, did.name) in paused_dids:
            continue

        try:
            start_time = time.time()
            re_evaluate_did(scope=did.scope, name=did.name, rule_evaluation_action=did.rule_evaluation_action)
            logger(logging.DEBUG, 'evaluation of %s:%s took %f', did.scope, did.name, time.time() - start_time)
            delete_updated_did(id_=did.id)
            done_dids[did_tag].append(did.rule_evaluation_action)
        except DataIdentifierNotFound:
            delete_updated_did(id_=did.id)
        except (DatabaseException, DatabaseError) as e:
            if match(ORACLE_UNIQUE_CONSTRAINT_VIOLATED_REGEX, str(e.args[0])) or match(ORACLE_RESOURCE_BUSY_REGEX, str(e.args[0])):
                paused_dids[(did.scope.internal, did.name)] = datetime.utcnow() + timedelta(seconds=randint(60, 600))
                logger(logging.WARNING, 'Locks detected for %s:%s', did.scope, did.name)
                METRICS.counter('exceptions.{exception}').labels(exception='LocksDetected').inc()
            elif match('.*QueuePool.*', str(e.args[0])):
                logger(logging.WARNING, traceback.format_exc())
                METRICS.counter('exceptions.{exception}').labels(exception=e.__class__.__name__).inc()
            elif match(ORACLE_CONNECTION_LOST_CONTACT_REGEX, str(e.args[0])):
                logger(logging.WARNING, traceback.format_exc())
                METRICS.counter('exceptions.{exception}').labels(exception=e.__class__.__name__).inc()
            else:
                logger(logging.ERROR, traceback.format_exc())
                METRICS.counter('exceptions.{exception}').labels(exception=e.__class__.__name__).inc()
        except ReplicationRuleCreationTemporaryFailed as e:
            METRICS.counter('exceptions.{exception}').labels(exception=e.__class__.__name__).inc()
            logger(logging.WARNING, 'Replica Creation temporary failed, retrying later for %s:%s', did.scope, did.name)
        except FlushError as e:
            METRICS.counter('exceptions.{exception}').labels(exception=e.__class__.__name__).inc()
            logger(logging.WARNING, 'Flush error for %s:%s', did.scope, did.name)


def stop(signum: "Optional[int]" = None, frame: "Optional[FrameType]" = None) -> None:
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, threads=1, sleep_time=30, did_limit=100):
    """
    Starts up the Judge-Eval threads.
    """
    setup_logging(process_name=DAEMON_NAME)

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    if once:
        re_evaluator(once=once, did_limit=did_limit)
    else:
        logging.info('Evaluator starting %s threads' % str(threads))
        threads = [threading.Thread(target=re_evaluator, kwargs={'once': once,
                                                                 'sleep_time': sleep_time,
                                                                 'did_limit': did_limit}) for i in range(0, threads)]
        [t.start() for t in threads]
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
