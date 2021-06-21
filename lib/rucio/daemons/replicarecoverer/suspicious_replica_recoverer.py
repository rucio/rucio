# -*- coding: utf-8 -*-
# Copyright 2018-2021 CERN
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Martin Barisits <martin.barisits@cern.ch>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Thomas Beermann <thomas.beermann@cern.ch>, 2021

"""
Suspicious-Replica-Recoverer is a daemon that declares suspicious replicas as bad if they are found available on other RSE.
Consequently, automatic replica recovery is triggered via necromancer daemon, which creates a rule for such bad replica(s).
"""

from __future__ import print_function

import logging
import os
import socket
import threading
import time
import traceback
from datetime import datetime, timedelta
from re import match
from sys import argv

from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common.config import config_get_bool
from rucio.common.exception import DatabaseException, VONotFound, InvalidRSEExpression
from rucio.common.logging import setup_logging
from rucio.common.types import InternalAccount
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.monitor import record_counter
from rucio.core.replica import list_replicas, declare_bad_file_replicas, get_suspicious_files
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.vo import list_vos
from rucio.db.sqla.constants import BadFilesStatus
from rucio.db.sqla.util import get_db_time

GRACEFUL_STOP = threading.Event()


def declare_suspicious_replicas_bad(once=False, younger_than=3, nattempts=10, rse_expression='MOCK', vos=None, max_replicas_per_rse=100):

    """
    Main loop to check for available replicas which are labeled as suspicious

    Gets a list of suspicious replicas that are listed as AVAILABLE in 'replicas' table
    and available on other RSE. Finds surls of these replicas and declares them as bad.

    :param once: If True, the loop is run just once, otherwise the daemon continues looping until stopped.
    :param younger_than: The number of days since which bad_replicas table will be searched
                         for finding replicas declared 'SUSPICIOUS' at a specific RSE ('rse_expression'),
                         but 'AVAILABLE' on other RSE(s).
    :param nattempts: The minimum number of appearances in the bad_replica DB table
                      in order to appear in the resulting list of replicas for recovery.
    :param rse_expression: Search for suspicious replicas on RSEs matching the 'rse_expression'.
    :param vos: VOs on which to look for RSEs. Only used in multi-VO mode.
                If None, we either use all VOs if run from "def",
    :param max_replicas_per_rse: Maximum number of replicas which are allowed to be labeled as bad per RSE.
                                 If more is found, processing is skipped and warning is printed.
    :returns: None
    """

    # assembling the worker name identifier ('executable') including the rses from <rse_expression>
    # in order to have the possibility to detect a start of a second instance with the same set of RSES

    executable = argv[0]

    multi_vo = config_get_bool('common', 'multi_vo', raise_exception=False, default=False)
    if not multi_vo:
        if vos:
            logging.warning('Ignoring argument vos, this is only applicable in a multi-VO setup.')
        vos = ['def']
    else:
        if vos:
            invalid = set(vos) - set([v['vo'] for v in list_vos()])
            if invalid:
                msg = 'VO{} {} cannot be found'.format('s' if len(invalid) > 1 else '', ', '.join([repr(v) for v in invalid]))
                raise VONotFound(msg)
        else:
            vos = [v['vo'] for v in list_vos()]
        logging.info('replica_recoverer: This instance will work on VO%s: %s' % ('s' if len(vos) > 1 else '', ', '.join([v for v in vos])))

    # Don't require a result from the expression at each VO, only raise if we can't get a result from any of them
    rses = []
    exceptions_raised = 0
    for vo in vos:
        try:
            parsed_rses = parse_expression(expression=rse_expression, filter={'vo': vo})
        except InvalidRSEExpression:
            exceptions_raised += 1
            parsed_rses = []
        for rse in parsed_rses:
            rses.append(rse['id'])
    if exceptions_raised == len(vos):
        raise InvalidRSEExpression('RSE Expression resulted in an empty set.')

    rses.sort()
    executable += ' --rse-expression ' + str(rses)

    sanity_check(executable=executable, hostname=socket.gethostname())

    # make an initial heartbeat - expected only one replica-recoverer thread on one node
    # heartbeat mechanism is used in this daemon only for information purposes
    # (due to expected low load, the actual DB query does not filter the result based on worker number)
    live(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())

    # wait a moment in case all workers started at the same time
    GRACEFUL_STOP.wait(1)

    while not GRACEFUL_STOP.is_set():
        try:
            # issuing the heartbeat for a second time to make all workers aware of each other (there is only 1 worker allowed for this daemon)
            heartbeat = live(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
            total_workers = heartbeat['nr_threads']
            worker_number = heartbeat['assign_thread']

            # there is only 1 worker allowed for this daemon
            if total_workers != 1:
                logging.error('replica_recoverer: Another running instance on %s has been detected. Stopping gracefully.', socket.gethostname())
                die(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
                break

            start = time.time()

            logging.info('replica_recoverer[%i/%i]: ready to query replicas at RSE %s,'
                         + ' reported suspicious in the last %i days at least %i times which are available on other RSEs.',  # NOQA: W503
                         worker_number, total_workers, rse_expression, younger_than, nattempts)

            getfileskwargs = {'younger_than': younger_than,
                              'nattempts': nattempts,
                              'exclude_states': ['B', 'R', 'D', 'L', 'T'],
                              'available_elsewhere': True,
                              'is_suspicious': True}

            # Don't require a result from the expression at each VO, only raise if we can't get a result from any of them
            recoverable_replicas = []
            exceptions_raised = 0
            for vo in vos:
                try:
                    recoverable_replicas.extend(get_suspicious_files(rse_expression, filter={'vo': vo}, **getfileskwargs))
                except InvalidRSEExpression:
                    exceptions_raised += 1
            if exceptions_raised == len(vos):
                raise InvalidRSEExpression('RSE Expression resulted in an empty set.')

            logging.info('replica_recoverer[%i/%i]: suspicious replica query took %.2f seconds, total of %i replicas were found.',
                         worker_number, total_workers, time.time() - start, len(recoverable_replicas))

            if not recoverable_replicas and not once:
                logging.info('replica_recoverer[%i/%i]: found %i recoverable suspicious replicas. Sleeping for 60 seconds.', worker_number, total_workers, len(recoverable_replicas))
                GRACEFUL_STOP.wait(60)
            else:
                logging.info('replica_recoverer[%i/%i]: looking for replica surls.', worker_number, total_workers)

                start = time.time()
                surls_to_recover = {}  # dictionary of { vo1: {rse1: [surl1, surl2, ... ], rse2: ...}, vo2:... }
                cnt_surl_not_found = 0
                for replica in recoverable_replicas:
                    scope = replica['scope']
                    name = replica['name']
                    vo = scope.vo
                    rse = replica['rse']
                    rse_id = replica['rse_id']
                    if GRACEFUL_STOP.is_set():
                        break
                    if vo not in surls_to_recover:
                        surls_to_recover[vo] = {}
                    if rse_id not in surls_to_recover[vo]:
                        surls_to_recover[vo][rse_id] = []
                    # for each suspicious replica, we get its surl through the list_replicas function
                    surl_not_found = True
                    for rep in list_replicas([{'scope': scope, 'name': name}]):
                        for site in rep['rses']:
                            if site == rse_id:
                                surls_to_recover[vo][rse_id].append(rep['rses'][site][0])
                                surl_not_found = False
                    if surl_not_found:
                        cnt_surl_not_found += 1
                        logging.warning('replica_recoverer[%i/%i]: skipping suspicious replica %s on %s, no surls were found.', worker_number, total_workers, name, rse)

                logging.info('replica_recoverer[%i/%i]: found %i/%i surls (took %.2f seconds), declaring them as bad replicas now.',
                             worker_number, total_workers, len(recoverable_replicas) - cnt_surl_not_found, len(recoverable_replicas), time.time() - start)

                for vo in surls_to_recover:
                    for rse_id in surls_to_recover[vo]:
                        logging.info('replica_recoverer[%i/%i]: ready to declare %i bad replica(s) on %s: %s.',
                                     worker_number, total_workers, len(surls_to_recover[vo][rse_id]), rse, str(surls_to_recover[vo][rse_id]))
                        if len(surls_to_recover[vo][rse_id]) > max_replicas_per_rse:
                            logging.warning('replica_recoverer[%i/%i]: encountered more than %i suspicious replicas (%s) on %s. Please investigate.',
                                            worker_number, total_workers, max_replicas_per_rse, str(len(surls_to_recover[vo][rse_id])), rse)
                        else:
                            declare_bad_file_replicas(pfns=surls_to_recover[vo][rse_id], reason='Suspicious. Automatic recovery.', issuer=InternalAccount('root', vo=vo), status=BadFilesStatus.BAD, session=None)
                            logging.info('replica_recoverer[%i/%i]: finished declaring bad replicas on %s.', worker_number, total_workers, rse)

        except (DatabaseException, DatabaseError) as err:
            if match('.*QueuePool.*', str(err.args[0])):
                logging.warning(traceback.format_exc())
                record_counter('replica.recoverer.exceptions.' + err.__class__.__name__)
            elif match('.*ORA-03135.*', str(err.args[0])):
                logging.warning(traceback.format_exc())
                record_counter('replica.recoverer.exceptions.' + err.__class__.__name__)
            else:
                logging.critical(traceback.format_exc())
                record_counter('replica.recoverer.exceptions.' + err.__class__.__name__)
        except Exception as err:
            logging.critical(traceback.format_exc())
            record_counter('replica.recoverer.exceptions.' + err.__class__.__name__)
        if once:
            break

    die(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
    logging.info('replica_recoverer[%i/%i]: graceful stop done', worker_number, total_workers)


def run(once=False, younger_than=3, nattempts=10, rse_expression='MOCK', vos=None, max_replicas_per_rse=100):
    """
    Starts up the Suspicious-Replica-Recoverer threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    client_time, db_time = datetime.utcnow(), get_db_time()
    max_offset = timedelta(hours=1, seconds=10)
    if isinstance(db_time, datetime):
        if db_time - client_time > max_offset or client_time - db_time > max_offset:
            logging.critical('Offset between client and db time too big. Stopping Suspicious-Replica-Recoverer.')
            return

    sanity_check(executable='rucio-replica-recoverer', hostname=socket.gethostname())

    if once:
        declare_suspicious_replicas_bad(once, younger_than, nattempts, rse_expression, vos, max_replicas_per_rse)
    else:
        logging.info('Suspicious file replicas recovery starting 1 worker.')
        t = threading.Thread(target=declare_suspicious_replicas_bad,
                             kwargs={'once': once, 'younger_than': younger_than,
                                     'nattempts': nattempts, 'rse_expression': rse_expression,
                                     'vos': vos, 'max_replicas_per_rse': max_replicas_per_rse})
        t.start()
        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while t.is_alive():
            t.join(timeout=3.14)


def stop():
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()
