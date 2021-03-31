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
# - Christoph Ames <christoph.ames@cern.ch>, 2021

"""
Suspicious-Replica-Recoverer is a daemon that deals with suspicious replicas based on if they are found available on other RSEs
or if they are the last remaining copy, on how many suspicious replicas are on a given RSE and on a replica's metadata.
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

import json

from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common.config import config_get_bool
from rucio.common.exception import DatabaseException, VONotFound
from rucio.common.logging import setup_logging
from rucio.common.types import InternalAccount
from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.monitor import record_counter
from rucio.core.did import get_metadata
from rucio.core.replica import list_replicas, get_suspicious_files, add_bad_pfns

from rucio.core.rse import list_rses
from rucio.core.vo import list_vos
from rucio.db.sqla.util import get_db_time

GRACEFUL_STOP = threading.Event()


logging.basicConfig(filename='suspicious_replica_recoverer.log', filemode='w', level=logging.DEBUG)


def declare_suspicious_replicas_bad(once=False, younger_than=3, nattempts=10, vos=None, limit_suspicious_files_on_rse=5):
    """
    Main loop to check for available replicas which are labeled as suspicious.

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
    :param limit_suspicious_files_on_rse: Maximum number of suspicious replicas on an RSE before that RSE
                                          is considered problematic and the suspicious replicas on that RSE
                                          are labeled as 'TEMPORARY_UNAVAILABLE'.
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
            worker_number = heartbeat['assign_thread'] + 1

            # there is only 1 worker allowed for this daemon
            if total_workers != 1:
                logging.error('replica_recoverer: Another running instance on %s has been detected. Stopping gracefully.', socket.gethostname())
                die(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
                break

            start = time.time()

            logging.info('replica_recoverer[%i/%i]: Ready to query replicas which were'
                         + ' reported as suspicious in the last %i days at least %i times.',
                         worker_number, total_workers, younger_than, nattempts)

            getfileskwargs_avail_elsewhere = {'younger_than': younger_than,
                                              'nattempts': nattempts,
                                              'exclude_states': ['B', 'R', 'D', 'L', 'T'],
                                              'available_elsewhere': 1,
                                              'is_suspicious': True}

            getfileskwargs_last_copy = {'younger_than': younger_than,
                                              'nattempts': nattempts,
                                              'exclude_states': ['B', 'R', 'D', 'L', 'T'],
                                              'available_elsewhere': 2,
                                              'is_suspicious': True}

            for vo in vos:
                logging.info('replica_recoverer[%i/%i]: Start replica recovery for VO: %s', worker_number, total_workers, vo)
                recoverable_replicas = {}
                if vo not in recoverable_replicas:
                    recoverable_replicas[vo] = {}
                rse_list = list_rses()
                logging.debug("List of RSEs:")
                for i in rse_list:
                    logging.debug(i)
                # Remove RSEs from the list that have been labeled as deleted or where the RSE expression does not end with "DATADISK" or "SCRATCHDISK"
                rse_list[:] = [rse for rse in rse_list if ((rse['deleted'] is False) and (rse['rse'].split("_")[-1] in {"DATADISK", "SCRATCHDISK"}))]

                for rse in rse_list:
                    time_start_rse = time.time()
                    rse_expr = rse['rse']
                    cnt_surl_not_found = 0
                    if rse_expr not in recoverable_replicas[vo]:
                        recoverable_replicas[vo][rse_expr] = {}
                    # Get a dictionary of the suspicious replicas on the RSE that have available copies on other RSEs
                    suspicious_replicas_avail_elsewhere = get_suspicious_files(rse_expr, filter={'vo': vo}, **getfileskwargs_avail_elsewhere)
                    # Get the suspicious replicas that are the last remaining copies
                    suspicious_replicas_last_copy = get_suspicious_files(rse_expr, filter={'vo': vo}, **getfileskwargs_last_copy)
                    logging.debug('\n')
                    logging.debug('Suspicious replicas on %s:', rse_expr)
                    logging.debug('Replicas with copies on other RSEs (%i):', len(suspicious_replicas_avail_elsewhere))
                    for i in suspicious_replicas_avail_elsewhere:
                        logging.debug(i)
                    logging.debug('Replicas that are the last remaining copy (%i):', len(suspicious_replicas_last_copy))
                    for i in suspicious_replicas_last_copy:
                        logging.debug(i)
                    logging.debug('')

                    # RSEs that aren't available shouldn't have suspicious replicas showing up. Skip to next RSE.
                    if (rse['availability'] not in {4, 5, 6, 7}) and ((len(suspicious_replicas_avail_elsewhere) > 0) or (len(suspicious_replicas_last_copy) > 0)):
                        logging.warning("replica_recoverer[%i/%i]: %s is not available (availability: %i), yet is has suspicious replicas. Please investigate. \n", worker_number, total_workers, rse_expr, rse['availability'])
                        continue

                    if suspicious_replicas_avail_elsewhere:
                        for replica in suspicious_replicas_avail_elsewhere:
                            if vo == replica['scope'].vo:
                                scope = replica['scope']
                                rep_name = replica['name']
                                rse_id = replica['rse_id']
                                surl_not_found = True
                                for rep in list_replicas([{'scope': scope, 'name': rep_name}]):
                                    for rse_ in rep['rses']:
                                        if rse_ == rse_id:
                                            recoverable_replicas[vo][rse_expr][rep_name] = {'name': rep_name, 'rse_id': rse_id, 'scope': scope, 'surl': rep['rses'][rse_][0], 'available_elsewhere': True}
                                            surl_not_found = False
                                if surl_not_found:
                                    cnt_surl_not_found += 1
                                    logging.warning('replica_recoverer[%i/%i]: Skipping suspicious replica %s on %s, no surls were found.', worker_number, total_workers, rep_name, rse_expr)

                    if suspicious_replicas_last_copy:
                        for replica in suspicious_replicas_last_copy:
                            if vo == replica['scope'].vo:
                                scope = replica['scope']
                                rep_name = replica['name']
                                rse_id = replica['rse_id']
                                surl_not_found = True
                                for rep in list_replicas([{'scope': scope, 'name': rep_name}]):
                                    for rse_ in rep['rses']:
                                        if rse_ == rse_id:
                                            recoverable_replicas[vo][rse_expr][rep_name] = {'name': rep_name, 'rse_id': rse_id, 'scope': scope, 'surl': rep['rses'][rse_][0], 'available_elsewhere': False}
                                            surl_not_found = False
                                if surl_not_found:
                                    cnt_surl_not_found += 1
                                    logging.warning('replica_recoverer[%i/%i]: Skipping suspicious replica %s on %s, no surls were found.', worker_number, total_workers, rep_name, rse_expr)

                    logging.info('replica_recoverer[%i/%i]: Suspicious replica query took %.2f seconds on %s and found %i suspicious replicas. The pfns for %i/%i replicas were found.',
                                    worker_number, total_workers,  time.time() - time_start_rse, rse_expr, len(suspicious_replicas_avail_elsewhere) + len(suspicious_replicas_last_copy), len(suspicious_replicas_avail_elsewhere) + len(suspicious_replicas_last_copy) - cnt_surl_not_found, len(suspicious_replicas_avail_elsewhere) + len(suspicious_replicas_last_copy))

                    if len(suspicious_replicas_avail_elsewhere) + len(suspicious_replicas_last_copy) != 0:
                        logging.debug('List of replicas on %s for which the pfns have been found:', rse_expr)
                        for i in recoverable_replicas[vo][rse_expr]:
                            logging.debug(i)

                logging.info('\n\n\n\n\n\n\n\n')
                logging.info('replica_recoverer[%i/%i]: All RSEs have been checked for suspicious replicas. Total time: %.2f seconds.', worker_number, total_workers, time.time() - start)
                logging.info('replica_recoverer[%i/%i]: Begin check for problematic RSEs.\n\n\n', worker_number, total_workers)
                time_start_check_probl = time.time()

                # If an RSE has more than *limit_suspicious_files_on_rse* suspicious files, then there might be a problem with the RSE.
                # The suspicious files are marked as temporarily unavailable.
                list_problematic_rses = []
                for rse_key in list(recoverable_replicas[vo].keys()):
                    if len(recoverable_replicas[vo][rse_key].values()) > limit_suspicious_files_on_rse:
                        list_problematic_rses.append(rse_key)
                        surls_list = []
                        for replica_value in recoverable_replicas[vo][rse_key].values():
                            surls_list.append(replica_value['surl'])

                        add_bad_pfns(pfns=surls_list, account=InternalAccount('root', vo=vo), state=TEMPORARY_UNAVAILABLE)

                        logging.info('')
                        logging.info("replica_recoverer[%i/%i]: %s is problematic (more than %i suspicious replicas). Send a Jira ticket for the RSE (to be implemented).", worker_number, total_workers, rse_key, limit_suspicious_files_on_rse)
                        logging.info("replica_recoverer[%i/%i]: The following files on %s have been marked as TEMPORARILY UNAVAILABLE:", worker_number, total_workers, rse_key)
                        for rse_values in recoverable_replicas[vo][rse_key].values():
                            logging.info('replica_recoverer[%i/%i]: Scope: %s    Name: %s', worker_number, total_workers, rse_values['scope'], rse_values['name'])
                        # Remove the RSE from the dictionary as it has been dealt with.
                        del recoverable_replicas[vo][rse_key]

                logging.info("\n\n")
                logging.info("replica_recoverer[%i/%i]: Following RSEs were deemed problematic (total: %i)", worker_number, total_workers, len(list_problematic_rses))
                for rse in list_problematic_rses:
                    logging.info("replica_recoverer[%i/%i]: %s", worker_number, total_workers, rse)

                json_file = open("suspicious_replica_recoverer.json")
                json_data = json.load(json_file)

                # Label suspicious replicas as bad if they have oher copies on other RSEs (that aren't also marked as suspicious).
                # If they are the last remaining copies, deal with them differently.
                for rse_key in list(recoverable_replicas[vo].keys()):
                    files_to_be_declared_bad = []
                    files_to_be_ignored = []
                    # Remove RSEs from dictionary that don't have any suspicious replicas
                    if len(recoverable_replicas[vo][rse_key]) == 0:
                        del recoverable_replicas[vo][rse_key]
                        continue
                    # Get the rse_id by going to one of the suspicious replicas from that RSE and reading it from there
                    rse_id = list(recoverable_replicas[vo][rse_key].values())[0]['rse_id']
                    for replica_key in list(recoverable_replicas[vo][rse_key].keys()):
                        if recoverable_replicas[vo][rse_key][replica_key]['available_elsewhere'] == True:
                            # Replicas with other copies on at least one other RSE can safely be labeled as bad
                            files_to_be_declared_bad.append(recoverable_replicas[vo][rse_key][replica_key]['surl'])
                            # Remove replica from dictionary
                            del recoverable_replicas[vo][rse_key][replica_key]
                        elif recoverable_replicas[vo][rse_key][replica_key]['available_elsewhere'] == False:
                            if (recoverable_replicas[vo][rse_key][replica_key]['name'].startswith("log.")) or (recoverable_replicas[vo][rse_key][replica_key]['name'].startswith("user")):
                                # Don't keep log files or user files
                                files_to_be_declared_bad.append(recoverable_replicas[vo][rse_key][replica_key]['surl'])
                                del recoverable_replicas[vo][rse_key][replica_key]
                            else:
                                # Deal with replicas based on their metadata.
                                file_metadata = get_metadata(recoverable_replicas[vo][rse_key][replica_key]["scope"], recoverable_replicas[vo][rse_key][replica_key]["name"])
                                if file_metadata["datatype"] == None: # "None" type has no function "split()"
                                    files_to_be_ignored.append(recoverable_replicas[vo][rse_key][replica_key]['surl'])
                                    continue
                                for i in json_data:
                                    if i["datatype"] == file_metadata["datatype"].split("_")[-1]:
                                        action = i["action"]
                                        if action == "ignore":
                                            files_to_be_ignored.append(recoverable_replicas[vo][rse_key][replica_key]['surl'])
                                        elif action == "declare bad":
                                            files_to_be_declared_bad.append(recoverable_replicas[vo][rse_key][replica_key]['surl'])
                                        break

                    logging.debug('\n')
                    logging.debug('(%s) Remaining replicas (pfns) that will be ignored:', rse_key)
                    for i in files_to_be_ignored:
                        logging.debug(i)
                    logging.debug('(%s) Remaining replica (pfns) that will be marked BAD:', rse_key)
                    for i in files_to_be_declared_bad:
                        logging.debug(i)
                    logging.info('replica_recoverer[%i/%i]: Ready to declare %i bad replica(s) on %s (RSE id: %s).',
                                 worker_number, total_workers, len(files_to_be_declared_bad), rse_key, str(rse_id))

                    declare_bad_file_replicas(pfns=files_to_be_declared_bad, reason='Suspicious. Automatic recovery.', issuer=InternalAccount('root', vo=vo), status=BadFilesStatus.BAD, session=None)

                    logging.info('replica_recoverer[%i/%i]: Finished declaring bad replicas on %s.\n', worker_number, total_workers, rse_key)

                logging.info('replica_recoverer[%i/%i]: Finished checking for problematic RSEs and declaring bad replicas. Total time: %.2f seconds.', worker_number, total_workers, time.time() - time_start_check_probl)
                logging.info('replica_recoverer[%i/%i]: Total time: %.2f seconds', worker_number, total_workers, time.time() - start)
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
    logging.info('replica_recoverer[%i/%i]: Graceful stop done.', worker_number, total_workers)




def run(once=False, younger_than=3, nattempts=10, vos=None, limit_suspicious_files_on_rse=5):
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
        declare_suspicious_replicas_bad(once, younger_than, nattempts, vos, limit_suspicious_files_on_rse)
    else:
        logging.info('Suspicious file replicas recovery starting 1 worker.')
        t = threading.Thread(target=declare_suspicious_replicas_bad,
                             kwargs={'once': once,
                                     'younger_than': younger_than,
                                     'nattempts': nattempts,
                                     'vos': vos,
                                     'limit_suspicious_files_on_rse': limit_suspicious_files_on_rse})
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

# For testing purposes, uncomment run(once=True) and run "python3 suspicous_replica_recoverer".
# run(once=True)
