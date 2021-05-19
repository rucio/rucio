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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018-2021
# - Martin Barisits <martin.barisits@cern.ch>, 2018-2021
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020-2021
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Dimitrios Christidis <dimitrios.christidis@cern.ch>, 2021

from __future__ import division

import logging
import math
import os
import socket
import threading
import time
from datetime import datetime

import rucio.db.sqla.util
from rucio.common.exception import UnsupportedOperation, DataIdentifierNotFound, ReplicaNotFound, DatabaseException
from rucio.common.logging import formatted_logger, setup_logging
from rucio.common.utils import chunks
from rucio.core import heartbeat
from rucio.core.did import get_metadata
from rucio.core.replica import (get_bad_pfns, get_pfn_to_rse, declare_bad_file_replicas,
                                get_did_from_pfns, update_replicas_states, bulk_add_bad_replicas,
                                bulk_delete_bad_pfns, get_replicas_state)
from rucio.core.rse import get_rse_name
from rucio.db.sqla.constants import BadFilesStatus, BadPFNStatus, ReplicaState
from rucio.db.sqla.session import get_session

GRACEFUL_STOP = threading.Event()


def minos(bulk=1000, once=False, sleep_time=60):
    """
    Creates a Minos Worker that gets a list of bad PFNs,
    extract the scope, name and rse_id and fill the bad_replicas table.

    :param bulk: The number of requests to process.
    :param once: Run only once.
    :param sleep_time: Time between two cycles.
    """

    executable = 'minos'
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prefix = 'minos[%i/%i] ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
    logger = formatted_logger(logging.log, prefix + '%s')
    logger(logging.INFO, 'Minos starting')

    time.sleep(10)  # To prevent running on the same partition if all the daemons restart at the same time
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prefix = 'minos[%i/%i] ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
    logger = formatted_logger(logging.log, prefix + '%s')

    states_mapping = {BadPFNStatus.BAD: BadFilesStatus.BAD,
                      BadPFNStatus.SUSPICIOUS: BadFilesStatus.SUSPICIOUS,
                      BadPFNStatus.TEMPORARY_UNAVAILABLE: BadFilesStatus.TEMPORARY_UNAVAILABLE}
    logger(logging.INFO, 'Minos started')

    chunk_size = 10  # The chunk size used for the commits

    while not GRACEFUL_STOP.is_set():
        start_time = time.time()
        heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
        prefix = 'minos[%i/%i] ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
        logger = formatted_logger(logging.log, prefix + '%s')
        pfns = []
        try:
            bad_replicas = {}
            temporary_unvailables = {}
            pfns = get_bad_pfns(thread=heart_beat['assign_thread'], total_threads=heart_beat['nr_threads'], limit=bulk)

            # Class the PFNs into bad_replicas and temporary_unavailable
            for pfn in pfns:
                path = pfn['pfn']
                account = pfn['account']
                reason = pfn['reason']
                expires_at = pfn['expires_at']
                state = states_mapping[pfn['state']]
                if state in [BadFilesStatus.BAD, BadFilesStatus.SUSPICIOUS]:
                    if (account, reason, state) not in bad_replicas:
                        bad_replicas[(account, reason, state)] = []
                    bad_replicas[(account, reason, state)].append(path)
                elif state == BadFilesStatus.TEMPORARY_UNAVAILABLE:
                    if (account, reason, expires_at) not in temporary_unvailables:
                        temporary_unvailables[(account, reason, expires_at)] = []
                    temporary_unvailables[(account, reason, expires_at)].append(path)

            # Process the bad and suspicious files
            # The scope, name, rse_id are extracted and filled into the bad_replicas table
            for account, reason, state in bad_replicas:
                vo = account.vo
                pfns = bad_replicas[(account, reason, state)]
                logger(logging.INFO, 'Declaring %s replicas with state %s and reason %s' % (len(pfns), str(state), reason))
                session = get_session()
                schemes = {}
                dict_rse = {}
                unknown_replicas = []
                try:
                    # Splitting the PFNs by schemes
                    for pfn in pfns:
                        scheme = pfn.split(':')[0]
                        if scheme not in schemes:
                            schemes[scheme] = []
                        schemes[scheme].append(pfn)
                    for scheme in schemes:
                        _, tmp_dict_rse, tmp_unknown_replicas = get_pfn_to_rse(schemes[scheme], vo=vo)
                        for rse_id in tmp_dict_rse:
                            if rse_id not in dict_rse:
                                dict_rse[rse_id] = []
                            dict_rse[rse_id].extend(tmp_dict_rse[rse_id])
                        unknown_replicas.extend(tmp_unknown_replicas.get('unknown', []))
                    # The replicas in unknown_replicas do not exist, so we flush them from bad_pfns
                    if unknown_replicas:
                        logger(logging.INFO, 'The following replicas are unknown and will be removed : %s' % str(unknown_replicas))
                        bulk_delete_bad_pfns(pfns=unknown_replicas, session=None)

                    for rse_id in dict_rse:
                        vo_str = '' if vo == 'def' else ' on VO ' + vo
                        logger(logging.DEBUG, 'Running on RSE %s%s with %s replicas' % (get_rse_name(rse_id=rse_id), vo_str, len(dict_rse[rse_id])))
                        nchunk = 0
                        tot_chunk = int(math.ceil(len(dict_rse[rse_id]) / chunk_size))
                        for chunk in chunks(dict_rse[rse_id], chunk_size):
                            nchunk += 1
                            logger(logging.DEBUG, 'Running on %s chunk out of %s' % (nchunk, tot_chunk))
                            unknown_replicas = declare_bad_file_replicas(pfns=chunk, reason=reason, issuer=account, status=state, session=session)
                            if unknown_replicas:
                                logger(logging.DEBUG, 'Unknown replicas : %s' % (str(unknown_replicas)))
                            bulk_delete_bad_pfns(pfns=chunk, session=session)
                            session.commit()  # pylint: disable=no-member
                except Exception:
                    session.rollback()  # pylint: disable=no-member
                    logger(logging.CRITICAL, 'Exception', exc_info=True)

            # Now get the temporary unavailable and update the replicas states
            for account, reason, expires_at in temporary_unvailables:
                vo = account.vo
                pfns = temporary_unvailables[(account, reason, expires_at)]
                logger(logging.INFO, 'Declaring %s replicas temporary available with timeout %s and reason %s' % (len(pfns), str(expires_at), reason))
                logger(logging.DEBUG, 'Extracting RSEs')
                schemes = {}
                dict_rse = {}
                unknown_replicas = []

                # Splitting the PFNs by schemes
                for pfn in pfns:
                    scheme = pfn.split(':')[0]
                    if scheme not in schemes:
                        schemes[scheme] = []
                    schemes[scheme].append(pfn)
                for scheme in schemes:
                    _, tmp_dict_rse, tmp_unknown_replicas = get_pfn_to_rse(schemes[scheme], vo=vo)
                    for rse_id in tmp_dict_rse:
                        if rse_id not in dict_rse:
                            dict_rse[rse_id] = []
                        dict_rse[rse_id].extend(tmp_dict_rse[rse_id])
                        unknown_replicas.extend(tmp_unknown_replicas.get('unknown', []))

                # The replicas in unknown_replicas do not exist, so we flush them from bad_pfns
                if unknown_replicas:
                    logger(logging.INFO, 'The following replicas are unknown and will be removed : %s' % str(unknown_replicas))
                    bulk_delete_bad_pfns(pfns=unknown_replicas, session=None)

                for rse_id in dict_rse:
                    replicas = []
                    rse = get_rse_name(rse_id=rse_id, session=None)
                    rse_vo_str = rse if vo == 'def' else '{} on {}'.format(rse, vo)
                    logger(logging.DEBUG, 'Running on RSE %s' % rse_vo_str)
                    for rep in get_did_from_pfns(pfns=dict_rse[rse_id], rse_id=None, vo=vo, session=None):
                        for pfn in rep:
                            scope = rep[pfn]['scope']
                            name = rep[pfn]['name']
                            replicas.append({'scope': scope, 'name': name, 'rse_id': rse_id, 'state': ReplicaState.TEMPORARY_UNAVAILABLE, 'pfn': pfn})
                    # The following part needs to be atomic
                    # We update the replicas states to TEMPORARY_UNAVAILABLE
                    # then insert a row in the bad_replicas table. TODO Update the row if it already exists
                    # then delete the corresponding rows into the bad_pfns table
                    logger(logging.DEBUG, 'Running on %s replicas on RSE %s' % (len(replicas), rse_vo_str))
                    nchunk = 0
                    tot_chunk = int(math.ceil(len(replicas) / float(chunk_size)))
                    session = get_session()
                    for chunk in chunks(replicas, chunk_size):
                        try:
                            nchunk += 1
                            logger(logging.DEBUG, 'Running on %s chunk out of %s' % (nchunk, tot_chunk))
                            update_replicas_states(chunk, nowait=False, session=session)
                            bulk_add_bad_replicas(chunk, account, state=BadFilesStatus.TEMPORARY_UNAVAILABLE, reason=reason, expires_at=expires_at, session=session)
                            pfns = [entry['pfn'] for entry in chunk]
                            bulk_delete_bad_pfns(pfns=pfns, session=session)
                            session.commit()  # pylint: disable=no-member
                        except (UnsupportedOperation, ReplicaNotFound) as error:
                            session.rollback()  # pylint: disable=no-member
                            logger(logging.ERROR, 'Problem to bulk update PFNs. PFNs will be updated individually. Error : %s' % str(error))
                            for rep in chunk:
                                logger(logging.DEBUG, 'Working on %s' % (str(rep)))
                                try:
                                    get_metadata(rep['scope'], rep['name'])
                                    unavailable_states = []
                                    rep_state = get_replicas_state(rep['scope'], rep['name'])
                                    unavailable_states.extend(rep_state.get(ReplicaState.TEMPORARY_UNAVAILABLE, []))
                                    unavailable_states.extend(rep_state.get(ReplicaState.BEING_DELETED, []))
                                    unavailable_states.extend(rep_state.get(ReplicaState.BAD, []))
                                    # If the replica is already not available, it is removed from the bad PFNs table
                                    if rep['rse_id'] in unavailable_states:
                                        logger(logging.INFO, '%s is in unavailable state. Will be removed from the list of bad PFNs' % str(rep['pfn']))
                                        bulk_delete_bad_pfns(pfns=[rep['pfn']], session=None)
                                    # If the expiration date of the TEMPORARY_UNAVAILABLE is in the past, it is removed from the bad PFNs table
                                    elif expires_at < datetime.now():
                                        logger(logging.INFO, 'PFN %s expiration time (%s) is older than now and is not in unavailable state. Removing the PFNs from bad_pfns' % (str(rep['pfn']), expires_at))
                                        bulk_delete_bad_pfns(pfns=[rep['pfn']], session=None)
                                    # Else update everything in the same transaction
                                    else:
                                        try:
                                            session = get_session()
                                            update_replicas_states([rep], nowait=False, session=session)
                                            bulk_add_bad_replicas([rep], account, state=BadFilesStatus.TEMPORARY_UNAVAILABLE, reason=reason, expires_at=expires_at, session=session)
                                            bulk_delete_bad_pfns(pfns=[rep['pfn']], session=session)
                                            session.commit()  # pylint: disable=no-member
                                        except Exception:
                                            logger(logging.ERROR, 'Cannot update state of %s' % str(rep['pfn']))
                                except (DataIdentifierNotFound, ReplicaNotFound):
                                    logger(logging.ERROR, 'Will remove %s from the list of bad PFNs' % str(rep['pfn']))
                                    bulk_delete_bad_pfns(pfns=[rep['pfn']], session=None)
                            session = get_session()
                        except Exception:
                            session.rollback()  # pylint: disable=no-member
                            logger(logging.CRITICAL, 'Exception', exc_info=True)
                            session = get_session()

        except Exception as error:
            logger(logging.ERROR, '%s' % (str(error)))

        tottime = time.time() - start_time
        if once:
            break
        if len(pfns) == bulk:
            logger(logging.INFO, 'Processed maximum number of pfns according to the bulk size. Restart immediately next cycle')
        elif tottime < sleep_time:
            logger(logging.INFO, 'Will sleep for %s seconds' % (sleep_time - tottime))
            time.sleep(sleep_time - tottime)

    heartbeat.die(executable, hostname, pid, hb_thread)
    logger(logging.INFO, 'Graceful stop requested')
    logger(logging.INFO, 'Graceful stop done')


def run(threads=1, bulk=100, once=False, sleep_time=60):
    """
    Starts up the minos threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    if once:
        logging.info('Will run only one iteration in a single threaded mode')
        minos(bulk=bulk, once=once)
    else:
        logging.info('starting transmogrifier threads')
        thread_list = [threading.Thread(target=minos, kwargs={'once': once,
                                                              'sleep_time': sleep_time,
                                                              'bulk': bulk}) for _ in range(0, threads)]
        [thread.start() for thread in thread_list]
        logging.info('waiting for interrupts')
        # Interruptible joins require a timeout.
        while thread_list:
            thread_list = [thread.join(timeout=3.14) for thread in thread_list if thread and thread.is_alive()]


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()
