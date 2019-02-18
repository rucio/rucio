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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018-2019
#
# PY3K COMPATIBLE

import logging
import os
import socket
import traceback
import threading
import time

from sys import stdout, argv

from rucio.db.sqla.constants import BadFilesStatus, BadPFNStatus, ReplicaState

from rucio.db.sqla.session import get_session
from rucio.common.config import config_get
from rucio.common.utils import chunks
from rucio.core.replica import (get_bad_pfns, get_pfn_to_rse, declare_bad_file_replicas,
                                get_did_from_pfns, update_replicas_states, bulk_add_bad_replicas,
                                bulk_delete_bad_pfns)
from rucio.core.rse import get_rse_id

from rucio.core import heartbeat


logging.basicConfig(stream=stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


graceful_stop = threading.Event()


def minos(bulk=1000, once=False, sleep_time=60):
    """
    Creates a Minos Worker that gets a list of bad PFNs,
    extract the scope, name and rse_id and fill the bad_replicas table.

    :param bulk: The number of requests to process.
    :param once: Run only once.
    :param sleep_time: Time between two cycles.
    """

    executable = ' '.join(argv)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'] + 1, heart_beat['nr_threads'])
    logging.info(prepend_str + 'Minos starting')

    time.sleep(10)  # To prevent running on the same partition if all the daemons restart at the same time
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'] + 1, heart_beat['nr_threads'])

    states_mapping = {BadPFNStatus.BAD: BadFilesStatus.BAD,
                      BadPFNStatus.SUSPICIOUS: BadFilesStatus.SUSPICIOUS,
                      BadPFNStatus.TEMPORARY_UNAVAILABLE: BadFilesStatus.TEMPORARY_UNAVAILABLE}
    logging.info(prepend_str + 'Minos started')

    chunk_size = 500  # The chunk size used for the commits

    while not graceful_stop.is_set():
        start_time = time.time()
        heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
        prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'] + 1, heart_beat['nr_threads'])
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
                state = pfn['state']
                if states_mapping[state] in [BadFilesStatus.BAD, BadFilesStatus.SUSPICIOUS]:
                    if (account, reason, state) not in bad_replicas:
                        bad_replicas[(account, reason, state)] = []
                    bad_replicas[(account, reason, state)].append(path)
                if states_mapping[state] == BadFilesStatus.TEMPORARY_UNAVAILABLE:
                    if (account, reason, expires_at) not in temporary_unvailables:
                        temporary_unvailables[(account, reason, expires_at)] = []
                    temporary_unvailables[(account, reason, expires_at)].append(path)

            # Process the bad and suspicious files
            # The scope, name, rse_id are extracted and filled into the bad_replicas table
            for account, reason, state in bad_replicas:
                pfns = bad_replicas[(account, reason, state)]
                logging.info(prepend_str + 'Declaring %s replicas with state %s and reason %s' % (len(pfns), str(state), reason))
                logging.debug(prepend_str + 'List of replicas : %s' % (str(pfns)))
                session = get_session()
                try:
                    for chunk in chunks(pfns, chunk_size):
                        unknown_replicas = declare_bad_file_replicas(pfns=chunk, reason=reason, issuer=account, status=state, session=session)
                        logging.debug(prepend_str + 'Unknown replicas : %s' % (str(unknown_replicas)))
                        bulk_delete_bad_pfns(pfns=chunk, session=session)
                        session.commit()  # pylint: disable=no-member
                except Exception:
                    session.rollback()  # pylint: disable=no-member
                    logging.critical(traceback.format_exc())

            # Now get the temporary unavailable and update the replicas states
            for account, reason, expires_at in temporary_unvailables:
                pfns = temporary_unvailables[(account, reason, expires_at)]
                logging.info(prepend_str + 'Declaring %s replicas temporary available with timeout %s and reason %s' % (len(pfns), str(expires_at), reason))
                logging.debug(prepend_str + 'List of replicas : %s' % (str(pfns)))
                logging.debug(prepend_str + 'Extracting RSEs')
                _, dict_rse, unknown_replicas = get_pfn_to_rse(pfns)
                # The replicas in unknown_replicas do not exist, so we flush them from bad_pfns
                if unknown_replicas:
                    logging.info(prepend_str + 'The following replicas are unknown and will be removed : %s' % str(unknown_replicas))
                    bulk_delete_bad_pfns(pfns=unknown_replicas, session=None)

                for rse in dict_rse:
                    replicas = []
                    rse_id = get_rse_id(rse=rse, session=None)
                    logging.debug(prepend_str + 'Running on RSE %s' % rse)
                    for rep in get_did_from_pfns(pfns=dict_rse[rse], rse=None, session=None):
                        for pfn in rep:
                            scope = rep[pfn]['scope']
                            name = rep[pfn]['name']
                            replicas.append({'scope': scope, 'name': name, 'rse_id': rse_id, 'state': ReplicaState.TEMPORARY_UNAVAILABLE, 'pfn': pfn})
                    # The following part needs to be atomic
                    # We update the replicas states to TEMPORARY_UNAVAILABLE
                    # then insert a row in the bad_replicas table. TODO Update the row if it already exists
                    # then delete the corresponding rows into the bad_pfns table
                    session = get_session()
                    try:
                        for chunk in chunks(replicas, chunk_size):
                            update_replicas_states(chunk, nowait=False, session=session)
                            bulk_add_bad_replicas(chunk, account, state=BadFilesStatus.TEMPORARY_UNAVAILABLE, reason=None, expires_at=expires_at, session=session)
                            pfns = [entry['pfn'] for entry in chunk]
                            bulk_delete_bad_pfns(pfns=pfns, session=session)
                            session.commit()  # pylint: disable=no-member
                    except Exception:
                        session.rollback()  # pylint: disable=no-member
                        logging.critical(traceback.format_exc())

        except Exception as error:
            logging.error(prepend_str + '%s' % (str(error)))

        tottime = time.time() - start_time
        if once:
            break
        if len(pfns) == bulk:
            logging.info(prepend_str + 'Processed maximum number of pfns according to the bulk size. Restart immediately next cycle')
        elif tottime < sleep_time:
            logging.info(prepend_str + 'Will sleep for %s seconds' % (sleep_time - tottime))
            time.sleep(sleep_time - tottime)

    heartbeat.die(executable, hostname, pid, hb_thread)
    logging.info(prepend_str + 'Graceful stop requested')
    logging.info(prepend_str + 'Graceful stop done')


def run(threads=1, bulk=100, once=False, sleep_time=60):
    """
    Starts up the minos threads.
    """

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
            thread_list = [thread.join(timeout=3.14) for thread in thread_list if thread and thread.isAlive()]


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()
