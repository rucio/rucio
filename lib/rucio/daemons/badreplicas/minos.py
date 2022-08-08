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

import functools
import logging
import math
import re
import threading
from datetime import datetime
from typing import TYPE_CHECKING
from typing import Tuple, Dict, Callable

from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common.config import config_get_int
from rucio.common.exception import UnsupportedOperation, DataIdentifierNotFound, ReplicaNotFound, DatabaseException
from rucio.common.logging import setup_logging
from rucio.common.utils import chunks
from rucio.core.did import get_metadata
from rucio.core.replica import (get_bad_pfns, get_pfn_to_rse, declare_bad_file_replicas,
                                get_did_from_pfns, update_replicas_states, bulk_add_bad_replicas,
                                bulk_delete_bad_pfns, get_replicas_state)
from rucio.core.rse import get_rse_name
from rucio.daemons.common import run_daemon
from rucio.db.sqla.constants import BadFilesStatus, BadPFNStatus, ReplicaState
from rucio.db.sqla.session import get_session


if TYPE_CHECKING:
    from rucio.daemons.common import HeartbeatHandler
    from rucio.common.types import InternalAccount

graceful_stop = threading.Event()


def __classify_bad_pfns(pfns: list) -> Tuple[Dict, Dict]:
    """
    Function that takes a list of PFNs and classify them in 2 dictionaries : bad_replicas and temporary_unvailables
    :param pfns: List of PFNs

    :returns: Tuple (bad_replicas, temporary_unvailables)
    """
    states_mapping = {BadPFNStatus.BAD: BadFilesStatus.BAD,
                      BadPFNStatus.SUSPICIOUS: BadFilesStatus.SUSPICIOUS,
                      BadPFNStatus.TEMPORARY_UNAVAILABLE: BadFilesStatus.TEMPORARY_UNAVAILABLE}
    bad_replicas, temporary_unvailables = {}, {}
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
    return bad_replicas, temporary_unvailables


def __clean_unknown_replicas(pfns: list, vo: str, logger: "Callable") -> dict:
    """
    Identify from the list of PFNs the one that are unknown and remove them from the bad_pfns table
    :param pfns: List of PFNs
    :param vo: The VO name
    :param logger: The logger

    :returns: Dictionary cleaned from unkwnon replicas
    """
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
                dict_rse[rse_id] = {}
            if scheme not in dict_rse[rse_id]:
                dict_rse[rse_id][scheme] = []
            dict_rse[rse_id][scheme].extend(tmp_dict_rse[rse_id])
        unknown_replicas.extend(tmp_unknown_replicas.get('unknown', []))
    # The replicas in unknown_replicas do not exist, so we flush them from bad_pfns
    if unknown_replicas:
        logger(logging.INFO, 'The following replicas are unknown and will be removed : %s', str(unknown_replicas))
        bulk_delete_bad_pfns(pfns=unknown_replicas, session=None)
    return dict_rse


def __update_temporary_unavailable(chunk: list, reason: str, expires_at: datetime, account: "InternalAccount", logger: "Callable") -> None:
    """
    Update temporary unavailable replicas one by one
    :param chunk: List of unvailable replicas to update
    :param reason: Reason of the temporary unavailable replica
    :param expires_at: Expiration date of the temporary unavailability
    :param account: Account who declared the replica
    :param logger: The logger

    """
    for rep in chunk:
        logger(logging.DEBUG, 'Working on %s', str(rep))
        try:
            get_metadata(rep['scope'], rep['name'])
            unavailable_states = []
            rep_state = get_replicas_state(rep['scope'], rep['name'])
            unavailable_states.extend(rep_state.get(ReplicaState.TEMPORARY_UNAVAILABLE, []))
            unavailable_states.extend(rep_state.get(ReplicaState.BEING_DELETED, []))
            unavailable_states.extend(rep_state.get(ReplicaState.BAD, []))
            # If the replica is already not available, it is removed from the bad PFNs table
            if rep['rse_id'] in unavailable_states:
                logger(logging.INFO, '%s is in unavailable state. Will be removed from the list of bad PFNs', str(rep['pfn']))
                bulk_delete_bad_pfns(pfns=[rep['pfn']], session=None)
            # If the expiration date of the TEMPORARY_UNAVAILABLE is in the past, it is removed from the bad PFNs table
            elif expires_at < datetime.now():
                logger(logging.INFO, 'PFN %s expiration time (%s) is older than now and is not in unavailable state. Removing the PFNs from bad_pfns', str(rep['pfn']), expires_at)
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
                    logger(logging.ERROR, 'Cannot update state of %s', str(rep['pfn']))
        except (DataIdentifierNotFound, ReplicaNotFound):
            logger(logging.ERROR, 'Will remove %s from the list of bad PFNs', str(rep['pfn']))
            bulk_delete_bad_pfns(pfns=[rep['pfn']], session=None)


def minos(bulk: int = 1000, once: bool = False, sleep_time: int = 60) -> None:
    """
    Creates a Minos Worker that gets a list of bad PFNs,
    extract the scope, name and rse_id and fill the bad_replicas table.

    :param bulk: The number of requests to process.
    :param once: Run only once.
    :param sleep_time: Time between two cycles.
    """
    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable='minos',
        logger_prefix='minos',
        partition_wait_time=10,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            bulk=bulk,
        ),
    )


def run_once(heartbeat_handler: "HeartbeatHandler", bulk: int, **_kwargs) -> bool:
    worker_number, total_workers, logger = heartbeat_handler.live()
    logger(logging.INFO, 'Minos started')

    chunk_size = config_get_int('minos', 'commit_size', default=10, raise_exception=False)  # The chunk size used for the commits

    pfns = get_bad_pfns(thread=worker_number, total_threads=total_workers, limit=bulk)

    # Class the PFNs into bad_replicas and temporary_unavailable
    bad_replicas, temporary_unvailables = __classify_bad_pfns(pfns)

    # Process the bad and suspicious files
    # The scope, name, rse_id are extracted and filled into the bad_replicas table
    for account, reason, state in bad_replicas:
        vo = account.vo
        pfns = bad_replicas[(account, reason, state)]
        logger(logging.INFO, 'Declaring %s replicas with state %s and reason %s', len(pfns), str(state), reason)
        session = get_session()
        try:
            dict_rse = __clean_unknown_replicas(pfns, vo, logger)
            for rse_id, pfns_by_scheme in dict_rse.items():
                rse = get_rse_name(rse_id=rse_id, session=None)
                rse_vo_str = rse if vo == 'def' else '{} on VO {}'.format(rse, vo)
                for scheme, pfns in pfns_by_scheme.items():
                    logger(logging.DEBUG, 'Running on RSE %s with %s replicas', rse_vo_str, len(pfns))
                    tot_chunk = int(math.ceil(len(pfns) / chunk_size))
                    for nchunk, chunk in enumerate(chunks(pfns, chunk_size)):
                        logger(logging.DEBUG, 'Running on %s chunk out of %s', nchunk + 1, tot_chunk)
                        unknown_replicas = declare_bad_file_replicas(chunk, reason=reason, issuer=account, status=state, session=session)
                        if unknown_replicas:
                            logger(logging.DEBUG, 'Unknown replicas : %s', str(unknown_replicas))
                        bulk_delete_bad_pfns(pfns=chunk, session=session)
                        session.commit()  # pylint: disable=no-member
        except (DatabaseException, DatabaseError) as error:
            if re.match('.*ORA-00054.*', error.args[0]) or re.match('.*ORA-00060.*', error.args[0]) or 'ERROR 1205 (HY000)' in error.args[0]:
                logger(logging.WARNING, 'Lock detected when handling request - skipping: %s', str(error))
            else:
                logger(logging.ERROR, 'Exception', exc_info=True)
            session.rollback()  # pylint: disable=no-member
        except Exception:
            session.rollback()  # pylint: disable=no-member
            logger(logging.CRITICAL, 'Exception', exc_info=True)

    worker_number, total_workers, logger = heartbeat_handler.live()

    # Now get the temporary unavailable and update the replicas states
    for account, reason, expires_at in temporary_unvailables:
        vo = account.vo
        pfns = temporary_unvailables[(account, reason, expires_at)]
        logger(logging.INFO, 'Declaring %s replicas temporary available with timeout %s and reason %s', len(pfns), str(expires_at), reason)
        logger(logging.DEBUG, 'Extracting RSEs')

        dict_rse = __clean_unknown_replicas(pfns, vo, logger)
        for rse_id in dict_rse:
            replicas = []
            rse = get_rse_name(rse_id=rse_id, session=None)
            rse_vo_str = rse if vo == 'def' else '{} on VO {}'.format(rse, vo)
            logger(logging.DEBUG, 'Running on RSE %s', rse_vo_str)
            for rse_id, pfns_by_scheme in dict_rse.items():
                for scheme, pfns in pfns_by_scheme.items():
                    for rep in get_did_from_pfns(pfns=pfns, rse_id=None, vo=vo, session=None):
                        for pfn in rep:
                            scope = rep[pfn]['scope']
                            name = rep[pfn]['name']
                            replicas.append({'scope': scope, 'name': name, 'rse_id': rse_id, 'state': ReplicaState.TEMPORARY_UNAVAILABLE, 'pfn': pfn})
            # The following part needs to be atomic
            # We update the replicas states to TEMPORARY_UNAVAILABLE
            # then insert a row in the bad_replicas table. TODO Update the row if it already exists
            # then delete the corresponding rows into the bad_pfns table
            logger(logging.DEBUG, 'Running on %s replicas on RSE %s', len(replicas), rse_vo_str)
            tot_chunk = int(math.ceil(len(replicas) / float(chunk_size)))
            session = get_session()
            for nchunk, chunk in enumerate(chunks(replicas, chunk_size)):
                try:
                    logger(logging.DEBUG, 'Running on %s chunk out of %s', nchunk + 1, tot_chunk)
                    update_replicas_states(chunk, nowait=False, session=session)
                    bulk_add_bad_replicas(chunk, account, state=BadFilesStatus.TEMPORARY_UNAVAILABLE, reason=reason, expires_at=expires_at, session=session)
                    pfns = [entry['pfn'] for entry in chunk]
                    bulk_delete_bad_pfns(pfns=pfns, session=session)
                    session.commit()  # pylint: disable=no-member
                except (UnsupportedOperation, ReplicaNotFound) as error:
                    session.rollback()  # pylint: disable=no-member
                    logger(logging.ERROR, 'Problem to bulk update PFNs. PFNs will be updated individually. Error : %s', str(error))
                    # Update all the replicas one by one
                    __update_temporary_unavailable(chunk=chunk, reason=reason, expires_at=expires_at, account=account, logger=logger)
                    session = get_session()
                except (DatabaseException, DatabaseError) as error:
                    if re.match('.*ORA-00054.*', error.args[0]) or re.match('.*ORA-00060.*', error.args[0]) or 'ERROR 1205 (HY000)' in error.args[0]:
                        logger(logging.WARNING, 'Lock detected when handling request - skipping: %s', str(error))
                    else:
                        logger(logging.ERROR, 'Exception', exc_info=True)
                    session.rollback()  # pylint: disable=no-member
                    session = get_session()
                except Exception:
                    session.rollback()  # pylint: disable=no-member
                    logger(logging.CRITICAL, 'Exception', exc_info=True)
                    session = get_session()
    must_sleep = True
    if len(pfns) == bulk:
        logger(logging.INFO, 'Processed maximum number of pfns according to the bulk size. Restart immediately next cycle')
        must_sleep = False
        return must_sleep
    return must_sleep


def run(threads: int = 1, bulk: int = 100, once: bool = False, sleep_time: int = 60) -> None:
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
    graceful_stop.set()
