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
OAuth Manager is a daemon which is reponsible for:
- deletion of expired access tokens (in case there is a valid refresh token,
  expired access tokens will be kept until refresh_token expires as well.)
- deletion of expired OAuth session parameters
- refreshing access tokens via their refresh tokens.

These 3 actions run consequently one after another in a loop with a sleeptime of 'looprate' seconds.
The maximum number of DB rows (tokens, parameters, refresh tokens) on which the script will operate
can be specified by 'max_rows' parameter.

"""

import functools
import logging
import threading
import traceback
from re import match

from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common.exception import DatabaseException
from rucio.common.logging import setup_logging
from rucio.core.authentication import delete_expired_tokens
from rucio.core.monitor import record_counter, Timer
from rucio.core.oidc import delete_expired_oauthrequests, refresh_jwt_tokens
from rucio.daemons.common import run_daemon
from rucio.daemons.common import HeartbeatHandler

graceful_stop = threading.Event()


def OAuthManager(once: bool = False, max_rows: int = 100, sleep_time: int = 300) -> None:
    """
    Main loop to delete all expired tokens, refresh tokens eligible
    for refresh and delete all expired OAuth session parameters.
    It was decided to have only 1 daemon for all 3 of these cleanup activities.

    :param once: If True, the loop is run just once, otherwise the daemon continues looping until stopped.
    :param max_rows: Max number of DB rows to deal with per operation.
    :param sleep_time: The number of seconds the daemon will wait before running next loop of operations.

    :returns: None
    """

    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable='oauth-manager',
        logger_prefix='oauth-manager',
        partition_wait_time=1,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            max_rows=max_rows,
            sleep_time=sleep_time
        ),
    )


def run_once(heartbeat_handler: HeartbeatHandler, max_rows: int, sleep_time: int, **_kwargs) -> None:

    # make an initial heartbeat
    heartbeat_handler.live()

    timer = Timer()

    ndeleted = 0
    ndeletedreq = 0
    nrefreshed = 0

    try:
        # ACCESS TOKEN REFRESH - better to run first (in case some of the refreshed tokens needed deletion after this step)

        # make a heartbeat
        worker_number, total_workers, logger = heartbeat_handler.live()

        logger(logging.INFO, '----- START ----- ACCESS TOKEN REFRESH ----- ')
        logger(logging.INFO, 'starting to query tokens for automatic refresh')
        nrefreshed = refresh_jwt_tokens(total_workers, worker_number, refreshrate=int(sleep_time), limit=max_rows)
        logger(logging.INFO, 'successfully refreshed %i tokens', nrefreshed)
        logger(logging.INFO, '----- END ----- ACCESS TOKEN REFRESH ----- ')
        record_counter(name='oauth_manager.tokens.refreshed', delta=nrefreshed)

    except (DatabaseException, DatabaseError) as err:
        if match('.*QueuePool.*', str(err.args[0])):
            logger(logging.WARNING, traceback.format_exc())
            record_counter('oauth_manager.exceptions.{exception}', labels={'exception': err.__class__.__name__})
        elif match('.*ORA-03135.*', str(err.args[0])):
            logger(logging.WARNING, traceback.format_exc())
            record_counter('oauth_manager.exceptions.{exception}', labels={'exception': err.__class__.__name__})
        else:
            logger(logging.CRITICAL, traceback.format_exc())
            record_counter('oauth_manager.exceptions.{exception}', labels={'exception': err.__class__.__name__})

    try:
        # waiting 1 sec as DBs does not store milisecond and tokens
        # eligible for deletion after refresh might not get deleted otherwise
        graceful_stop.wait(1)

        # make a heartbeat
        worker_number, total_workers, logger = heartbeat_handler.live()

        # EXPIRED TOKEN DELETION
        logger(logging.INFO, '----- START ----- DELETION OF EXPIRED TOKENS ----- ')
        logger(logging.INFO, 'starting to delete expired tokens')
        ndeleted += delete_expired_tokens(total_workers, worker_number, limit=max_rows)
        logger(logging.INFO, 'deleted %i expired tokens', ndeleted)
        logger(logging.INFO, '----- END ----- DELETION OF EXPIRED TOKENS ----- ')
        record_counter(name='oauth_manager.tokens.deleted', delta=ndeleted)

    except (DatabaseException, DatabaseError) as err:
        if match('.*QueuePool.*', str(err.args[0])):
            logger(logging.WARNING, traceback.format_exc())
            record_counter('oauth_manager.exceptions.{exception}', labels={'exception': err.__class__.__name__})
        elif match('.*ORA-03135.*', str(err.args[0])):
            logger(logging.WARNING, traceback.format_exc())
            record_counter('oauth_manager.exceptions.{exception}', labels={'exception': err.__class__.__name__})
        else:
            logger(logging.CRITICAL, traceback.format_exc())
            record_counter('oauth_manager.exceptions.{exception}', labels={'exception': err.__class__.__name__})

    try:
        # make a heartbeat
        worker_number, total_workers, logger = heartbeat_handler.live()

        # DELETING EXPIRED OAUTH SESSION PARAMETERS
        logger(logging.INFO, '----- START ----- DELETION OF EXPIRED OAUTH SESSION REQUESTS ----- ')
        logger(logging.INFO, 'starting deletion of expired OAuth session requests')
        ndeletedreq += delete_expired_oauthrequests(total_workers, worker_number, limit=max_rows)
        logger(logging.INFO, 'expired parameters of %i authentication requests were deleted', ndeletedreq)
        logger(logging.INFO, '----- END ----- DELETION OF EXPIRED OAUTH SESSION REQUESTS ----- ')
        record_counter(name='oauth_manager.oauthreq.deleted', delta=ndeletedreq)

    except (DatabaseException, DatabaseError) as err:
        if match('.*QueuePool.*', str(err.args[0])):
            logger(logging.WARNING, traceback.format_exc())
            record_counter('oauth_manager.exceptions.{exception}', labels={'exception': err.__class__.__name__})
        elif match('.*ORA-03135.*', str(err.args[0])):
            logger(logging.WARNING, traceback.format_exc())
            record_counter('oauth_manager.exceptions.{exception}', labels={'exception': err.__class__.__name__})
        else:
            logger(logging.CRITICAL, traceback.format_exc())
            record_counter('oauth_manager.exceptions.{exception}', labels={'exception': err.__class__.__name__})

    timer.stop()
    logger(logging.INFO, 'took %f seconds to delete %i tokens, %i session parameters and refreshed %i tokens', timer.elapsed, ndeleted, ndeletedreq, nrefreshed)
    timer.record('oauth_manager.duration')


def run(once: bool = False, threads: int = 1, max_rows: int = 100, sleep_time: int = 300) -> None:
    """
    Starts up the OAuth Manager threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    if once:
        OAuthManager(once, max_rows, sleep_time)
    else:
        logging.info('OAuth Manager starting %s threads', str(threads))
        threads = [threading.Thread(target=OAuthManager,
                                    kwargs={'once': once,
                                            'max_rows': max_rows,
                                            'sleep_time': sleep_time}) for i in range(0, threads)]
        _ = [t.start() for t in threads]
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            _ = [t.join(timeout=3.14) for t in threads]


def stop() -> None:
    """
    Graceful exit.
    """
    graceful_stop.set()
