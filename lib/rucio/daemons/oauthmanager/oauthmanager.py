#!/usr/bin/env python
# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
#  - Jaroslav Guenther, <jaroslav.guenther@cern.ch>, 2019
# PY3K COMPATIBLE

"""
OAuth Manager is a daemon which is reponsible for:
- deletion of expired access tokens (in case there is a valid refresh token,
  expired access tokens will be kept until refresh_token expires as well.)
- deletion of expired OAuth session parameters
- refreshing access tokens via their refresh tokens.

These 3 actions run consequently one after another in a loop with a sleeptime of 'looprate' seconds.
The maximum number of DB rows (tokens, parameters, refresh tokens) on which the script will operate
can be specified by 'maxrows' parameter.

"""

from __future__ import print_function

import os
import threading
import traceback
import time
import logging
import socket
from sys import stdout, argv
from re import match
from datetime import datetime, timedelta

from sqlalchemy.exc import DatabaseError

from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.monitor import record_counter, record_timer
from rucio.core.authentication import delete_expired_tokens, delete_expired_oauthreqests, get_tokens_for_refresh, refresh_token_OIDC

from rucio.db.sqla.util import get_db_time
from rucio.common.config import config_get
from rucio.common.exception import DatabaseException


logging.basicConfig(stream=stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

GRACEFUL_STOP = threading.Event()


def OAuthManager(once=False, looprate=300, maxrows=100):

    """

    Main loop to delete all expired tokens, refresh tokens eligible
    for refresh and delete all expired OAuth session parameters.
    It was decided to have only 1 daemon for all 3 of these cleanup activities.

    :param once: If True, the loop is run just once, otherwise the daemon continues looping until stopped.
    :param looprate: The number of seconds the daemon will wait before running next loop of operations.
    :param maxrows: Max number of DB rows to deal with per operation.

    :returns: None
    """

    executable = argv[0]

    sanity_check(executable=executable, hostname=socket.gethostname())

    # make an initial heartbeat
    live(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())

    # wait a moment in case all workers started at the same time
    GRACEFUL_STOP.wait(1)

    while not GRACEFUL_STOP.is_set():
        try:

            # issuing the heartbeat for a second time to make all workers aware of each other
            heartbeat = live(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
            total_workers = heartbeat['nr_threads']
            worker_number = heartbeat['assign_thread'] + 1

            start = time.time()
            # EXPIRED TOKEN DELETION
            logging.info('oauth_manager[%i/%i]: ----- START ----- DELETION OF EXPIRED TOKENS ----- ', worker_number, total_workers)
            logging.info('oauth_manager[%i/%i]: starting to delete expired tokens', worker_number, total_workers)
            ndeleted = delete_expired_tokens(total_workers, worker_number, limit=maxrows)
            logging.info('oauth_manager[%i/%i]: deleted %i expired tokens', worker_number, total_workers, ndeleted)
            logging.info('oauth_manager[%i/%i]: ----- END ----- DELETION OF EXPIRED TOKENS ----- ', worker_number, total_workers)
            record_counter(counters='oauth_manager.tokens.deleted', delta=ndeleted)

            # ACCESS TOKEN REFRESH
            logging.info('oauth_manager[%i/%i]: ----- START ----- ACCESS TOKEN REFRESH ----- ', worker_number, total_workers)
            logging.info('oauth_manager[%i/%i]: starting to query tokens for automatic refresh', worker_number, total_workers)
            tokens_for_refresh = get_tokens_for_refresh(total_workers, worker_number, refreshrate=int(looprate), limit=maxrows)
            logging.info('oauth_manager[%i/%i]: starting attempts to refresh %i tokens', worker_number, total_workers, len(tokens_for_refresh))
            nrefreshed = 0
            for token in tokens_for_refresh:
                refresh_token_OIDC(token)
                nrefreshed += 1
            logging.info('oauth_manager[%i/%i]: successfully refreshed %i tokens', worker_number, total_workers, nrefreshed)
            logging.info('oauth_manager[%i/%i]: ----- END ----- ACCESS TOKEN REFRESH ----- ', worker_number, total_workers)
            record_counter(counters='oauth_manager.tokens.refreshed', delta=nrefreshed)

            # DELETING EXPIRED OAUTH SESSION PARAMETERS
            logging.info('oauth_manager[%i/%i]: ----- START ----- DELETION OF EXPIRED OAUTH SESSION REQUESTS ----- ', worker_number, total_workers)
            logging.info('oauth_manager[%i/%i]: starting deletion of expired OAuth session requests', worker_number, total_workers)
            ndeletedreq = delete_expired_oauthreqests(total_workers, worker_number, limit=maxrows)
            logging.info('oauth_manager[%i/%i]: expired parameters of %i authentication requests were deleted', worker_number, total_workers, ndeletedreq)
            logging.info('oauth_manager[%i/%i]: ----- END ----- DELETION OF EXPIRED OAUTH SESSION REQUESTS ----- ', worker_number, total_workers)
            record_counter(counters='oauth_manager.oauthreq.deleted', delta=ndeletedreq)
            tottime = time.time() - start
            logging.info('oauth_manager[%i/%i]: took %f seconds to delete %i tokens, %i session parameters and refreshed %i tokens' % (worker_number, total_workers, tottime, ndeleted, ndeletedreq, nrefreshed))
            record_timer(stat='oauth_manager.duration', time=1000 * tottime)

        except (DatabaseException, DatabaseError) as err:
            if match('.*QueuePool.*', str(err.args[0])):
                logging.warning(traceback.format_exc())
                record_counter('oauth_manager.exceptions.%s', err.__class__.__name__)
            elif match('.*ORA-03135.*', str(err.args[0])):
                logging.warning(traceback.format_exc())
                record_counter('oauth_manager.exceptions.%s', err.__class__.__name__)
            else:
                logging.critical(traceback.format_exc())
                record_counter('oauth_manager.exceptions.%s', err.__class__.__name__)
        except Exception as err:
            logging.critical(traceback.format_exc())
            record_counter('oauth_manager.exceptions.%s', err.__class__.__name__)

        if once:
            break
        else:
            logging.info('oauth_manager[%i/%i]: Sleeping for %i seconds.', worker_number, total_workers, looprate)
            GRACEFUL_STOP.wait(looprate)

    die(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
    logging.info('oauth_manager[%i/%i]: graceful stop done', worker_number, total_workers)


def run(once=False, threads=1, looprate=300, maxrows=100):

    """
    Starts up the OAuth Manager threads.
    """

    client_time, db_time = datetime.utcnow(), get_db_time()
    max_offset = timedelta(hours=1, seconds=10)
    if isinstance(db_time, datetime):
        if db_time - client_time > max_offset or client_time - db_time > max_offset:
            logging.critical('Offset between client and db time too big. Stopping Token Manager.')
            return

    sanity_check(executable='OAuthManager', hostname=socket.gethostname())

    if once:
        OAuthManager(once, looprate, maxrows)
    else:
        logging.info('OAuth Manager starting %s threads' % str(threads))
        threads = [threading.Thread(target=OAuthManager,
                                    kwargs={'once': once,
                                            'looprate': int(looprate),
                                            'maxrows': maxrows}) for i in range(0, threads)]
        [t.start() for t in threads]
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]


def stop():
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()
