# -*- coding: utf-8 -*-
# Copyright 2019-2020 CERN
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
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019-2020
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

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

from __future__ import print_function

import logging
import os
import socket
import threading
import time
import traceback
from re import match
from sys import stdout

from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common.config import config_get
from rucio.common.exception import DatabaseException
from rucio.core.authentication import delete_expired_tokens
from rucio.core.heartbeat import die, live, sanity_check
from rucio.core.monitor import record_counter, record_timer
from rucio.core.oidc import delete_expired_oauthrequests, refresh_jwt_tokens

logging.basicConfig(stream=stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

GRACEFUL_STOP = threading.Event()


def OAuthManager(once=False, loop_rate=300, max_rows=100):
    """
    Main loop to delete all expired tokens, refresh tokens eligible
    for refresh and delete all expired OAuth session parameters.
    It was decided to have only 1 daemon for all 3 of these cleanup activities.

    :param once: If True, the loop is run just once, otherwise the daemon continues looping until stopped.
    :param loop_rate: The number of seconds the daemon will wait before running next loop of operations.
    :param max_rows: Max number of DB rows to deal with per operation.

    :returns: None
    """

    executable = 'oauth-manager'

    sanity_check(executable=executable, hostname=socket.gethostname())

    # make an initial heartbeat
    live(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())

    # wait a moment in case all workers started at the same time
    GRACEFUL_STOP.wait(1)

    while not GRACEFUL_STOP.is_set():
        start = time.time()
        # issuing the heartbeat for a second time to make all workers aware of each other
        heartbeat = live(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
        total_workers = heartbeat['nr_threads']
        worker_number = heartbeat['assign_thread'] + 1
        ndeleted = 0
        ndeletedreq = 0
        nrefreshed = 0

        try:
            # ACCESS TOKEN REFRESH - better to run first (in case some of the refreshed tokens needed deletion after this step)
            logging.info('oauth_manager[%i/%i]: ----- START ----- ACCESS TOKEN REFRESH ----- ', worker_number, total_workers)
            logging.info('oauth_manager[%i/%i]: starting to query tokens for automatic refresh', worker_number, total_workers)
            nrefreshed = refresh_jwt_tokens(total_workers, worker_number, refreshrate=int(loop_rate), limit=max_rows)
            logging.info('oauth_manager[%i/%i]: successfully refreshed %i tokens', worker_number, total_workers, nrefreshed)
            logging.info('oauth_manager[%i/%i]: ----- END ----- ACCESS TOKEN REFRESH ----- ', worker_number, total_workers)
            record_counter(counters='oauth_manager.tokens.refreshed', delta=nrefreshed)

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

        try:
            # waiting 1 sec as DBs does not store milisecond and tokens
            # eligible for deletion after refresh might not get dleeted otherwise
            GRACEFUL_STOP.wait(1)
            # EXPIRED TOKEN DELETION
            logging.info('oauth_manager[%i/%i]: ----- START ----- DELETION OF EXPIRED TOKENS ----- ', worker_number, total_workers)
            logging.info('oauth_manager[%i/%i]: starting to delete expired tokens', worker_number, total_workers)
            ndeleted += delete_expired_tokens(total_workers, worker_number, limit=max_rows)
            logging.info('oauth_manager[%i/%i]: deleted %i expired tokens', worker_number, total_workers, ndeleted)
            logging.info('oauth_manager[%i/%i]: ----- END ----- DELETION OF EXPIRED TOKENS ----- ', worker_number, total_workers)
            record_counter(counters='oauth_manager.tokens.deleted', delta=ndeleted)

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

        try:
            # DELETING EXPIRED OAUTH SESSION PARAMETERS
            logging.info('oauth_manager[%i/%i]: ----- START ----- DELETION OF EXPIRED OAUTH SESSION REQUESTS ----- ', worker_number, total_workers)
            logging.info('oauth_manager[%i/%i]: starting deletion of expired OAuth session requests', worker_number, total_workers)
            ndeletedreq += delete_expired_oauthrequests(total_workers, worker_number, limit=max_rows)
            logging.info('oauth_manager[%i/%i]: expired parameters of %i authentication requests were deleted', worker_number, total_workers, ndeletedreq)
            logging.info('oauth_manager[%i/%i]: ----- END ----- DELETION OF EXPIRED OAUTH SESSION REQUESTS ----- ', worker_number, total_workers)
            record_counter(counters='oauth_manager.oauthreq.deleted', delta=ndeletedreq)

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

        tottime = time.time() - start
        logging.info('oauth_manager[%i/%i]: took %f seconds to delete %i tokens, %i session parameters and refreshed %i tokens', worker_number, total_workers, tottime, ndeleted, ndeletedreq, nrefreshed)
        record_timer(stat='oauth_manager.duration', time=1000 * tottime)

        if once:
            break
        else:
            logging.info('oauth_manager[%i/%i]: Sleeping for %i seconds.', worker_number, total_workers, loop_rate)
            GRACEFUL_STOP.wait(loop_rate)

    die(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
    logging.info('oauth_manager[%i/%i]: graceful stop done', worker_number, total_workers)


def run(once=False, threads=1, loop_rate=300, max_rows=100):
    """
    Starts up the OAuth Manager threads.
    """
    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    sanity_check(executable='OAuthManager', hostname=socket.gethostname())

    if once:
        OAuthManager(once, loop_rate, max_rows)
    else:
        logging.info('OAuth Manager starting %s threads', str(threads))
        threads = [threading.Thread(target=OAuthManager,
                                    kwargs={'once': once,
                                            'loop_rate': int(loop_rate),
                                            'max_rows': max_rows}) for i in range(0, threads)]
        [t.start() for t in threads]
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]


def stop():
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()
