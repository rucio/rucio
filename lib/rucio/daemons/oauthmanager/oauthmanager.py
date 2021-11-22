# -*- coding: utf-8 -*-
# Copyright 2019-2021 CERN
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
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020-2021
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - David Población Criado <david.poblacion.criado@cern.ch>, 2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021
# - Joel Dierkes <joel.dierkes@cern.ch>, 2021

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

from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common.exception import DatabaseException
from rucio.common.logging import setup_logging, formatted_logger
from rucio.common.utils import daemon_sleep
from rucio.core.authentication import delete_expired_tokens
from rucio.core.heartbeat import die, live, sanity_check
from rucio.core.monitor import record_counter, record_timer
from rucio.core.oidc import delete_expired_oauthrequests, refresh_jwt_tokens

GRACEFUL_STOP = threading.Event()


def OAuthManager(once=False, loop_rate=300, max_rows=100, sleep_time=300):
    """
    Main loop to delete all expired tokens, refresh tokens eligible
    for refresh and delete all expired OAuth session parameters.
    It was decided to have only 1 daemon for all 3 of these cleanup activities.

    :param once: If True, the loop is run just once, otherwise the daemon continues looping until stopped.
    :param loop_rate: obsolete, please use sleep_time instead. The number of seconds the daemon will wait before running next loop of operations.
    :param max_rows: Max number of DB rows to deal with per operation.
    :param sleep_time: The number of seconds the daemon will wait before running next loop of operations.

    :returns: None
    """
    if sleep_time == OAuthManager.__defaults__[3] and loop_rate != OAuthManager.__defaults__[1]:
        sleep_time = loop_rate

    executable = 'oauth-manager'

    sanity_check(executable=executable, hostname=socket.gethostname())

    # make an initial heartbeat
    heartbeat = live(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
    prepend_str = 'oauth_manager [%i/%i] : ' % (heartbeat['assign_thread'], heartbeat['nr_threads'])
    logger = formatted_logger(logging.log, prepend_str + '%s')

    # wait a moment in case all workers started at the same time
    GRACEFUL_STOP.wait(1)

    while not GRACEFUL_STOP.is_set():
        start = time.time()
        # issuing the heartbeat for a second time to make all workers aware of each other
        heartbeat = live(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
        prepend_str = 'oauth_manager [%i/%i] : ' % (heartbeat['assign_thread'], heartbeat['nr_threads'])
        logger = formatted_logger(logging.log, prepend_str + '%s')
        ndeleted = 0
        ndeletedreq = 0
        nrefreshed = 0

        try:
            # ACCESS TOKEN REFRESH - better to run first (in case some of the refreshed tokens needed deletion after this step)
            logger(logging.INFO, '----- START ----- ACCESS TOKEN REFRESH ----- ')
            logger(logging.INFO, 'starting to query tokens for automatic refresh')
            nrefreshed = refresh_jwt_tokens(heartbeat['nr_threads'], heartbeat['assign_thread'] + 1, refreshrate=int(sleep_time), limit=max_rows)
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
        except Exception as err:
            logger(logging.CRITICAL, traceback.format_exc())
            record_counter('oauth_manager.exceptions.{exception}', labels={'exception': err.__class__.__name__})

        try:
            # waiting 1 sec as DBs does not store milisecond and tokens
            # eligible for deletion after refresh might not get dleeted otherwise
            GRACEFUL_STOP.wait(1)
            # EXPIRED TOKEN DELETION
            logger(logging.INFO, '----- START ----- DELETION OF EXPIRED TOKENS ----- ')
            logger(logging.INFO, 'starting to delete expired tokens')
            ndeleted += delete_expired_tokens(heartbeat['nr_threads'], heartbeat['assign_thread'] + 1, limit=max_rows)
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
        except Exception as err:
            logger(logging.CRITICAL, traceback.format_exc())
            record_counter('oauth_manager.exceptions.{exception}', labels={'exception': err.__class__.__name__})

        try:
            # DELETING EXPIRED OAUTH SESSION PARAMETERS
            logger(logging.INFO, '----- START ----- DELETION OF EXPIRED OAUTH SESSION REQUESTS ----- ')
            logger(logging.INFO, 'starting deletion of expired OAuth session requests')
            ndeletedreq += delete_expired_oauthrequests(heartbeat['nr_threads'], heartbeat['assign_thread'] + 1, limit=max_rows)
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
        except Exception as err:
            logger(logging.CRITICAL, traceback.format_exc())
            record_counter('oauth_manager.exceptions.{exception}', labels={'exception': err.__class__.__name__})

        tottime = time.time() - start
        logger(logging.INFO, 'took %f seconds to delete %i tokens, %i session parameters and refreshed %i tokens', tottime, ndeleted, ndeletedreq, nrefreshed)
        record_timer(name='oauth_manager.duration', time=1000 * tottime)

        if once:
            break
        else:
            daemon_sleep(start_time=start, sleep_time=sleep_time, graceful_stop=GRACEFUL_STOP)

    die(executable=executable, hostname=socket.gethostname(), pid=os.getpid(), thread=threading.current_thread())
    logger(logging.INFO, 'graceful stop done')


def run(once=False, threads=1, loop_rate=300, max_rows=100, sleep_time=300):
    """
    Starts up the OAuth Manager threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    sanity_check(executable='OAuthManager', hostname=socket.gethostname())

    if once:
        OAuthManager(once, loop_rate, max_rows, sleep_time)
    else:
        logging.info('OAuth Manager starting %s threads', str(threads))
        threads = [threading.Thread(target=OAuthManager,
                                    kwargs={'once': once,
                                            'loop_rate': int(loop_rate),
                                            'max_rows': max_rows,
                                            'sleep_time': sleep_time}) for i in range(0, threads)]
        [t.start() for t in threads]
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]


def stop():
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()
