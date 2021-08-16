# -*- coding: utf-8 -*-
# Copyright 2015-2021 CERN
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
# - Wen Guan <wen.guan@cern.ch>, 2015-2016
# - Vincent Garonne <vincent.garonne@cern.ch>, 2015-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2016-2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020-2021
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Mario Lassnig <mario.lassnig@cern.ch>, 2021
# - Sahan Dilshan <32576163+sahandilshan@users.noreply.github.com>, 2021
# - David Población Criado <david.poblacion.criado@cern.ch>, 2021

"""
Conveyor is a daemon to manage file transfers.
"""

import datetime
import logging
import os
import socket
import threading
import time
import traceback

from requests.exceptions import RequestException

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.constants import FTS_STATE
from rucio.common.logging import setup_logging
from rucio.common.utils import daemon_sleep
from rucio.core import heartbeat, transfer, request
from rucio.core.monitor import record_timer, record_counter

graceful_stop = threading.Event()

datetime.datetime.strptime('', '')


def poller_latest(external_hosts, once=False, last_nhours=1, fts_wait=1800, sleep_time=1800):
    """
    Main loop to check the status of a transfer primitive with a transfertool.
    :param fts_wait: OBSOLETE, please use sleep_time instead
    """
    if sleep_time == poller_latest.__defaults__[3] and fts_wait != poller_latest.__defaults__[2]:
        sleep_time = fts_wait
    executable = 'conveyor-poller-latest'
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()

    logging.info('polling latest %s hours on hosts: %s' % (last_nhours, external_hosts))
    if external_hosts:
        if isinstance(external_hosts, str):
            external_hosts = [external_hosts]

    while not graceful_stop.is_set():

        try:
            heartbeat.live(executable, hostname, pid, hb_thread)

            start_time = time.time()
            for external_host in external_hosts:
                logging.debug('polling latest %s hours on host: %s' % (last_nhours, external_host))
                ts = time.time()
                resps = None
                state = [FTS_STATE.FINISHED,
                         FTS_STATE.FAILED,
                         FTS_STATE.FINISHEDDIRTY,
                         FTS_STATE.CANCELED]
                try:
                    resps = transfer.query_latest(external_host, state=state, last_nhours=last_nhours)
                except Exception:
                    logging.error(traceback.format_exc())
                record_timer('daemons.conveyor.poller_latest.000-query_latest', (time.time() - ts) * 1000)

                if resps:
                    logging.info('poller_latest - polling %i requests' % (len(resps)))

                if not resps or resps == []:
                    if once:
                        break
                    logging.info("no requests found. will sleep 60 seconds")
                    continue

                for resp in resps:
                    try:
                        ret = request.update_request_state(resp)
                        # if True, really update request content; if False, only touch request
                        record_counter('daemons.conveyor.poller_latest.update_request_state.%s' % ret)
                    except Exception:
                        logging.error(traceback.format_exc())
            if once:
                break

            daemon_sleep(start_time=start_time, sleep_time=sleep_time, graceful_stop=graceful_stop)
        except RequestException as error:
            logging.error("Failed to contact FTS server: %s" % (str(error)))
        except Exception:
            logging.critical(traceback.format_exc())

        if once:
            return

    logging.info('poller_latest - graceful stop requests')

    heartbeat.die(executable, hostname, pid, hb_thread)

    logging.info('poller_latest - graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, last_nhours=1, external_hosts=None, fts_wait=1800, total_threads=1, sleep_time=1800):
    """
    Starts up the conveyer threads.
    :param fts_wait: OBSOLETE, please use sleep_time instead
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    if not external_hosts:
        external_hosts = []

    if once:
        logging.info('executing one poller iteration only')
        poller_latest(external_hosts, once=once, last_nhours=last_nhours)
    else:

        logging.info('starting poller threads')

        threads = [threading.Thread(target=poller_latest, kwargs={'external_hosts': external_hosts,
                                                                  'fts_wait': fts_wait,
                                                                  'last_nhours': last_nhours,
                                                                  'sleep_time': sleep_time}) for _ in range(0, total_threads)]

        [thread.start() for thread in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while threads:
            threads = [thread.join(timeout=3.14) for thread in threads if thread and thread.is_alive()]
