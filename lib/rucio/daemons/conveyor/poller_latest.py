# Copyright 2015-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Wen Guan <wguan.icedew@gmail.com>, 2015-2016
# - Vincent Garonne <vgaronne@gmail.com>, 2015-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2016-2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018
#
# PY3K COMPATIBLE

"""
Conveyor is a daemon to manage file transfers.
"""

import datetime
import logging
import os
import sys
import socket
import threading
import time
import traceback

from requests.exceptions import RequestException

from rucio.common.config import config_get
from rucio.core import heartbeat, transfer, request
from rucio.core.monitor import record_timer, record_counter
from rucio.db.sqla.constants import FTSState


logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()

datetime.datetime.strptime('', '')


def poller_latest(external_hosts, once=False, last_nhours=1, fts_wait=1800):
    """
    Main loop to check the status of a transfer primitive with a transfertool.
    """

    executable = ' '.join(sys.argv)
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
                state = [str(FTSState.FINISHED), str(FTSState.FAILED), str(FTSState.FINISHEDDIRTY), str(FTSState.CANCELED)]
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

            time_left = fts_wait - abs(time.time() - start_time)
            if time_left > 0:
                logging.debug("Waiting %s seconds until next FTS terminal state retrieval" % time_left)
                graceful_stop.wait(time_left)
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


def run(once=False, last_nhours=1, external_hosts=None, fts_wait=1800, total_threads=1):
    """
    Starts up the conveyer threads.
    """

    if not external_hosts:
        external_hosts = []

    if once:
        logging.info('executing one poller iteration only')
        poller_latest(external_hosts, once=once, last_nhours=last_nhours)
    else:

        logging.info('starting poller threads')

        threads = [threading.Thread(target=poller_latest, kwargs={'external_hosts': external_hosts,
                                                                  'fts_wait': fts_wait,
                                                                  'last_nhours': last_nhours}) for _ in range(0, total_threads)]

        [thread.start() for thread in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while threads:
            threads = [thread.join(timeout=3.14) for thread in threads if thread and thread.isAlive()]
