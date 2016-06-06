# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014
# - Wen Guan, <wen.guan@cern.ch>, 2014-2016

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
from rucio.core import request, heartbeat
from rucio.core.monitor import record_timer, record_counter
from rucio.daemons.conveyor import common
from rucio.db.sqla.constants import FTSState


logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()

# http://bugs.python.org/issue7980
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
        if type(external_hosts) == str:
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
                    resps = request.query_latest(external_host, state=state, last_nhours=last_nhours)
                except:
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
                        ret = common.update_request_state(resp)
                        # if True, really update request content; if False, only touch request
                        record_counter('daemons.conveyor.poller_latest.update_request_state.%s' % ret)
                    except:
                        logging.error(traceback.format_exc())
            if once:
                break

            time_left = fts_wait - abs(time.time() - start_time)
            if time_left > 0:
                logging.debug("Waiting %s seconds until next FTS terminal state retrieval" % time_left)
                time.sleep(time_left)
        except RequestException, e:
            logging.error("Failed to contact FTS server: %s" % (str(e)))
        except:
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

    if once:
        logging.info('executing one poller iteration only')
        poller_latest(external_hosts, once=once, last_nhours=last_nhours)
    else:

        logging.info('starting poller threads')

        threads = [threading.Thread(target=poller_latest, kwargs={'external_hosts': external_hosts,
                                                                  'fts_wait': fts_wait,
                                                                  'last_nhours': last_nhours}) for i in xrange(0, total_threads)]

        [t.start() for t in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            threads = [t.join(timeout=3.14) for t in threads if t and t.isAlive()]
