# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2014
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014
# - Wen Guan, <wen.guan@cern.ch>, 2014

"""
Conveyor is a daemon to manage file transfers.
"""

import datetime
import logging
import sys
import threading
import time
import traceback

from rucio.common.config import config_get
from rucio.core import request
from rucio.core.monitor import record_timer
from rucio.daemons.conveyor import common
from rucio.db.constants import RequestState, RequestType

logging.getLogger("requests").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()

# http://bugs.python.org/issue7980
datetime.datetime.strptime('', '')


def poller(once=False, process=0, total_processes=1, thread=0, total_threads=1, bulk=100):
    """
    Main loop to check the status of a transfer primitive with a transfertool.
    """

    logging.info('poller starting - process (%i/%i) thread (%i/%i) bulk (%i)' % (process, total_processes,
                                                                                 thread, total_threads,
                                                                                 bulk))

    logging.info('poller started - process (%i/%i) thread (%i/%i) bulk (%i)' % (process, total_processes,
                                                                                thread, total_threads,
                                                                                bulk))

    while not graceful_stop.is_set():

        try:
            ts = time.time()

            reqs = request.get_next(request_type=[RequestType.TRANSFER, RequestType.STAGEIN, RequestType.STAGEOUT],
                                    state=RequestState.SUBMITTED,
                                    limit=bulk,
                                    older_than=datetime.datetime.utcnow()-datetime.timedelta(seconds=3600),
                                    process=process, total_processes=total_processes,
                                    thread=thread, total_threads=total_threads)
            record_timer('daemons.conveyor.poller.000-get_next', (time.time()-ts)*1000)

            if reqs:
                logging.debug('%i:%i - polling %i requests' % (process, thread, len(reqs)))

            if not reqs or reqs == []:
                if once:
                    break
                time.sleep(1)  # Only sleep if there is nothing to do
                continue

            req_ids = {}
            for req in reqs:
                if not req['external_host'] in req_ids:
                    req_ids[req['external_host']] = []
                req_ids[req['external_host']].append((req['request_id'], req['external_id']))

            responses = {}
            for external_host in req_ids:
                ts = time.time()
                resps = request.bulk_query_requests(external_host, req_ids[external_host], 'fts3')
                record_timer('daemons.conveyor.poller.001-bulk_query_requests', (time.time()-ts)*1000/len(req_ids[external_host]))
                responses = dict(responses.items() + resps.items())

            tmp = []
            for req in reqs:
                tmp.append([req, responses[req['request_id']]])

            common.update_requests_states(tmp)

        except:
            logging.critical(traceback.format_exc())

        if once:
            return

    logging.debug('%i:%i - graceful stop requests' % (process, thread))

    logging.debug('%i:%i - graceful stop done' % (process, thread))


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, process=0, total_processes=1, total_threads=1, bulk=None):
    """
    Starts up the conveyer threads.
    """

    if once:
        logging.info('executing one poller iteration only')
        poller(once=once, bulk=bulk)

    else:

        logging.info('starting poller threads')
        threads = [threading.Thread(target=poller, kwargs={'process': process,
                                                           'total_processes': total_processes,
                                                           'thread': i,
                                                           'total_threads': total_threads,
                                                           'bulk': bulk}) for i in xrange(0, total_threads)]

        [t.start() for t in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            [t.join(timeout=3.14) for t in threads if t and t.isAlive()]
