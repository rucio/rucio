# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2014

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
from rucio.core.monitor import record_counter, record_timer
from rucio.daemons.conveyor import common
from rucio.db.constants import RequestState, RequestType
from rucio.db.session import get_session

logging.getLogger("requests").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def poller(once=False, process=0, total_processes=1, thread=0, total_threads=1):
    """
    Main loop to check the status of a transfer primitive with a transfertool.
    """

    logging.info('poller starting')

    session = get_session()

    logging.info('poller started')

    while not graceful_stop.is_set():

        try:
            ts = time.time()
            reqs = request.get_next(request_type=[RequestType.TRANSFER, RequestType.STAGEIN, RequestType.STAGEOUT],
                                    state=RequestState.SUBMITTED,
                                    limit=100,
                                    older_than=datetime.datetime.utcnow()-datetime.timedelta(seconds=3600),
                                    process=process, total_processes=total_processes,
                                    thread=thread, total_threads=total_threads,
                                    session=session)
            record_timer('daemons.conveyor.poller.000-get_next', (time.time()-ts)*1000)

            if reqs is None or reqs == []:
                if once:
                    break
                session.commit()
                time.sleep(1)  # Only sleep if there is nothing to do
                continue

            for req in reqs:
                ts = time.time()
                response = request.query_request(req['request_id'], 'fts3', session=session)
                record_timer('daemons.conveyor.poller.001-query_request', (time.time()-ts)*1000)

                req['src_rse'] = 'UNKNOWN'
                response['transfer_id'] = req['external_id']

                if common.update_request_state(req, response, session):
                    session.commit()
                else:
                    session.rollback()

                record_counter('daemons.conveyor.poller.query_request')

        except:
            session.rollback()
            logging.critical(traceback.format_exc())

        if once:
            return

    logging.info('poller: graceful stop requested')

    logging.info('poller: graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, process=0, total_processes=1, total_threads=1):
    """
    Starts up the conveyer threads.
    """

    if once:
        logging.info('executing one poller iteration only')
        poller(once)

    else:

        logging.info('starting poller threads')
        threads = [threading.Thread(target=poller, kwargs={'process': process, 'total_processes': total_processes, 'thread': i, 'total_threads': total_threads}) for i in xrange(0, total_threads)]

        [t.start() for t in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            [t.join(timeout=3.14) for t in threads if t and t.isAlive()]
