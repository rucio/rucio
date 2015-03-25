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
# - Wen Guan, <wen.guan@cern.ch>, 2014-2015

"""
Conveyor is a daemon to manage file transfers.
"""

import datetime
import json
import logging
import os
import re
import socket
import sys
import threading
import time
import traceback

from requests.exceptions import RequestException
from sqlalchemy.exc import DatabaseError

from rucio.common.config import config_get
from rucio.common.exception import DatabaseException
from rucio.common.utils import chunks
from rucio.core import request, heartbeat
from rucio.core.monitor import record_timer, record_counter
from rucio.daemons.conveyor import common
from rucio.db.constants import RequestState, RequestType


logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()

# http://bugs.python.org/issue7980
datetime.datetime.strptime('', '')


def poller(once=False,
           process=0, total_processes=1, thread=0, total_threads=1,
           fts_bulk=100, db_bulk=1000, older_than=60, activity_shares=None):
    """
    Main loop to check the status of a transfer primitive with a transfertool.
    """

    logging.info('poller starting - process (%i/%i) thread (%i/%i) bulk (%i)' % (process, total_processes,
                                                                                 thread, total_threads,
                                                                                 db_bulk))

    executable = ' '.join(sys.argv)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()

    logging.info('poller started - process (%i/%i) thread (%i/%i) bulk (%i)' % (process, total_processes,
                                                                                thread, total_threads,
                                                                                db_bulk))

    while not graceful_stop.is_set():

        try:
            heartbeat.live(executable, hostname, pid, hb_thread)

            ts = time.time()

            logging.debug('%i:%i - start to poll transfers older than %i seconds' % (process, thread, older_than))
            transfs = request.get_next_transfers(request_type=[RequestType.TRANSFER, RequestType.STAGEIN, RequestType.STAGEOUT],
                                                 state=RequestState.SUBMITTED,
                                                 limit=db_bulk,
                                                 older_than=datetime.datetime.utcnow()-datetime.timedelta(seconds=older_than),
                                                 process=process, total_processes=total_processes,
                                                 thread=thread, total_threads=total_threads,
                                                 activity_shares=activity_shares)
            record_timer('daemons.conveyor.poller.000-get_next_transfers', (time.time()-ts)*1000)

            if transfs:
                logging.debug('%i:%i - polling %i transfers' % (process, thread, len(transfs)))

            if not transfs or transfs == []:
                if once:
                    break
                logging.debug("%i:%i - no transfers found. will sleep 60 second" % (process, thread))
                time.sleep(60)  # Only sleep if there is nothing to do
                continue

            xfers_ids = {}
            for transf in transfs:
                if not transf['external_host'] in xfers_ids:
                    xfers_ids[transf['external_host']] = []
                xfers_ids[transf['external_host']].append(transf['external_id'])

            for external_host in xfers_ids:
                for xfers in chunks(xfers_ids[external_host], fts_bulk):
                    try:
                        try:
                            ts = time.time()
                            logging.debug('%i:%i - polling %i transfers against %s' % (process, thread, len(xfers), external_host))
                            resps = request.bulk_query_transfers(external_host, xfers, 'fts3')
                            record_timer('daemons.conveyor.poller.001-bulk_query_requests', (time.time()-ts)*1000/len(xfers))
                        except RequestException, e:
                            logging.error("Failed to contact FTS server: %s" % (str(e)))

                        for transfer_id in resps:
                            try:
                                transf_resp = resps[transfer_id]
                                # transf_resp is None: Lost.
                                #             is Exception: Failed to get fts job status.
                                #             is {}: No terminated jobs.
                                #             is {request_id: {file_status}}: terminated jobs.
                                if transf_resp is None:
                                    common.set_transfer_state(external_host, transfer_id, RequestState.LOST)
                                    record_counter('daemons.conveyor.poller.transfer_lost')
                                elif isinstance(transf_resp, Exception):
                                    logging.warning("Failed to poll FTS(%s) job (%s): %s" % (external_host, transfer_id, transf_resp))
                                    record_counter('daemons.conveyor.poller.query_transfer_exception')
                                    common.touch_transfer(external_host, transfer_id)
                                else:
                                    # should touch transfers. Otherwise the updated_at is not renewed if the request is not terminated.
                                    common.touch_transfer(external_host, transfer_id)
                                    for request_id in transf_resp:
                                        ret = common.update_request_state(transf_resp[request_id])
                                        # if True, really update request content; if False, only touch request
                                        record_counter('daemons.conveyor.poller.update_request_state.%s' % ret)
                            except (DatabaseException, DatabaseError), e:
                                if isinstance(e.args[0], tuple) and (re.match('.*ORA-00054.*', e.args[0][0]) or ('ERROR 1205 (HY000)' in e.args[0][0])):
                                    logging.warn("Lock detected when handling request %s - skipping" % request_id)
                                else:
                                    logging.critical(traceback.format_exc())
                    except:
                        logging.critical(traceback.format_exc())
        except:
            logging.critical(traceback.format_exc())

        if once:
            return

    logging.debug('%i:%i - graceful stop requests' % (process, thread))

    heartbeat.die(executable, hostname, pid, hb_thread)

    logging.debug('%i:%i - graceful stop done' % (process, thread))


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False,
        process=0, total_processes=1, total_threads=1,
        fts_bulk=100, db_bulk=1000, older_than=60, activity_shares=None):
    """
    Starts up the conveyer threads.
    """

    if activity_shares:

        try:
            activity_shares = json.loads(activity_shares)
        except:
            logging.critical('activity share is not a valid JSON dictionary')
            return

        try:
            if round(sum(activity_shares.values()), 2) != 1:
                logging.critical('activity shares do not sum up to 1, got %s - aborting' % round(sum(activity_shares.values()), 2))
                return
        except:
            logging.critical('activity shares are not numbers? - aborting')
            return

        activity_shares.update((share, int(percentage*db_bulk)) for share, percentage in activity_shares.items())
        logging.info('activity shares enabled: %s' % activity_shares)

    if once:
        logging.info('executing one poller iteration only')
        poller(once=once, fts_bulk=fts_bulk, db_bulk=db_bulk, older_than=older_than, activity_shares=activity_shares)

    else:

        logging.info('starting poller threads')

        threads = [threading.Thread(target=poller, kwargs={'process': process,
                                                           'total_processes': total_processes,
                                                           'thread': i,
                                                           'total_threads': total_threads,
                                                           'older_than': older_than,
                                                           'fts_bulk': fts_bulk,
                                                           'db_bulk': db_bulk,
                                                           'activity_shares': activity_shares}) for i in xrange(0, total_threads)]

        [t.start() for t in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            [t.join(timeout=3.14) for t in threads if t and t.isAlive()]
