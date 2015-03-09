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
           bulk=1000, older_than=60, activity_shares=None):
    """
    Main loop to check the status of a transfer primitive with a transfertool.
    """

    logging.info('poller starting - process (%i/%i) thread (%i/%i) bulk (%i)' % (process, total_processes,
                                                                                 thread, total_threads,
                                                                                 bulk))

    executable = ' '.join(sys.argv)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()

    logging.info('poller started - process (%i/%i) thread (%i/%i) bulk (%i)' % (process, total_processes,
                                                                                thread, total_threads,
                                                                                bulk))

    while not graceful_stop.is_set():

        try:
            heartbeat.live(executable, hostname, pid, hb_thread)

            ts = time.time()

            logging.debug('%i:%i - start to poll requests older than %i seconds' % (process, thread, older_than))
            reqs = request.get_next(request_type=[RequestType.TRANSFER, RequestType.STAGEIN, RequestType.STAGEOUT],
                                    state=RequestState.SUBMITTED,
                                    limit=bulk,
                                    older_than=datetime.datetime.utcnow()-datetime.timedelta(seconds=older_than),
                                    process=process, total_processes=total_processes,
                                    thread=thread, total_threads=total_threads,
                                    activity_shares=activity_shares)
            record_timer('daemons.conveyor.poller.000-get_next', (time.time()-ts)*1000)

            if reqs:
                logging.debug('%i:%i - polling %i requests' % (process, thread, len(reqs)))

            if not reqs or reqs == []:
                if once:
                    break
                logging.debug("%i:%i - no requests found. will sleep 60 second" % (process, thread))
                time.sleep(60)  # Only sleep if there is nothing to do
                continue

            for xfers in chunks(reqs, bulk):
                try:
                    req_ids = {}
                    for req in xfers:
                        record_counter('daemons.conveyor.poller.query_request')
                        if not req['external_host'] in req_ids:
                            req_ids[req['external_host']] = []
                        req_ids[req['external_host']].append((req['request_id'], req['external_id']))

                    responses = {}
                    for external_host in req_ids:
                        ts = time.time()
                        logging.debug('%i:%i - polling %i requests against %s' % (process, thread, len(req_ids[external_host]), external_host))
                        resps = request.bulk_query_requests(external_host, req_ids[external_host], 'fts3')
                        record_timer('daemons.conveyor.poller.001-bulk_query_requests', (time.time()-ts)*1000/len(req_ids[external_host]))
                        responses = dict(responses.items() + resps.items())

                    for external_host in req_ids:
                        for request_id, external_id in req_ids[external_host]:
                            response = responses[request_id]
                            if isinstance(response, Exception):
                                logging.warning("Failed to poll request(%s) with FTS(%s) job (%s): %s" % (request_id, external_host, external_id, responses[request_id]))
                                record_counter('daemons.conveyor.poller.query_request_exception')
                                response = {'new_state': None, 'request_id': request_id, 'transfer_id': external_id, 'job_state': None}
                            ret = common.update_request_state(response)
                            # if True, really update request content; if False, only touch request
                            record_counter('daemons.conveyor.poller.update_request_state.%s' % ret)
                            if response['new_state'] == RequestState.LOST:
                                record_counter('daemons.conveyor.poller.request_lost')
                except (DatabaseException, DatabaseError), e:
                    if isinstance(e.args[0], tuple) and (re.match('.*ORA-00054.*', e.args[0][0]) or ('ERROR 1205 (HY000)' in e.args[0][0])):
                        logging.warn("Lock detected when handling request %s - skipping" % request_id)
                    else:
                        logging.critical(traceback.format_exc())
                except RequestException, e:
                    logging.error("Failed to contact FTS server: %s" % (str(e)))
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
        bulk=1000, older_than=60, activity_shares=None):
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

        activity_shares.update((share, int(percentage*bulk)) for share, percentage in activity_shares.items())
        logging.info('activity shares enabled: %s' % activity_shares)

    if once:
        logging.info('executing one poller iteration only')
        poller(once=once, bulk=bulk, older_than=older_than, activity_shares=activity_shares)

    else:

        logging.info('starting poller threads')

        threads = [threading.Thread(target=poller, kwargs={'process': process,
                                                           'total_processes': total_processes,
                                                           'thread': i,
                                                           'total_threads': total_threads,
                                                           'older_than': older_than,
                                                           'bulk': bulk,
                                                           'activity_shares': activity_shares}) for i in xrange(0, total_threads)]

        [t.start() for t in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            [t.join(timeout=3.14) for t in threads if t and t.isAlive()]
