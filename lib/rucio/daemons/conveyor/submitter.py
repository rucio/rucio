# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0OA
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013-2015
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2015
# - Wen Guan, <wen.guan@cern.ch>, 2014-2015
# - Joaquin Bogado, <jbogadog@cern.ch>, 2016

"""
Conveyor is a daemon to manage file transfers.
"""

import datetime
import json
import logging
import os
import socket
import sys
import threading
import time
import traceback
import urlparse

from collections import defaultdict
from ConfigParser import NoOptionError
from requests.exceptions import RequestException

from rucio.common.config import config_get
from rucio.common.exception import UnsupportedOperation
from rucio.core import heartbeat, request
from rucio.core.monitor import record_counter, record_timer
from rucio.daemons.conveyor.submitter_utils import get_rses, get_transfers_from_requests
from rucio.db.sqla.constants import RequestState
from rucio.transfertool import fts3

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def submitter(once=False, rses=[],
              process=0, total_processes=1, thread=0, total_threads=1,
              mock=False, bulk=100, fts_source_strategy='auto',
              activities=None, activity_shares=None, sleep_time=300, max_sources=4):
    """
    Main loop to submit a new transfer primitive to a transfertool.
    """

    logging.info('submitter starting - process (%i/%i) thread (%i/%i)' % (process,
                                                                          total_processes,
                                                                          thread,
                                                                          total_threads))
    try:
        scheme = config_get('conveyor', 'scheme')
    except NoOptionError:
        scheme = None

    executable = ' '.join(sys.argv)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()

    logging.info('submitter started - process (%i/%i) thread (%i/%i)' % (process,
                                                                         total_processes,
                                                                         thread,
                                                                         total_threads))

    activity_next_exe_time = defaultdict(time.time)

    while not graceful_stop.is_set():

        heartbeat.live(executable, hostname, pid, hb_thread)

        try:

            if activities is None:
                activities = [None]
            if rses:
                rse_ids = [rse['id'] for rse in rses]
            else:
                rse_ids = None

            for activity in activities:
                if activity_next_exe_time[activity] > time.time():
                    time.sleep(1)
                    continue

                logging.info("%s:%s Starting to submit jobs on activity: %s" % (process, thread, activity))

                logging.info("%s:%s Starting to get transfers" % (process, thread))
                ts = time.time()
                transfers = get_transfers_from_requests(process, total_processes, thread, total_threads, rse_ids, mock, bulk, activity, activity_shares, scheme, max_sources=max_sources)
                record_timer('daemons.conveyor.submitter.get_transfers_from_requests.per_transfer', (time.time() - ts) * 1000 / (len(transfers) if len(transfers) else 1))
                record_counter('daemons.conveyor.submitter.get_transfers_from_requests', len(transfers))

                logging.info("%s:%s Starting to submit transfers" % (process, thread))
                for request_id in transfers:
                    try:
                        transfer = transfers[request_id]
                        ts = time.time()
                        tmp_metadata = transfer['file_metadata']
                        # Submition time should be calculated before call to submit_transfers()
                        submitted_at = datetime.datetime.utcnow()
                        transfer_ids = fts3.submit_transfers([transfer, ], tmp_metadata)
                        request.set_requests_external(transfer_ids, submitted_at)
                        record_timer('daemons.conveyor.submitter.submit_transfer', (time.time() - ts) * 1000)

                        if 'previous_attempt_id' in transfer['file_metadata']:
                            logging.info('COPYING REQUEST %s PREVIOUS %s DID %s:%s selection_strategy %s FROM %s TO %s USING %s TRANSFERID: %s' % (transfer['request_id'],
                                                                                                                                                   transfer['file_metadata']['previous_attempt_id'],
                                                                                                                                                   transfer['file_metadata']['scope'],
                                                                                                                                                   transfer['file_metadata']['name'],
                                                                                                                                                   fts_source_strategy,
                                                                                                                                                   transfer['sources'],
                                                                                                                                                   transfer['dest_urls'],
                                                                                                                                                   transfer_ids[transfer['request_id']]['external_host'] if transfer['request_id'] in transfer_ids else None,
                                                                                                                                                   transfer_ids[transfer['request_id']]['external_id'] if transfer['request_id'] in transfer_ids else None))
                        else:
                            logging.info('COPYING REQUEST %s DID %s:%s selection_strategy %s FROM %s TO %s USING %s TRANSFERID: %s' % (transfer['request_id'],
                                                                                                                                       transfer['file_metadata']['scope'],
                                                                                                                                       transfer['file_metadata']['name'],
                                                                                                                                       fts_source_strategy,
                                                                                                                                       transfer['sources'],
                                                                                                                                       transfer['dest_urls'],
                                                                                                                                       transfer_ids[transfer['request_id']]['external_host'] if transfer['request_id'] in transfer_ids else None,
                                                                                                                                       transfer_ids[transfer['request_id']]['external_id'] if transfer['request_id'] in transfer_ids else None))
                        if not transfer['request_id'] in transfer_ids:
                            request.set_request_state(transfer['request_id'], RequestState.SUBMITTING)
                            record_counter('daemons.conveyor.submitter.lost_request.%s' % urlparse.urlparse(transfer['external_host']).hostname.replace('.', '_'))
                            logging.warn("Failed to submit request: %s, set request SUBMITTING" % (transfer['request_id']))
                    except UnsupportedOperation, e:
                        # The replica doesn't exist, need to cancel the request
                        logging.warning(e)
                        logging.info('Cancelling transfer request %s' % transfer['request_id'])
                        try:
                            # TODO: for now, there is only ever one destination
                            request.cancel_request_did(transfer['file_metadata']['scope'], transfer['file_metadata']['name'], transfer['dest_urls'][0])
                        except Exception, e:
                            logging.warning('Cannot cancel request: %s' % str(e))
                    except RequestException, e:
                        logging.error("Failed to submit request %s: %s" % (transfer['request_id'], str(e)))
                if len(transfers) < bulk / 2:
                    logging.info("Not enough requests, will sleep % seconds" % sleep_time)
                    if activity_next_exe_time[activity] < time.time():
                        activity_next_exe_time[activity] = time.time() + sleep_time
        except:
            logging.critical(traceback.format_exc())

        if once:
            return

    logging.info('graceful stop requested')

    heartbeat.die(executable, hostname, pid, hb_thread)

    logging.info('graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False,
        process=0, total_processes=1, total_threads=1, fts_source_strategy='auto',
        mock=False, rses=[], include_rses=None, exclude_rses=None, bulk=100,
        activities=[], activity_shares=None, sleep_time=300, max_sources=4):
    """
    Starts up the conveyer threads.
    """

    if mock:
        logging.info('mock source replicas: enabled')

    working_rses = None
    if rses or include_rses or exclude_rses:
        working_rses = get_rses(rses, include_rses, exclude_rses)
        logging.info("RSE selection: RSEs: %s, Include: %s, Exclude: %s" % (rses,
                                                                            include_rses,
                                                                            exclude_rses))
    else:
        logging.info("RSE selection: automatic")

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

        activity_shares.update((share, int(percentage * bulk)) for share, percentage in activity_shares.items())
        logging.info('activity shares enabled: %s' % activity_shares)

    if once:
        logging.info('executing one submitter iteration only')
        submitter(once,
                  rses=working_rses,
                  mock=mock,
                  bulk=bulk,
                  max_sources=max_sources,
                  fts_source_strategy=fts_source_strategy,
                  activities=activities,
                  activity_shares=activity_shares)

    else:
        logging.info('starting submitter threads')
        threads = [threading.Thread(target=submitter, kwargs={'process': process,
                                                              'total_processes': total_processes,
                                                              'thread': i,
                                                              'total_threads': total_threads,
                                                              'rses': working_rses,
                                                              'bulk': bulk,
                                                              'activities': activities,
                                                              'mock': mock,
                                                              'sleep_time': sleep_time,
                                                              'max_sources': max_sources,
                                                              'fts_source_strategy': fts_source_strategy,
                                                              'activity_shares': activity_shares}) for i in xrange(0, total_threads)]

        [t.start() for t in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            [t.join(timeout=3.14) for t in threads if t and t.isAlive()]
