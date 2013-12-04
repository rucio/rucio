# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

"""
ConveyorInjector is a daemon to queue file transfers for testing purposes.
"""

import logging
import sys
import threading
import time
import traceback

from rucio.common.config import config_get
from rucio.common.utils import generate_uuid
from rucio.core import did, rse, request
from rucio.core.monitor import record_counter, record_timer
from rucio.db.constants import DIDType, RequestType
from rucio.db.session import get_session

logging.getLogger("requests").setLevel(logging.CRITICAL)

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def request_transfer(once=False, process=0, total_processes=1, thread=0, total_threads=1):
    """
    Main loop to request a new transfer.
    """

    logging.info('request: starting')

    session = get_session()

    logging.info('request: started')

    while not graceful_stop.is_set():

        try:

            ts = time.time()

            tmp_name = generate_uuid()

            did.add_did(scope='mock', name='dataset-%s' % tmp_name,
                        type=DIDType.DATASET, account='root', session=session)

            rse.add_replica(rse='MOCK', scope='mock', name='file-%s' % tmp_name,
                            bytes=1, account='root', session=session)

            did.attach_dids(scope='mock', name='dataset-%s' % tmp_name, dids=[{'scope': 'mock',
                                                                               'name': 'file-%s' % tmp_name,
                                                                               'bytes': 1234}],
                            account='root', session=session)

            request.queue_request('mock', 'file-%s' % tmp_name, rse.get_rse('MOCK3')['id'],
                                  RequestType.TRANSFER, {'random': 'metadata'}, session=session)

            logging.info('inserted transfer request for DID mock:%s' % tmp_name)

            record_timer('daemons.mock.conveyorinjector.request_transfer', (time.time()-ts)*1000)

            record_counter('daemons.mock.conveyorinjector.request_transfer')

            session.commit()
        except:
            session.rollback()
            logging.critical(traceback.format_exc())

        if once:
            return

    logging.info('request: graceful stop requested')

    logging.info('request: graceful stop done')


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
        logging.info('executing one conveyorinjector iteration only')
        request_transfer(once)

    else:

        logging.info('starting conveyorinjector threads')
        threads = [threading.Thread(target=request_transfer, kwargs={'process': process, 'total_processes': total_processes, 'thread': i, 'total_threads': total_threads}) for i in xrange(0, total_threads)]

        [t.start() for t in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while len(threads) > 0:
            [t.join(timeout=3.14) for t in threads if t is not None and t.isAlive()]
