# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

'''
Undertaker is a daemon to manage expired did.
'''

import threading
import time
import traceback

from logging import getLogger, StreamHandler, DEBUG

from rucio.common.exception import DatabaseException
from rucio.core import monitor
from rucio.core.did import list_expired_dids, delete_dids


logger = getLogger("rucio.daemons.undertaker")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

graceful_stop = threading.Event()


def undertaker(worker_number=1, total_workers=1, chunk_size=5, once=False):
    """
    Main loop to select and delete dids.
    """

    print 'Undertaker(%s): starting' % worker_number
    print 'Undertaker(%s): started' % worker_number

    while not graceful_stop.is_set():
        try:
            dids = list_expired_dids(worker_number=worker_number, total_workers=total_workers, limit=chunk_size)
            if not dids:
                print 'Undertaker(%s): Nothing to do. sleep 1.' % worker_number
                time.sleep(1)
            else:
                print 'Undertaker(%s): Receive %s dids to delete' % (worker_number, len(dids))
                delete_dids(dids=dids, account='root')
                print 'Undertaker(%s): Delete %s dids' % (worker_number, len(dids))
                monitor.record_counter(counters='undertaker.delete_dids',  delta=len(dids))
        except DatabaseException, e:
            print 'Undertaker(%s): Got database error %s.' % (worker_number, str(e))
        except:
            print traceback.format_exc()
            time.sleep(1)

        if once:
            break

        time.sleep(0.01)

    print 'Undertaker(%s): graceful stop requested' % worker_number
    print 'Undertaker(%s): graceful stop done' % worker_number


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()


def run(once=False, total_workers=1, chunk_size=10):
    """
    Starts up the undertaker threads.
    """

    print 'main: starting threads'
    threads = [threading.Thread(target=undertaker,  kwargs={'worker_number': i, 'total_workers': total_workers, 'once': once, 'chunk_size': chunk_size}) for i in xrange(1, total_workers+1)]

    [t.start() for t in threads]

    print 'main: waiting for interrupts'

    # Interruptible joins require a timeout.
    while threads[0].is_alive():
        [t.join(timeout=3.14) for t in threads]
