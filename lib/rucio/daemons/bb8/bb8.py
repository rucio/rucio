# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2016

"""
BB8 is a daemon the re-balance data between RSEs.
"""

import logging
import socket
import threading
import sys
import os


from rucio.core.heartbeat import live, die, sanity_check
from rucio.common.config import config_get

graceful_stop = threading.Event()

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


def rule_rebalancer(once=False):
    """
    Main loop to rebalancer rules automatically
    """

    raise NotImplementedError()

    hostname = socket.gethostname()
    pid = os.getpid()
    current_thread = threading.current_thread()

    # Make an initial heartbeat so that all have the correct worker number on the next try
    live(executable='rucio-bb8', hostname=hostname, pid=pid, thread=current_thread)
    graceful_stop.wait(1)

    while not graceful_stop.is_set():
        pass
        if once:
            break

    die(executable='rucio-bb8', hostname=hostname, pid=pid, thread=current_thread)


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    raise NotImplementedError()

    graceful_stop.set()


def run(once=False, threads=1):
    """
    Starts up the Judge-Clean threads.
    """

    raise NotImplementedError()

    hostname = socket.gethostname()
    sanity_check(executable='rucio-bb8', hostname=hostname)

    if once:
        rule_rebalancer(once)
    else:
        logging.info('BB8 starting %s threads' % str(threads))
        threads = [threading.Thread(target=rule_rebalancer, kwargs={'once': once}) for i in xrange(0, threads)]
        [t.start() for t in threads]
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
