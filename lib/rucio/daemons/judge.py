# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2013

"""
Judge is a daemon to re-evaluate and execute replication rules.
"""

import threading
import time
import traceback

from rucio.core.rule import re_evaluate_did, delete_expired_rule

graceful_stop = threading.Event()


def re_evaluator(once=False, worker_number=1, total_workers=1):
    """
    Main loop to check the re-evaluation of dids.
    """

    print 're_evaluator: starting'

    print 're_evaluator: started'

    wait = False
    while not graceful_stop.is_set():
        try:
            start_time = time.time()
            wait = re_evaluate_did(worker_number=worker_number, total_workers=total_workers)
            print 'Evaluation took %f' % (time.time() - start_time)
        except:
            print traceback.format_exc()
        if once:
            return
        if not wait:
            time.sleep(10)  # TODO get from config

    print 're_evaluator: graceful stop requested'

    print 're_evaluator: graceful stop done'


def rule_cleaner(once=False, worker_number=1, total_workers=1,):
    """
    Main loop to check for expired replication rules
    """

    print 'rule_cleaner: starting'

    print 'rule_cleaner: started'

    wait = False
    while not graceful_stop.is_set():
        try:
            wait = delete_expired_rule(worker_number=worker_number, total_workers=total_workers)
        except:
            print traceback.format_exc()

        if once:
            return
        if not wait:
            time.sleep(10)  # TODO get from config

    print 'rule_cleaner: graceful stop requested'

    print 'rule_cleaner: graceful stop done'


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, re_evaluate_workers=1, cleaner_workers=1):
    """
    Starts up the Judge thread.
    """

    if once:
        print 'main: executing one iteration only'
        re_evaluator(once)
        rule_cleaner(once)
    else:
        print 'main: starting threads'
        threads = [threading.Thread(target=re_evaluator, kwargs={'worker_number': i, 'total_workers': re_evaluate_workers, 'once': once}) for i in xrange(1, re_evaluate_workers+1)]
        threads.extend([threading.Thread(target=rule_cleaner, kwargs={'worker_number': i, 'total_workers': cleaner_workers, 'once': once}) for i in xrange(1, cleaner_workers+1)])

        [t.start() for t in threads]
        print 'main: waiting for interrupts'
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
