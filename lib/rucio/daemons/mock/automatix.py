# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

"""
Automatix is a daemon to queue file transfers for testing purposes.
"""

import threading
import time
import traceback

from rucio.common.exception import Duplicate
from rucio.common.utils import generate_uuid
from rucio.core import did, rse, scope, request

graceful_stop = threading.Event()


def request_transfer(once=False):
    """
    Main loop to request a new transfer.
    """

    print 'request: starting'

    print 'request: started'

    while not graceful_stop.is_set():

        try:
            print 'request: create new scope-dataset-file and request transfer'

            tmp_scope = generate_uuid()[:3]  # distribute between 1000 scopes
            tmp_name = generate_uuid()

            try:
                scope.add_scope(tmp_scope, 'root')  # ignore existing scopes
            except Duplicate:
                pass

            did.add_identifier(scope=tmp_scope, name='dataset-%s' % tmp_name, type='dataset', issuer='root')
            rse.add_file_replica(rse='MOCK', scope=tmp_scope, name='file-%s' % tmp_name, size=1, issuer='root')
            did.append_identifier(scope=tmp_scope, name='dataset-%s' % tmp_name, dids=[{'scope': tmp_scope, 'name': 'file-%s' % tmp_name}], issuer='root')

            request.queue_request(tmp_scope, 'file-%s' % tmp_name, 'MOCK3', 'TRANSFER', {'random': 'metadata'})

        except:
            print traceback.format_exc()

        if once:
            return

        time.sleep(1)

    print 'request: graceful stop requested'

    print 'request: graceful stop done'


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False):
    """
    Starts up automatix threads
    """

    if once:
        print 'main: executing one iteration only'
        request_transfer(once)

    else:

        print 'main: starting thread'

        thread = threading.Thread(target=request_transfer)

        thread.start()

        print 'main: waiting for interrupts'

        # Interruptible joins require a timeout.
        while thread.is_alive():
            thread.join(timeout=3.14)
