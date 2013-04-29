# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013

'''
Reaper is a daemon to manage file deletion.
'''

import threading
import time
import traceback

from logging import getLogger, StreamHandler, DEBUG

from rucio.core import rse as rse_core
from rucio.rse.rsemanager import RSEMgr

logger = getLogger("rucio.daemons.reaper")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

graceful_stop = threading.Event()


def __check_rse_limits(rse):
    limits = rse_core.get_rse_limits(rse=rse, name='MinFreeSpace')
    usage = rse_core.get_rse_usage(rse)

    # ToDO: Get the amount of bytes waiting for deletion to add
    if not usage or not limits:
        return False, False, False

    free, used = usage['free'], usage['used']
    for limit in limits:
        if limit['value'] > free:
            return limit['value'] - free, used, free  # + bytesWaitingForDeletion

    return False, False, False


def reaper(once=False):
    """
    Main loop to select and delete files.
    """

    print 'Reaper: starting'

    rsemgr = RSEMgr(server_mode=True, server_mode_with_credentials=True)

    print 'Reaper: started'

    while not graceful_stop.is_set():
        try:
            for rse in rse_core.list_rses():
                bytes, used, free = __check_rse_limits(rse)
                if bytes:
                    print 'Freeing up some space(%(bytes)s) on %(rse)s' % locals()
                    replicas = rse_core.list_unlocked_replicas(rse=rse, bytes=bytes)
                    # Race conditions with locks
                    freed_space = 0
                    for replica in replicas:
                        print 'Delete the file %(scope)s:%(name)s' % replica
                        # Should deleguate the deletion to a backend for persistency and retrial
                        rsemgr.delete(rse_id=rse, lfns=[{'scope': replica['scope'], 'filename': replica['name']}, ])
                        print 'Remove file replica information with size %(size)s for file %(scope)s:%(name)s' % replica
                        # Remove file replica information : Check replica locks ?
                        rse_core.del_file_replica(rse=rse, scope=replica['scope'], name=replica['name'])
                        freed_space += replica['size']
                    print 'RSE: %(rse)s, Freed space: %(freed_space)s, Needed freed space: %(bytes)s' % locals()
                    # Update RSE space usage information
                    rse_core.set_rse_usage(rse='MOCK', source='srm', used=used-freed_space, free=free+freed_space)
        except:
            print traceback.format_exc()

        if once:
            break
        time.sleep(1)

    print 'reaper: graceful stop requested'

    print 'reaper: graceful stop done'


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()


def run(once=False):
    """
    Starts up the reaper threads.
    """

    if once:
        print 'main: executing one iteration only'
        reaper(once)

    else:

        print 'main: starting threads'

        threads = [threading.Thread(target=reaper), ]

        [t.start() for t in threads]

        print 'main: waiting for interrupts'

        # Interruptible joins require a timeout.
        while threads[0].is_alive() and threads[1].is_alive():
            [t.join(timeout=3.14) for t in threads]
