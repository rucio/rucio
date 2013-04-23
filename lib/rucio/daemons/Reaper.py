# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

'''
Reaper is a daemon to manage file deletion
'''

from logging import getLogger, StreamHandler, DEBUG
from sys import exit

from rucio.core import rse as rse_core

logger = getLogger("rucio.daemons.Reaper")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

SUCCESS = 0
FAILURE = 1


# Callback called when you run `supervisorctl stop'
def stop(signum, frame):
    print "Kaboom Baby!"
    exit(SUCCESS)


def __check_rse_limits(rse):
    limits = rse_core.get_rse_limits(rse=rse, name='MinFreeSpace')
    usage = rse_core.get_rse_usage(rse)

    # ToDO: Get the amount of bytes waiting for deletion to add

    if not usage or not limits:
        return False

    for limit in limits:
        if limit['value'] > usage['free']:
            return limit['value'] - usage['free']  # + bytesWaitingForDeletion

    return False


def run_once():

    for rse in rse_core.list_rses():
        bytes = __check_rse_limits(rse)
        if bytes:
            print 'Freeing up some space(%(bytes)s) on %(rse)s' % locals()
            # select files with no locks for x bytes on RSE
            # submit the files for deletion
