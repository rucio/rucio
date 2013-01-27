# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

'''
Conveyor is a daemon to manage file transfers
'''

from logging import getLogger, StreamHandler, DEBUG
from random import choice
from sys import exit

from rucio.core import identifier as identifier_core
from rucio.core import rse as rse_core

logger = getLogger("rucio.daemons.Conveyor")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

SUCCESS = 0
FAILURE = 1


# Callback called when you run `supervisorctl stop'
def stop(signum, frame):
    print "Kaboom Baby!"
    exit(SUCCESS)


def run_once():
    """
    List all the file replicas in the UNAVAILABLE state for a destination RSE
    Look-up source replicas
    Select a source
    Instantiate transfers from the selected source,
    i.e. submit to the underlying transfer tool, e.g. FTS
    propagate grouping option (dataset name) and account fairshares
    """
    rses = rse_core.list_rses()
    for rse in rses:
        #print 'Process RSE %(rse)s' % locals()
        replicas = rse_core.list_replicas(rse=rse, filters={'state': 'UNAVAILABLE'})  # grouping options, fairshare
        for replica in replicas:
            print
            print 'Destination: %(scope)s:%(name)s' % replica
            # Get source and select one randomly
            sources = [src for src in identifier_core.list_replicas(scope=replica['scope'], name=replica['name'])]
            if not sources:
                print 'No source replica found for: %(scope)s:%(name)s' % replica
                continue

            source = choice(sources)
            print 'Tranfer file  %(scope)s:%(name)s from RSE %(rse)s' % source
            # transfer_id = transfer (src=source, dest=rse, file={scope:  , name:, pfn=}) # pfn ?,
            rse_core.update_file_replica_state(rse=rse, scope=replica['scope'], name=replica['name'], state='COPYING')
