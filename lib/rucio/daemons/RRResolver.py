# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Replication Rule Resolver Daemon
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013

from logging import getLogger, StreamHandler, DEBUG
#from random import choice
from sys import exit

#from rucio.core import rule
#from rucio.core import rse

logger = getLogger("rucio.daemons.RRResolver")
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
    This process might be done asynchronously in a daemon.
    For the time being, this will be done synchronously in the add_replication_rule method.
    """
    pass
    #rules = rule.list_replication_rules(filters={'state': 'waiting'})
    #for r in rules:
    #    print
    #    print 'Process replication rule %(id)s for did %(scope)s:%(did)s and account %(account)s' % r
    #    print 'Parse rse_expression: %(rse_expression)s' % r
        # Resolve the rse_expression in a list of RSE
    #     filters = {}
    #    for exp in r['rse_expression'].split('and'):
    #        k, v = exp.split('=')
    #        filters[k] = v
    #    rses = rse.list_rses(filters=filters)

        # Apply the weight ? disk space ? quotas ? grouping (dataset for now) ?

        # Generate the replica locks
    #    did_locks = list()
    #    print 'Select %(copies)s did replica locks' % r
    #    for i in xrange(r['copies']):
    #        selected_rse = choice(rses)
    #        rses.remove(selected_rse)
    #        did_lock = {'id': r['id'], 'scope': r['scope'], 'did': r['did'], 'rse': selected_rse, 'account': r['account']}
    #        did_locks.append(did_lock)

    #    rule.add_replica_locks(locks=did_locks)
