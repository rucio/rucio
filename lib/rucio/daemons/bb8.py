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

from datetime import datetime

from rucio.core.heartbeat import live, die, sanity_check
from rucio.core.rule import get_rule, add_rule, update_rule
from rucio.common.config import config_get

graceful_stop = threading.Event()

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


def rebalance_rule(parent_rule_id, activity, rse_expression):
    """
    Rebalance a replication rule to a new RSE

    :param parent_rule_id:       Replication rule to be rebalanced.
    :param activity:             Activity to be used for the rebalancing.
    :param rse_expression:       RSE expression of the new rule.
    :returns:                    The new child rule id.
    """
    parent_rule = get_rule(rule_id=parent_rule_id)

    if parent_rule['expires_at'] is None:
        lifetime = None
    else:
        lifetime = (datetime.utcnow() - parent_rule['expires_at']).days * 24 * 3600 + (datetime.utcnow() - parent_rule['expires_at']).seconds

    child_rule = add_rule(dids=[{'scope': parent_rule['scope'],
                                 'name': parent_rule['name']}],
                          account=parent_rule['account'],
                          coppies=parent_rule['copies'],
                          rse_expression=rse_expression,
                          grouping=parent_rule['grouping'],
                          weight=parent_rule['weight'],
                          lifetime=lifetime,
                          locked=parent_rule['locked'],
                          subscription_id=parent_rule['subscription_id'],
                          source_replica_expression=None,
                          activity=activity,
                          notify=parent_rule['notify'],
                          purge_replicas=parent_rule['purge_replicas'],
                          ignore_availability=True,
                          comment=parent_rule['comment'],
                          ask_approval=False,
                          asynchronous=False)[0]

    update_rule(rule_id=parent_rule_id, options={'child_rule_id': child_rule, 'lifetime': 1})
    return child_rule


def rule_rebalancer(once=False):
    """
    Main loop to rebalancer rules automatically
    """
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

    graceful_stop.set()


def run(once=False, threads=1):
    """
    Starts up the Judge-Clean threads.
    """

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
