'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2015
  - Mario Lassnig, <mario.lassnig@cern.ch>, 2015
'''

import logging
import os
import re
import socket
import threading
import time

from json import loads
from math import exp
from sys import exc_info, stdout, argv
from traceback import format_exception


from rucio.api.did import list_new_dids, set_new_dids, get_metadata
from rucio.api.subscription import list_subscriptions
from rucio.db.constants import DIDType, SubscriptionState
from rucio.common.exception import (DatabaseException, DataIdentifierNotFound, InvalidReplicationRule, DuplicateRule,
                                    InvalidRSEExpression, InsufficientTargetRSEs, InsufficientAccountLimit, InputValidationError,
                                    ReplicationRuleCreationTemporaryFailed, InvalidRuleWeight, StagingAreaRuleRequiresLifetime)
from rucio.common.config import config_get
from rucio.common.schema import validate_schema
from rucio.common.utils import chunks
from rucio.core import monitor, heartbeat
from rucio.core.rule import add_rule

logging.getLogger("transmogrifier").setLevel(logging.CRITICAL)

logging.basicConfig(stream=stdout, level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def _retrial(func, *args, **kwargs):
    """
    Retrial method
    """
    delay = 0
    while True:
        try:
            return apply(func, args, kwargs)
        except DataIdentifierNotFound, excep:
            logging.warning(excep)
            return 1
        except DatabaseException, excep:
            logging.error(excep)
            if exp(delay) > 600:
                logging.error('Cannot execute %s after %i attempt. Failing the job.' % (func.__name__, delay))
                raise
            else:
                logging.error('Failure to execute %s. Retrial will be done in %d seconds ' % (func.__name__, exp(delay)))
            time.sleep(exp(delay))
            delay += 1
        except:
            exc_type, exc_value, exc_traceback = exc_info()
            logging.critical(''.join(format_exception(exc_type, exc_value, exc_traceback)).strip())
            raise


def is_matching_subscription(subscription, did, metadata):
    """
    Method to identify if a DID matches a subscription.

    param subscription: The subscription dictionnary.
    param did: The DID dictionnary
    param metadata: The metadata dictionnary for the DID
    return: True/False
    """
    if metadata['hidden']:
        return False
    try:
        filter = loads(subscription['filter'])
    except ValueError, excep:
        logging.error('%s : Subscription will be skipped' % excep)
        return False
    # Loop over the keys of filter for subscription
    for key in filter:
        values = filter[key]
        if key == 'pattern':
            if not re.match(values, did['name']):
                return False
        elif key == 'scope':
            match_scope = False
            for scope in values:
                if re.match(scope, did['scope']):
                    match_scope = True
                    break
            if not match_scope:
                return False
        else:
            if type(values) is str or type(values) is unicode:
                values = [values, ]
            has_metadata = False
            for meta in metadata:
                if str(meta) == str(key):
                    has_metadata = True
                    match_meta = False
                    for value in values:
                        if re.match(value, str(metadata[meta])):
                            match_meta = True
                            break
                    if not match_meta:
                        return False
            if not has_metadata:
                return False
    return True


def transmogrifier(thread=0, bulk=5, once=False):
    """
    Creates a Transmogrifier Worker that gets a list of new DIDs for a given hash,
    identifies the subscriptions matching the DIDs and
    submit a replication rule for each DID matching a subscription.

    :param thread: Thread number at startup.
    :param bulk: The number of requests to process.
    :param once: Run only once.
    """

    executable = ' '.join(argv)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)

    while not graceful_stop.is_set():

        hb = heartbeat.live(executable, hostname, pid, hb_thread)

        dids, subscriptions = [], []
        tottime = 0

        try:
            for did in list_new_dids(thread=hb['assign_thread'], total_threads=hb['nr_threads'], chunk_size=bulk):
                dids.append({'scope': did['scope'], 'did_type': str(did['did_type']), 'name': did['name']})

            for sub in list_subscriptions(None, None):
                if sub['state'] in [SubscriptionState.ACTIVE, SubscriptionState.UPDATED]:
                    subscriptions.append(sub)
        except Exception, error:
            logging.error('Thread [%i/%i] : Failed to get list of new DIDs or subscriptions: %s' % (hb['assign_thread'],
                                                                                                    hb['nr_threads'],
                                                                                                    str(error)))

            if once:
                break
            else:
                continue

        try:
            results = {}
            start_time = time.time()
            logging.debug('Thread [%i/%i] : In transmogrifier worker' % (hb['assign_thread'],
                                                                         hb['nr_threads']))
            identifiers = []
            for did in dids:
                if did['did_type'] == str(DIDType.DATASET) or did['did_type'] == str(DIDType.CONTAINER):
                    results['%s:%s' % (did['scope'], did['name'])] = []
                    try:
                        metadata = get_metadata(did['scope'], did['name'])
                        for subscription in subscriptions:
                            if is_matching_subscription(subscription, did, metadata) is True:
                                stime = time.time()
                                results['%s:%s' % (did['scope'], did['name'])].append(subscription['id'])
                                logging.info('Thread [%i/%i] : %s:%s matches subscription %s' % (hb['assign_thread'],
                                                                                                 hb['nr_threads'],
                                                                                                 did['scope'], did['name'],
                                                                                                 subscription['name']))
                                for rule in loads(subscription['replication_rules']):
                                    grouping = rule.get('grouping', 'DATASET')
                                    lifetime = rule.get('lifetime', None)
                                    ignore_availability = rule.get('ignore_availability', None)
                                    if lifetime:
                                        lifetime = int(lifetime)
                                    weight = rule.get('weight', None)
                                    source_replica_expression = rule.get('source_replica_expression', None)
                                    activity = rule.get('activity', None)
                                    try:
                                        validate_schema(name='activity', obj=activity)
                                    except InputValidationError, excep:
                                        logging.error('Error validating the activity %s' % (str(excep)))
                                        activity = 'default'

                                    locked = rule.get('locked', None)
                                    purge_replicas = rule.get('purge_replicas', False)
                                    success = True
                                    nattempt = 5
                                    attemptnr = 0
                                    for attempt in xrange(0, nattempt):
                                        attemptnr = attempt
                                        try:
                                            rse_expression = str(rule['rse_expression']).encode('string-escape')
                                            comment = str(subscription['comments'])
                                            add_rule(dids=[{'scope': did['scope'], 'name': did['name']}], account=subscription['account'], copies=int(rule['copies']), rse_expression=rse_expression,
                                                     grouping=grouping, weight=weight, lifetime=lifetime, locked=locked, subscription_id=subscription['id'], source_replica_expression=source_replica_expression, activity=activity,
                                                     purge_replicas=purge_replicas, ignore_availability=ignore_availability, comment=comment)
                                            monitor.record_counter(counters='transmogrifier.addnewrule.done', delta=1)
                                            if subscription['name'].find('test') > -1:
                                                monitor.record_counter(counters='transmogrifier.addnewrule.activity.test', delta=1)
                                            elif subscription['name'].startswith('group'):
                                                monitor.record_counter(counters='transmogrifier.addnewrule.activity.group', delta=1)
                                            elif subscription['name'].startswith('tier0export'):
                                                monitor.record_counter(counters='transmogrifier.addnewrule.activity.tier0export', delta=1)
                                            elif subscription['name'].endswith('export'):
                                                monitor.record_counter(counters='transmogrifier.addnewrule.activity.dataconsolidation', delta=1)
                                            else:
                                                monitor.record_counter(counters='transmogrifier.addnewrule.activity.other', delta=1)
                                            break
                                        except (InvalidReplicationRule, InvalidRuleWeight, InvalidRSEExpression, StagingAreaRuleRequiresLifetime, InsufficientTargetRSEs, DuplicateRule) as excep:
                                            # These errors shouldn't be retried
                                            logging.error('Thread [%i/%i] : %s' % (hb['assign_thread'],
                                                                                   hb['nr_threads'],
                                                                                   str(excep)))
                                            monitor.record_counter(counters='transmogrifier.addnewrule.errortype.%s' % (str(excep)), delta=1)
                                            break
                                        except (ReplicationRuleCreationTemporaryFailed, InsufficientTargetRSEs, InsufficientAccountLimit) as excep:
                                            logging.error('Thread [%i/%i] : %s' % (hb['assign_thread'],
                                                                                   hb['nr_threads'],
                                                                                   str(excep)))
                                            monitor.record_counter(counters='transmogrifier.addnewrule.errortype.%s' % (str(excep)), delta=1)
                                            break
                                        except DatabaseException, e:
                                            logging.error('Thread [%i/%i] : %s' % (hb['assign_thread'],
                                                                                   hb['nr_threads'],
                                                                                   str(e)))
                                            logging.error('Thread [%i/%i] : Will perform an other attempt %i/%i' % (hb['assign_thread'],
                                                                                                                    hb['nr_threads'],
                                                                                                                    attempt + 1,
                                                                                                                    nattempt))
                                            monitor.record_counter(counters='transmogrifier.addnewrule.errortype.%s' % (str(e)), delta=1)
                                            success = False
                                        except Exception, excep:
                                            monitor.record_counter(counters='transmogrifier.addnewrule.errortype.unknown', delta=1)
                                            exc_type, exc_value, exc_traceback = exc_info()
                                            logging.critical(''.join(format_exception(exc_type, exc_value, exc_traceback)).strip())

                                    if (attemptnr + 1) == nattempt and not success:
                                        logging.critical('Thread [%i/%i] : Rule for %s:%s on %s cannot be inserted' % (hb['assign_thread'],
                                                                                                                       hb['nr_threads'],
                                                                                                                       did['scope'],
                                                                                                                       did['name'],
                                                                                                                       rse_expression))
                                    else:
                                        logging.info('Thread [%i/%i] :Rule inserted in %f seconds' % (hb['assign_thread'],
                                                                                                      hb['nr_threads'],
                                                                                                      time.time()-stime))
                    except DataIdentifierNotFound, error:
                        logging.warning(error)

                if did['did_type'] == str(DIDType.FILE):
                    monitor.record_counter(counters='transmogrifier.did.file.processed', delta=1)
                elif did['did_type'] == str(DIDType.DATASET):
                    monitor.record_counter(counters='transmogrifier.did.dataset.processed', delta=1)
                elif did['did_type'] == str(DIDType.CONTAINER):
                    monitor.record_counter(counters='transmogrifier.did.container.processed', delta=1)
                monitor.record_counter(counters='transmogrifier.did.processed', delta=1)
                identifiers.append({'scope': did['scope'], 'name': did['name'], 'did_type': DIDType.from_sym(did['did_type'])})

            time1 = time.time()

            for identifier in chunks(identifiers, 100):
                _retrial(set_new_dids, identifier, None)

            logging.info('Thread [%i/%i] : Time to set the new flag : %f' % (hb['assign_thread'],
                                                                             hb['nr_threads'],
                                                                             time.time() - time1))
            tottime = time.time() - start_time
            logging.info('Thread [%i/%i] : It took %f seconds to process %i DIDs' % (hb['assign_thread'],
                                                                                     hb['nr_threads'],
                                                                                     tottime, len(dids)))
            logging.debug('Thread [%i/%i] : DIDs processed : %s' % (hb['assign_thread'],
                                                                    hb['nr_threads'],
                                                                    str(dids)))
            monitor.record_counter(counters='transmogrifier.job.done', delta=1)
            monitor.record_timer(stat='transmogrifier.job.duration', time=1000*tottime)
        except Exception:
            exc_type, exc_value, exc_traceback = exc_info()
            logging.critical(''.join(format_exception(exc_type, exc_value, exc_traceback)).strip())
            monitor.record_counter(counters='transmogrifier.job.error', delta=1)
            monitor.record_counter(counters='transmogrifier.addnewrule.error', delta=1)
        logging.info(once)
        if once is True:
            break
        if tottime < 10:
            time.sleep(10-tottime)
    heartbeat.die(executable, hostname, pid, hb_thread)
    logging.info('Thread [%i/%i] : Graceful stop requested' % (hb['assign_thread'],
                                                               hb['nr_threads']))
    logging.info('Thread [%i/%i] : Graceful stop done' % (hb['assign_thread'],
                                                          hb['nr_threads']))


def run(threads=1, bulk=100, once=False):
    """
    Starts up the transmogrifier threads.
    """

    logging.info('starting transmogrifier threads')
    thread_list = [threading.Thread(target=transmogrifier, kwargs={'once': once,
                                                                   'thread': i,
                                                                   'bulk': bulk}) for i in xrange(0, threads)]
    [t.start() for t in thread_list]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while len(thread_list) > 0:
        [t.join(timeout=3.14) for t in thread_list if t and t.isAlive()]


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()
