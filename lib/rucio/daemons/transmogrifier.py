# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2014


import logging
import re
import threading
import time

from json import loads
from math import exp
from sys import exc_info, stdout
from traceback import format_exception


from rucio.api.did import list_new_dids, set_new_dids, get_metadata
from rucio.api.rule import add_replication_rule
from rucio.api.subscription import list_subscriptions
from rucio.db.constants import DIDType, SubscriptionState
from rucio.common.exception import DatabaseException, DataIdentifierNotFound, InvalidReplicationRule, InvalidRSEExpression, InsufficientTargetRSEs, InsufficientAccountLimit
from rucio.common.config import config_get
from rucio.common.utils import chunks
from rucio.core import monitor


logging.getLogger("transmogrifier").setLevel(logging.CRITICAL)

logging.basicConfig(stream=stdout, level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def _retrial(func, *args, **kwargs):
    delay = 0
    while True:
        try:
            return apply(func, args, kwargs)
        except DataIdentifierNotFound, e:
            logging.warning(e)
            return 1
        except DatabaseException, e:
            logging.error(e)
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
    # filter = subscription['filter']
    try:
        filter = loads(subscription['filter'])
    except ValueError, e:
        logging.error('%s : Subscription will be skipped' % e)
        return False
    # Loop over the keys of filter for subscription
    for key in filter:
        values = filter[key]
        if key == 'pattern':
            if not re.match(values, did['name']):
                return False
        elif key == 'scope':
            if not did['scope'] in values:
                return False
        else:
            if type(values) is str or type(values) is unicode:
                values = [values, ]
            has_metadata = 0
            for meta in metadata:
                if str(meta) == str(key):
                    has_metadata = 1
                    if not metadata[meta] in values:
                        return False
            if has_metadata == 0:
                return False
    return True


def transmogrifier(worker_number=1, total_workers=1, chunk_size=5, once=False):
    """
    Creates a Transmogrifier Worker that gets a list of new DIDs for a given hash, identifies the subscriptions matching the DIDs and submit a replication rule for each DID matching a subscription.

    param worker_number: The number of the worker (thread).
    param total_number: The total number of workers (threads).
    chunk_size: The chunk of the size to process.
    once: To run only once
    """
    while not graceful_stop.is_set():
        dids, subscriptions = [], []
        tottime = 0
        try:
            for did in list_new_dids(worker_number=worker_number, total_workers=total_workers, chunk_size=chunk_size):
                d = {'scope': did['scope'], 'did_type': str(did['did_type']), 'name': did['name']}
                dids.append(d)
            for sub in list_subscriptions(None, None):
                if sub['state'] in [SubscriptionState.ACTIVE, SubscriptionState.UPDATED]:
                    subscriptions.append(sub)
        except:
            logging.error('Thread %i : Failed to get list of new DIDs or subsscriptions' % (worker_number))
            if once:
                break
            else:
                continue

        try:
            results = {}
            start_time = time.time()
            logging.debug('Thread %i : In transmogrifier worker' % (worker_number))
            identifiers = []
            for did in dids:
                if (did['did_type'] == str(DIDType.DATASET) or did['did_type'] == str(DIDType.CONTAINER)):
                    results['%s:%s' % (did['scope'], did['name'])] = []
                    try:
                        metadata = get_metadata(did['scope'], did['name'])
                        for subscription in subscriptions:
                            if is_matching_subscription(subscription, did, metadata) is True:
                                stime = time.time()
                                results['%s:%s' % (did['scope'], did['name'])].append(subscription['id'])
                                logging.info('Thread %i : %s:%s matches subscription %s' % (worker_number, did['scope'], did['name'], subscription['name']))
                                for rule in loads(subscription['replication_rules']):
                                    try:
                                        grouping = rule['grouping']
                                    except:
                                        grouping = 'DATASET'
                                    try:
                                        lifetime = int(rule['lifetime'])
                                    except:
                                        lifetime = None
                                    try:
                                        rse_expression = str(rule['rse_expression']).encode('string-escape')
                                        add_replication_rule(dids=[{'scope': did['scope'], 'name': did['name']}], account=subscription['account'], copies=int(rule['copies']), rse_expression=rse_expression,
                                                             grouping=grouping, weight=None, lifetime=lifetime, locked=False, subscription_id=subscription['id'], issuer='root')
                                        monitor.record_counter(counters='transmogrifier.addnewrule.done',  delta=1)
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
                                    except InvalidReplicationRule, e:
                                        logging.error('Thread %i : %s' % (worker_number, str(e)))
                                        monitor.record_counter(counters='transmogrifier.addnewrule.error', delta=1)
                                        monitor.record_counter(counters='transmogrifier.addnewrule.errortype.InvalidReplicationRule', delta=1)
                                    except InvalidRSEExpression, e:
                                        logging.error('Thread %i : %s' % (worker_number, str(e)))
                                        monitor.record_counter(counters='transmogrifier.addnewrule.error', delta=1)
                                        monitor.record_counter(counters='transmogrifier.addnewrule.errortype.InvalidRSEExpression', delta=1)
                                    except InsufficientTargetRSEs, e:
                                        # For the future might need a retry
                                        logging.error('Thread %i : %s' % (worker_number, str(e)))
                                        monitor.record_counter(counters='transmogrifier.addnewrule.error', delta=1)
                                        monitor.record_counter(counters='transmogrifier.addnewrule.errortype.InsufficientTargetRSEs', delta=1)
                                    except InsufficientAccountLimit, e:
                                        # For the future might need a retry
                                        logging.error('Thread %i : %s' % (worker_number, str(e)))
                                        monitor.record_counter(counters='transmogrifier.addnewrule.error', delta=1)
                                        monitor.record_counter(counters='transmogrifier.addnewrule.errortype.InsufficientAccountLimit', delta=1)
                                    except Exception, e:
                                        monitor.record_counter(counters='transmogrifier.addnewrule.error', delta=1)
                                        monitor.record_counter(counters='transmogrifier.addnewrule.errortype.unknown', delta=1)
                                        exc_type, exc_value, exc_traceback = exc_info()
                                        logging.critical(''.join(format_exception(exc_type, exc_value, exc_traceback)).strip())
                                logging.info('Thread %i :Rule inserted in %f seconds' % (worker_number, time.time()-stime))
                    except DataIdentifierNotFound, e:
                        logging.warning(e)
                if did['did_type'] == str(DIDType.FILE):
                    monitor.record_counter(counters='transmogrifier.did.file.processed',  delta=1)
                elif did['did_type'] == str(DIDType.DATASET):
                    monitor.record_counter(counters='transmogrifier.did.dataset.processed',  delta=1)
                elif did['did_type'] == str(DIDType.CONTAINER):
                    monitor.record_counter(counters='transmogrifier.did.container.processed',  delta=1)
                monitor.record_counter(counters='transmogrifier.did.processed',  delta=1)
                identifiers.append({'scope': did['scope'], 'name': did['name'], 'did_type': DIDType.from_sym(did['did_type'])})
            time1 = time.time()
            for id in chunks(identifiers, 100):
                _retrial(set_new_dids, id, None)
            logging.info('Thread %i : Time to set the new flag : %f' % (worker_number, time.time() - time1))
            tottime = time.time() - start_time
            logging.info('Thread %i : It took %f seconds to process %i DIDs' % (worker_number, tottime, len(dids)))
            logging.debug('Thread %i : DIDs processed : %s' % (worker_number, str(dids)))
            monitor.record_counter(counters='transmogrifier.job.done',  delta=1)
            monitor.record_timer(stat='transmogrifier.job.duration',  time=1000*tottime)
        except:
            exc_type, exc_value, exc_traceback = exc_info()
            logging.critical(''.join(format_exception(exc_type, exc_value, exc_traceback)).strip())
            monitor.record_counter(counters='transmogrifier.job.error',  delta=1)
            monitor.record_counter(counters='transmogrifier.addnewrule.error',  delta=1)
        logging.info(once)
        if once is True:
            break
        if tottime < 10:
            time.sleep(10-tottime)
    logging.info('Thread %i : Graceful stop requested' % (worker_number))
    logging.info('Thread %i : Graceful stop done' % (worker_number))


def run(total_workers=1, chunk_size=100, once=False):
    """
    Starts up the transmogrifier threads.
    """

    threads = list()
    for worker_number in xrange(0, total_workers):
        kwargs = {'worker_number': worker_number + 1,
                  'total_workers': total_workers,
                  'once': once,
                  'chunk_size': chunk_size}
        threads.append(threading.Thread(target=transmogrifier, kwargs=kwargs))
    [t.start() for t in threads]
    while threads[0].is_alive():
        logging.info('Still %i active threads' % len(threads))
        [t.join(timeout=3.14) for t in threads]


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()
