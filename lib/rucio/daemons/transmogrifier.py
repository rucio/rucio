'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2016
  - Mario Lassnig, <mario.lassnig@cern.ch>, 2015
  - Martin Barisits, <martin.barisits@cern.ch>, 2017
'''

import logging
import os
import re
import socket
import threading
import time

from datetime import datetime
from json import loads
from math import exp
from sys import exc_info, stdout, argv
from traceback import format_exception


from rucio.api.did import list_new_dids, set_new_dids, get_metadata
from rucio.api.subscription import list_subscriptions, update_subscription
from rucio.db.sqla.constants import DIDType, SubscriptionState
from rucio.common.exception import (DatabaseException, DataIdentifierNotFound, InvalidReplicationRule, DuplicateRule, RSEBlacklisted,
                                    InvalidRSEExpression, InsufficientTargetRSEs, InsufficientAccountLimit, InputValidationError,
                                    ReplicationRuleCreationTemporaryFailed, InvalidRuleWeight, StagingAreaRuleRequiresLifetime, SubscriptionNotFound)
from rucio.common.config import config_get
from rucio.common.schema import validate_schema
from rucio.common.utils import chunks
from rucio.core import monitor, heartbeat
from rucio.core.rse import list_rses
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rse_selector import RSESelector
from rucio.core.rule import add_rule, list_rules


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
        except DataIdentifierNotFound, error:
            logging.warning(error)
            return 1
        except DatabaseException, error:
            logging.error(error)
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
    except ValueError, error:
        logging.error('%s : Subscription will be skipped' % error)
        return False
    # Loop over the keys of filter for subscription
    for key in filter:
        values = filter[key]
        if key == 'pattern':
            if not re.match(values, did['name']):
                return False
        elif key == 'excluded_pattern':
            if re.match(values, did['name']):
                return False
        elif key == 'split_rule':
            pass
        elif key == 'scope':
            match_scope = False
            for scope in values:
                if re.match(scope, did['scope']):
                    match_scope = True
                    break
            if not match_scope:
                return False
        else:
            if type(values) is not list:
                values = [values, ]
            has_metadata = False
            for meta in metadata:
                if str(meta) == str(key):
                    has_metadata = True
                    match_meta = False
                    for value in values:
                        if re.match(str(value), str(metadata[meta])):
                            match_meta = True
                            break
                    if not match_meta:
                        return False
            if not has_metadata:
                return False
    return True


def transmogrifier(bulk=5, once=False):
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

        heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)

        dids, subscriptions = [], []
        tottime = 0
        prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'] + 1, heart_beat['nr_threads'])

        try:
            for did in list_new_dids(thread=heart_beat['assign_thread'], total_threads=heart_beat['nr_threads'], chunk_size=bulk):
                dids.append({'scope': did['scope'], 'did_type': str(did['did_type']), 'name': did['name']})

            sub_dict = {3: []}
            for sub in list_subscriptions(None, None):
                if sub['state'] != SubscriptionState.INACTIVE and sub['lifetime'] and (datetime.now() > sub['lifetime']):
                    update_subscription(name=sub['name'], account=sub['account'], state=SubscriptionState.INACTIVE)

                elif sub['state'] in [SubscriptionState.ACTIVE, SubscriptionState.UPDATED]:
                    priority = 3
                    if 'policyid' in sub:
                        if int(sub['policyid']) not in sub_dict:
                            sub_dict[int(sub['policyid'])] = []
                        priority = int(sub['policyid'])
                    sub_dict[priority].append(sub)
            priorities = sub_dict.keys()
            priorities.sort()
            for priority in priorities:
                subscriptions.extend(sub_dict[priority])
        except SubscriptionNotFound, error:
            logging.warning(prepend_str + 'No subscriptions defined: %s' % (str(error)))
            time.sleep(10)
            continue
        except Exception, error:
            logging.error(prepend_str + 'Failed to get list of new DIDs or subscriptions: %s' % (str(error)))

            if once:
                break
            else:
                continue

        try:
            results = {}
            start_time = time.time()
            blacklisted_rse_id = [rse['id'] for rse in list_rses({'availability_write': False})]
            logging.debug(prepend_str + 'In transmogrifier worker')
            identifiers = []
            for did in dids:
                did_success = True
                if did['did_type'] == str(DIDType.DATASET) or did['did_type'] == str(DIDType.CONTAINER):
                    results['%s:%s' % (did['scope'], did['name'])] = []
                    try:
                        metadata = get_metadata(did['scope'], did['name'])
                        for subscription in subscriptions:
                            if is_matching_subscription(subscription, did, metadata) is True:
                                filter = loads(subscription['filter'])
                                split_rule = filter.get('split_rule', False)
                                if split_rule == 'true':
                                    split_rule = True
                                elif split_rule == 'false':
                                    split_rule = False
                                stime = time.time()
                                results['%s:%s' % (did['scope'], did['name'])].append(subscription['id'])
                                logging.info(prepend_str + '%s:%s matches subscription %s' % (did['scope'], did['name'], subscription['name']))
                                for rule in loads(subscription['replication_rules']):
                                    # Get all the rule and subscription parameters
                                    grouping = rule.get('grouping', 'DATASET')
                                    lifetime = rule.get('lifetime', None)
                                    ignore_availability = rule.get('ignore_availability', None)
                                    weight = rule.get('weight', None)
                                    source_replica_expression = rule.get('source_replica_expression', None)
                                    locked = rule.get('locked', None)
                                    if locked == 'True':
                                        locked = True
                                    else:
                                        locked = False
                                    purge_replicas = rule.get('purge_replicas', False)
                                    if purge_replicas == 'True':
                                        purge_replicas = True
                                    else:
                                        purge_replicas = False
                                    rse_expression = str(rule['rse_expression'])
                                    comment = str(subscription['comments'])
                                    subscription_id = str(subscription['id'])
                                    account = subscription['account']
                                    copies = int(rule['copies'])
                                    activity = rule.get('activity', 'User Subscriptions')
                                    try:
                                        validate_schema(name='activity', obj=activity)
                                    except InputValidationError, error:
                                        logging.error(prepend_str + 'Error validating the activity %s' % (str(error)))
                                        activity = 'User Subscriptions'
                                    if lifetime:
                                        lifetime = int(lifetime)

                                    str_activity = "".join(activity.split())
                                    success = False
                                    nattempt = 5
                                    attemptnr = 0
                                    skip_rule_creation = False

                                    if split_rule:
                                        rses = parse_expression(rse_expression)
                                        list_of_rses = [rse['rse'] for rse in rses]
                                        # Check that some rule doesn't already exist for this DID and subscription
                                        preferred_rse_ids = []
                                        for rule in list_rules(filters={'subscription_id': subscription_id, 'scope': did['scope'], 'name': did['name']}):
                                            already_existing_rses = [(rse['rse'], rse['id']) for rse in parse_expression(rule['rse_expression'])]
                                            for rse, rse_id in already_existing_rses:
                                                if (rse in list_of_rses) and (rse_id not in preferred_rse_ids):
                                                    preferred_rse_ids.append(rse_id)
                                        if len(preferred_rse_ids) >= copies:
                                            skip_rule_creation = True

                                        rse_id_dict = {}
                                        for rse in rses:
                                            rse_id_dict[rse['id']] = rse['rse']
                                        try:
                                            rseselector = RSESelector(account=account, rses=rses, weight=weight, copies=copies - len(preferred_rse_ids))
                                            selected_rses = [rse_id_dict[rse_id] for rse_id, _, _ in rseselector.select_rse(0, preferred_rse_ids=preferred_rse_ids, copies=copies, blacklist=blacklisted_rse_id)]
                                        except (InsufficientTargetRSEs, InsufficientAccountLimit, InvalidRuleWeight) as error:
                                            logging.warning(prepend_str + 'Problem getting RSEs for subscription "%s" for account %s : %s. Try including blacklisted sites' %
                                                            (subscription['name'], account, str(error)))
                                            # Now including the blacklisted sites
                                            try:
                                                rseselector = RSESelector(account=account, rses=rses, weight=weight, copies=copies - len(preferred_rse_ids))
                                                selected_rses = [rse_id_dict[rse_id] for rse_id, _, _ in rseselector.select_rse(0, preferred_rse_ids=preferred_rse_ids, copies=copies, blacklist=[])]
                                                ignore_availability = True
                                            except (InsufficientTargetRSEs, InsufficientAccountLimit, InvalidRuleWeight) as error:
                                                logging.error(prepend_str + 'Problem getting RSEs for subscription "%s" for account %s : %s. Skipping rule creation.' %
                                                              (subscription['name'], account, str(error)))
                                                monitor.record_counter(counters='transmogrifier.addnewrule.errortype.%s' % (str(error.__class__.__name__)), delta=1)
                                                # The DID won't be reevaluated at the next cycle
                                                did_success = did_success and True
                                                continue

                                    for attempt in xrange(0, nattempt):
                                        attemptnr = attempt
                                        nb_rule = 0
                                        try:
                                            if split_rule:
                                                if not skip_rule_creation:
                                                    for rse in selected_rses:
                                                        logging.info(prepend_str + 'Will insert one rule for %s:%s on %s' % (did['scope'], did['name'], rse))
                                                        add_rule(dids=[{'scope': did['scope'], 'name': did['name']}], account=account, copies=1,
                                                                 rse_expression=rse, grouping=grouping, weight=weight, lifetime=lifetime, locked=locked,
                                                                 subscription_id=subscription_id, source_replica_expression=source_replica_expression, activity=activity,
                                                                 purge_replicas=purge_replicas, ignore_availability=ignore_availability, comment=comment)

                                                        nb_rule += 1
                                                        if nb_rule == copies:
                                                            success = True
                                                            break
                                            else:
                                                add_rule(dids=[{'scope': did['scope'], 'name': did['name']}], account=account, copies=copies,
                                                         rse_expression=rse_expression, grouping=grouping, weight=weight, lifetime=lifetime, locked=locked,
                                                         subscription_id=subscription['id'], source_replica_expression=source_replica_expression, activity=activity,
                                                         purge_replicas=purge_replicas, ignore_availability=ignore_availability, comment=comment)
                                                nb_rule += 1
                                            monitor.record_counter(counters='transmogrifier.addnewrule.done', delta=nb_rule)
                                            monitor.record_counter(counters='transmogrifier.addnewrule.activity.%s' % str_activity, delta=nb_rule)
                                            success = True
                                            break
                                        except (InvalidReplicationRule, InvalidRuleWeight, InvalidRSEExpression, StagingAreaRuleRequiresLifetime, DuplicateRule) as error:
                                            # Errors that won't be retried
                                            success = True
                                            logging.error(prepend_str + '%s' % (str(error)))
                                            monitor.record_counter(counters='transmogrifier.addnewrule.errortype.%s' % (str(error.__class__.__name__)), delta=1)
                                            break
                                        except (ReplicationRuleCreationTemporaryFailed, InsufficientTargetRSEs, InsufficientAccountLimit, DatabaseException, RSEBlacklisted) as error:
                                            # Errors to be retried
                                            logging.error(prepend_str + '%s Will perform an other attempt %i/%i' % (str(error), attempt + 1, nattempt))
                                            monitor.record_counter(counters='transmogrifier.addnewrule.errortype.%s' % (str(error.__class__.__name__)), delta=1)
                                        except Exception, error:
                                            # Unexpected errors
                                            monitor.record_counter(counters='transmogrifier.addnewrule.errortype.unknown', delta=1)
                                            exc_type, exc_value, exc_traceback = exc_info()
                                            logging.critical(prepend_str + ''.join(format_exception(exc_type, exc_value, exc_traceback)).strip())

                                    did_success = (did_success and success)
                                    if (attemptnr + 1) == nattempt and not success:
                                        logging.error(prepend_str + 'Rule for %s:%s on %s cannot be inserted' % (did['scope'], did['name'], rse_expression))
                                    else:
                                        logging.info(prepend_str + '%s rule(s) inserted in %f seconds' % (str(nb_rule), time.time() - stime))
                    except DataIdentifierNotFound, error:
                        logging.warning(prepend_str + error)

                if did_success:
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

            logging.info(prepend_str + 'Time to set the new flag : %f' % (time.time() - time1))
            tottime = time.time() - start_time
            logging.info(prepend_str + 'It took %f seconds to process %i DIDs' % (tottime, len(dids)))
            logging.debug(prepend_str + 'DIDs processed : %s' % (str(dids)))
            monitor.record_counter(counters='transmogrifier.job.done', delta=1)
            monitor.record_timer(stat='transmogrifier.job.duration', time=1000 * tottime)
        except Exception:
            exc_type, exc_value, exc_traceback = exc_info()
            logging.critical(prepend_str + ''.join(format_exception(exc_type, exc_value, exc_traceback)).strip())
            monitor.record_counter(counters='transmogrifier.job.error', delta=1)
            monitor.record_counter(counters='transmogrifier.addnewrule.error', delta=1)
        if once is True:
            break
        if tottime < 10:
            time.sleep(10 - tottime)
    heartbeat.die(executable, hostname, pid, hb_thread)
    logging.info(prepend_str + 'Graceful stop requested')
    logging.info(prepend_str + 'Graceful stop done')


def run(threads=1, bulk=100, once=False):
    """
    Starts up the transmogrifier threads.
    """

    if once:
        logging.info('Will run only one iteration in a single threaded mode')
        transmogrifier(bulk=bulk, once=once)
    else:
        logging.info('starting transmogrifier threads')
        thread_list = [threading.Thread(target=transmogrifier, kwargs={'once': once,
                                                                       'bulk': bulk}) for _ in xrange(0, threads)]
        [t.start() for t in thread_list]
        logging.info('waiting for interrupts')
        # Interruptible joins require a timeout.
        while len(thread_list) > 0:
            thread_list = [t.join(timeout=3.14) for t in thread_list if t and t.isAlive()]


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()
