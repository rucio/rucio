# -*- coding: utf-8 -*-
# Copyright 2018-2020 CERN
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018-2020
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Robert Illingworth <illingwo@fnal.gov>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Cedric Serfon <cedric.serfon@cern.ch>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
# - Eric Vaandering <ewv@fnal.gov>, 2020

import logging
import os
import re
import socket
import threading
import time
from datetime import datetime
from json import loads
from math import exp
from sys import exc_info, stdout
from traceback import format_exception

import rucio.db.sqla.util
from rucio.common.config import config_get
from rucio.common.exception import (DatabaseException, DataIdentifierNotFound, InvalidReplicationRule, DuplicateRule,
                                    RSEBlacklisted, RSEWriteBlocked, InvalidRSEExpression, InsufficientTargetRSEs,
                                    InsufficientAccountLimit, InputValidationError, RSEOverQuota,
                                    ReplicationRuleCreationTemporaryFailed, InvalidRuleWeight,
                                    StagingAreaRuleRequiresLifetime, SubscriptionWrongParameter, SubscriptionNotFound)
from rucio.common.schema import validate_schema
from rucio.common.utils import chunks
from rucio.core import monitor, heartbeat
from rucio.core.did import list_new_dids, set_new_dids, get_metadata
from rucio.core.rse import list_rses, rse_exists, get_rse_id, list_rse_attributes
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rse_selector import RSESelector
from rucio.core.rule import add_rule, list_rules, get_rule
from rucio.core.subscription import list_subscriptions, update_subscription
from rucio.db.sqla.constants import DIDType, SubscriptionState

logging.basicConfig(stream=stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')


graceful_stop = threading.Event()


def _retrial(func, *args, **kwargs):
    """
    Retrial method
    """
    delay = 0
    while True:
        try:
            return func(*args, **kwargs)
        except DataIdentifierNotFound as error:
            logging.warning(error)
            return 1
        except DatabaseException as error:
            logging.error(error)
            if exp(delay) > 600:
                logging.error('Cannot execute %s after %i attempt. Failing the job.' % (func.__name__, delay))
                raise
            else:
                logging.error('Failure to execute %s. Retrial will be done in %d seconds ' % (func.__name__, exp(delay)))
            time.sleep(exp(delay))
            delay += 1
        except Exception:
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
        filter_string = loads(subscription['filter'])
    except ValueError as error:
        logging.error('%s : Subscription will be skipped' % error)
        return False
    # Loop over the keys of filter_string for subscription
    for key in filter_string:
        values = filter_string[key]
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
                if re.match(scope, did['scope'].internal):
                    match_scope = True
                    break
            if not match_scope:
                return False
        elif key == 'account':
            match_account = False
            if not isinstance(values, list):
                values = [values]
            for account in values:
                if account == metadata['account'].internal:
                    match_account = True
                    break
            if not match_account:
                return False
        else:
            if not isinstance(values, list):
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


def select_algorithm(algorithm, rule_ids, params):
    """
    Method used in case of chained subscriptions

    :param algorithm: Algorithm used for the chained rule. Now only associated_site
                      associated_site : Choose an associated endpoint according to the RSE attribute assoiciated_site
    :param rule_ids: List of parent rules
    :param params: List of rules parameters to be used by the algorithm
    """
    selected_rses = {}
    if algorithm == 'associated_site':
        for rule_id in rule_ids:
            rule = get_rule(rule_id)
            logging.debug('In select_algorithm, %s', str(rule))
            rse = rule['rse_expression']
            vo = rule['account'].vo
            if rse_exists(rse, vo=vo):
                rse_id = get_rse_id(rse, vo=vo)
                rse_attributes = list_rse_attributes(rse_id)
                associated_sites = rse_attributes.get('associated_sites', None)
                associated_site_idx = params.get('associated_site_idx', None)
                if not associated_site_idx:
                    raise SubscriptionWrongParameter('Missing parameter associated_site_idx')
                if associated_sites:
                    associated_sites = associated_sites.split(',')
                    if associated_site_idx > len(associated_sites) + 1:
                        raise SubscriptionWrongParameter('Parameter associated_site_idx is out of range')
                    associated_site = associated_sites[associated_site_idx - 1]
                    selected_rses[associated_site] = {'source_replica_expression': rse, 'weight': None}
            else:
                raise SubscriptionWrongParameter('Algorithm associated_site only works with split_rule')
            if rule['copies'] != 1:
                raise SubscriptionWrongParameter('Algorithm associated_site only works with split_rule')
    return selected_rses


def transmogrifier(bulk=5, once=False, sleep_time=60):
    """
    Creates a Transmogrifier Worker that gets a list of new DIDs for a given hash,
    identifies the subscriptions matching the DIDs and
    submit a replication rule for each DID matching a subscription.

    :param thread: Thread number at startup.
    :param bulk: The number of requests to process.
    :param once: Run only once.
    :param sleep_time: Time between two cycles.
    """

    executable = 'transmogrifier'
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)

    while not graceful_stop.is_set():

        heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)

        dids, subscriptions = [], []
        tottime = 0
        prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])

        try:
            #  Get the new DIDs based on the is_new flag
            for did in list_new_dids(thread=heart_beat['assign_thread'], total_threads=heart_beat['nr_threads'], chunk_size=bulk, did_type=None):
                dids.append({'scope': did['scope'], 'did_type': str(did['did_type']), 'name': did['name']})

            sub_dict = {3: []}
            #  Get the list of subscriptions. The default priority of the subscription is 3. 0 is the highest priority, 5 the lowest
            #  The priority is defined as 'policyid'
            for sub in list_subscriptions(None, None):
                if sub['state'] != SubscriptionState.INACTIVE and sub['lifetime'] and (datetime.now() > sub['lifetime']):
                    update_subscription(name=sub['name'], account=sub['account'], metadata={'state': SubscriptionState.INACTIVE})

                elif sub['state'] in [SubscriptionState.ACTIVE, SubscriptionState.UPDATED]:
                    priority = 3
                    if 'policyid' in sub:
                        if int(sub['policyid']) not in sub_dict:
                            sub_dict[int(sub['policyid'])] = []
                        priority = int(sub['policyid'])
                    sub_dict[priority].append(sub)
            priorities = list(sub_dict.keys())
            priorities.sort()
            #  Order the subscriptions according to their priority
            for priority in priorities:
                subscriptions.extend(sub_dict[priority])
        except SubscriptionNotFound as error:
            logging.warning(prepend_str + 'No subscriptions defined: %s' % (str(error)))
            time.sleep(10)
            continue
        except Exception as error:
            logging.error(prepend_str + 'Failed to get list of new DIDs or subscriptions: %s' % (str(error)))

        try:
            results = {}
            start_time = time.time()
            blacklisted_rse_id = [rse['id'] for rse in list_rses({'availability_write': False})]
            logging.debug(prepend_str + 'In transmogrifier worker')
            identifiers = []
            #  Loop over all the new dids
            for did in dids:
                did_success = True
                if did['did_type'] == str(DIDType.DATASET) or did['did_type'] == str(DIDType.CONTAINER):
                    did_tag = '%s:%s' % (did['scope'].internal, did['name'])
                    results[did_tag] = []
                    try:
                        metadata = get_metadata(did['scope'], did['name'])
                        # Loop over all the subscriptions
                        for subscription in subscriptions:
                            #  Check if the DID match the subscription
                            if is_matching_subscription(subscription, did, metadata) is True:
                                filter_string = loads(subscription['filter'])
                                split_rule = filter_string.get('split_rule', False)
                                stime = time.time()
                                results[did_tag].append(subscription['id'])
                                logging.info(prepend_str + '%s:%s matches subscription %s' % (did['scope'], did['name'], subscription['name']))
                                rules = loads(subscription['replication_rules'])
                                created_rules = {}
                                cnt = 0
                                for rule_dict in rules:
                                    cnt += 1
                                    created_rules[cnt] = []
                                    # Get all the rule and subscription parameters
                                    grouping = rule_dict.get('grouping', 'DATASET')
                                    lifetime = rule_dict.get('lifetime', None)
                                    ignore_availability = rule_dict.get('ignore_availability', None)
                                    weight = rule_dict.get('weight', None)
                                    source_replica_expression = rule_dict.get('source_replica_expression', None)
                                    locked = rule_dict.get('locked', None)
                                    if locked == 'True':
                                        locked = True
                                    else:
                                        locked = False
                                    purge_replicas = rule_dict.get('purge_replicas', False)
                                    if purge_replicas == 'True':
                                        purge_replicas = True
                                    else:
                                        purge_replicas = False
                                    rse_expression = str(rule_dict['rse_expression'])
                                    comment = str(subscription['comments'])
                                    if 'comments' in rule_dict:
                                        comment = str(rule_dict['comments'])
                                    subscription_id = str(subscription['id'])
                                    account = subscription['account']
                                    copies = int(rule_dict['copies'])
                                    activity = rule_dict.get('activity', 'User Subscriptions')
                                    try:
                                        validate_schema(name='activity', obj=activity, vo=account.vo)
                                    except InputValidationError as error:
                                        logging.error(prepend_str + 'Error validating the activity %s' % (str(error)))
                                        activity = 'User Subscriptions'
                                    if lifetime:
                                        lifetime = int(lifetime)

                                    str_activity = "".join(activity.split())
                                    success = False
                                    nattempt = 5
                                    attemptnr = 0
                                    skip_rule_creation = False

                                    selected_rses = []
                                    chained_idx = rule_dict.get('chained_idx', None)
                                    if chained_idx:
                                        params = {}
                                        if rule_dict.get('associated_site_idx', None):
                                            params['associated_site_idx'] = rule_dict.get('associated_site_idx', None)
                                        logging.debug('%s Chained subscription identified. Will use %s', prepend_str, str(created_rules[chained_idx]))
                                        algorithm = rule_dict.get('algorithm', None)
                                        selected_rses = select_algorithm(algorithm, created_rules[chained_idx], params)
                                    else:
                                        # In the case of chained subscription, don't use rseselector but use the rses returned by the algorithm
                                        if split_rule:
                                            vo = account.vo
                                            rses = parse_expression(rse_expression, filter={'vo': vo})
                                            list_of_rses = [rse['id'] for rse in rses]
                                            # Check that some rule doesn't already exist for this DID and subscription
                                            preferred_rse_ids = []
                                            for rule in list_rules(filters={'subscription_id': subscription_id, 'scope': did['scope'], 'name': did['name']}):
                                                already_existing_rses = [(rse['rse'], rse['id']) for rse in parse_expression(rule['rse_expression'], filter={'vo': vo})]
                                                for rse, rse_id in already_existing_rses:
                                                    if (rse_id in list_of_rses) and (rse_id not in preferred_rse_ids):
                                                        preferred_rse_ids.append(rse_id)
                                            if len(preferred_rse_ids) >= copies:
                                                skip_rule_creation = True
                                            rse_id_dict = {}
                                            for rse in rses:
                                                rse_id_dict[rse['id']] = rse['rse']
                                            try:
                                                rseselector = RSESelector(account=account, rses=rses, weight=weight, copies=copies - len(preferred_rse_ids))
                                                selected_rses = [rse_id_dict[rse_id] for rse_id, _, _ in rseselector.select_rse(0, preferred_rse_ids=preferred_rse_ids, copies=copies, blacklist=blacklisted_rse_id)]
                                            except (InsufficientTargetRSEs, InsufficientAccountLimit, InvalidRuleWeight, RSEOverQuota) as error:
                                                logging.warning(prepend_str + 'Problem getting RSEs for subscription "%s" for account %s : %s. Try including blacklisted sites' %
                                                                (subscription['name'], account, str(error)))
                                                # Now including the blacklisted sites
                                                try:
                                                    rseselector = RSESelector(account=account, rses=rses, weight=weight, copies=copies - len(preferred_rse_ids))
                                                    selected_rses = [rse_id_dict[rse_id] for rse_id, _, _ in rseselector.select_rse(0, preferred_rse_ids=preferred_rse_ids, copies=copies, blacklist=[])]
                                                    ignore_availability = True
                                                except (InsufficientTargetRSEs, InsufficientAccountLimit, InvalidRuleWeight, RSEOverQuota) as error:
                                                    logging.error(prepend_str + 'Problem getting RSEs for subscription "%s" for account %s : %s. Skipping rule creation.' %
                                                                  (subscription['name'], account, str(error)))
                                                    monitor.record_counter(counters='transmogrifier.addnewrule.errortype.%s' % (str(error.__class__.__name__)), delta=1)
                                                    # The DID won't be reevaluated at the next cycle
                                                    did_success = did_success and True
                                                    continue

                                    for attempt in range(0, nattempt):
                                        attemptnr = attempt
                                        nb_rule = 0
                                        #  Try to create the rule
                                        try:
                                            if split_rule:
                                                if not skip_rule_creation:
                                                    for rse in selected_rses:
                                                        if isinstance(selected_rses, dict):
                                                            source_replica_expression = selected_rses[rse].get('source_replica_expression', None)
                                                            weight = selected_rses[rse].get('weight', None)
                                                        logging.info(prepend_str + 'Will insert one rule for %s:%s on %s' % (did['scope'], did['name'], rse))
                                                        rule_ids = add_rule(dids=[{'scope': did['scope'], 'name': did['name']}], account=account, copies=1,
                                                                            rse_expression=rse, grouping=grouping, weight=weight, lifetime=lifetime, locked=locked,
                                                                            subscription_id=subscription_id, source_replica_expression=source_replica_expression, activity=activity,
                                                                            purge_replicas=purge_replicas, ignore_availability=ignore_availability, comment=comment)
                                                        created_rules[cnt].append(rule_ids[0])
                                                        nb_rule += 1
                                                        if nb_rule == copies:
                                                            success = True
                                                            break
                                            else:
                                                rule_ids = add_rule(dids=[{'scope': did['scope'], 'name': did['name']}], account=account, copies=copies,
                                                                    rse_expression=rse_expression, grouping=grouping, weight=weight, lifetime=lifetime, locked=locked,
                                                                    subscription_id=subscription['id'], source_replica_expression=source_replica_expression, activity=activity,
                                                                    purge_replicas=purge_replicas, ignore_availability=ignore_availability, comment=comment)
                                                created_rules[cnt].append(rule_ids[0])
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
                                        except (ReplicationRuleCreationTemporaryFailed, InsufficientTargetRSEs,
                                                InsufficientAccountLimit, DatabaseException, RSEBlacklisted,
                                                RSEWriteBlocked) as error:
                                            # Errors to be retried
                                            logging.error(prepend_str + '%s Will perform an other attempt %i/%i' % (str(error), attempt + 1, nattempt))
                                            monitor.record_counter(counters='transmogrifier.addnewrule.errortype.%s' % (str(error.__class__.__name__)), delta=1)
                                        except Exception:
                                            # Unexpected errors
                                            monitor.record_counter(counters='transmogrifier.addnewrule.errortype.unknown', delta=1)
                                            exc_type, exc_value, exc_traceback = exc_info()
                                            logging.critical(prepend_str + ''.join(format_exception(exc_type, exc_value, exc_traceback)).strip())

                                    did_success = (did_success and success)
                                    if (attemptnr + 1) == nattempt and not success:
                                        logging.error(prepend_str + 'Rule for %s:%s on %s cannot be inserted' % (did['scope'], did['name'], rse_expression))
                                    else:
                                        logging.info(prepend_str + '%s rule(s) inserted in %f seconds' % (str(nb_rule), time.time() - stime))
                    except DataIdentifierNotFound as error:
                        logging.warning(prepend_str + error)

                if did_success:
                    if did['did_type'] == str(DIDType.FILE):
                        monitor.record_counter(counters='transmogrifier.did.file.processed', delta=1)
                    elif did['did_type'] == str(DIDType.DATASET):
                        monitor.record_counter(counters='transmogrifier.did.dataset.processed', delta=1)
                    elif did['did_type'] == str(DIDType.CONTAINER):
                        monitor.record_counter(counters='transmogrifier.did.container.processed', delta=1)
                    monitor.record_counter(counters='transmogrifier.did.processed', delta=1)
                    identifiers.append({'scope': did['scope'], 'name': did['name'], 'did_type': did['did_type']})

            time1 = time.time()

            #  Mark the DIDs as processed
            for identifier in chunks(identifiers, 100):
                _retrial(set_new_dids, identifier, None)

            logging.info(prepend_str + 'Time to set the new flag : %f' % (time.time() - time1))
            tottime = time.time() - start_time
            for sub in subscriptions:
                update_subscription(name=sub['name'], account=sub['account'], metadata={'last_processed': datetime.now()})
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
        if tottime < sleep_time:
            logging.info(prepend_str + 'Will sleep for %s seconds' % (sleep_time - tottime))
            time.sleep(sleep_time - tottime)
    heartbeat.die(executable, hostname, pid, hb_thread)
    logging.info(prepend_str + 'Graceful stop requested')
    logging.info(prepend_str + 'Graceful stop done')


def run(threads=1, bulk=100, once=False, sleep_time=60):
    """
    Starts up the transmogrifier threads.
    """
    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException('Database was not updated, daemon won\'t start')

    if once:
        logging.info('Will run only one iteration in a single threaded mode')
        transmogrifier(bulk=bulk, once=once)
    else:
        logging.info('starting transmogrifier threads')
        thread_list = [threading.Thread(target=transmogrifier, kwargs={'once': once,
                                                                       'sleep_time': sleep_time,
                                                                       'bulk': bulk}) for _ in range(0, threads)]
        [thread.start() for thread in thread_list]
        logging.info('waiting for interrupts')
        # Interruptible joins require a timeout.
        while thread_list:
            thread_list = [thread.join(timeout=3.14) for thread in thread_list if thread and thread.isAlive()]


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()
