# -*- coding: utf-8 -*-
# Copyright CERN since 2016
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

import datetime
import logging
import os
import random
import socket
import threading
import time
from sys import exc_info
from traceback import format_exception

import rucio.core.lifetime_exception
import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.exception import InvalidRSEExpression, RuleNotFound
from rucio.common.logging import setup_logging, formatted_logger
from rucio.common.utils import daemon_sleep
from rucio.core import heartbeat
from rucio.core.did import set_metadata
from rucio.core.lock import get_dataset_locks
from rucio.core.rse import get_rse_name, get_rse_vo
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rule import get_rules_beyond_eol, update_rule
from rucio.db.sqla.constants import LifetimeExceptionsState

GRACEFUL_STOP = threading.Event()


def atropos(thread, bulk, date_check, dry_run=True, grace_period=86400,
            once=True, unlock=False, spread_period=0, purge_replicas=False, sleep_time=60):
    """
    Creates an Atropos Worker that gets a list of rules which have an eol_at expired and delete them.

    :param thread: Thread number at startup.
    :param bulk: The number of requests to process.
    :param grace_period: The grace_period for the rules.
    :param once: Run only once.
    :param sleep_time: Thread sleep time after each chunk of work.
    """
    executable = 'atropos'
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    now = datetime.datetime.now()
    hb = heartbeat.live(executable, hostname, pid, hb_thread)
    time.sleep(10)
    hb = heartbeat.live(executable, hostname, pid, hb_thread)
    prepend_str = 'Thread [%i/%i] : ' % (hb['assign_thread'], hb['nr_threads'])
    logger = formatted_logger(logging.log, prepend_str + '%s')
    logger(logging.DEBUG, 'Starting worker')
    summary = {}
    lifetime_exceptions = {}
    rand = random.Random(hb['assign_thread'])
    for excep in rucio.core.lifetime_exception.list_exceptions(exception_id=None, states=[LifetimeExceptionsState.APPROVED, ], session=None):
        key = '{}:{}'.format(excep['scope'].internal, excep['name'])
        if key not in lifetime_exceptions:
            lifetime_exceptions[key] = excep['expires_at']
        elif lifetime_exceptions[key] < excep['expires_at']:
            lifetime_exceptions[key] = excep['expires_at']
    logger(logging.DEBUG, '%s active exceptions' % len(lifetime_exceptions))
    if not dry_run and date_check > now:
        logger(logging.ERROR, 'Atropos cannot run in non-dry-run mode for date in the future')
    else:
        while not GRACEFUL_STOP.is_set():

            hb = heartbeat.live(executable, hostname, pid, hb_thread)
            prepend_str = 'Thread [%i/%i] : ' % (hb['assign_thread'], hb['nr_threads'])
            logger = formatted_logger(logging.log, prepend_str + '%s')

            stime = time.time()
            try:
                rules = get_rules_beyond_eol(date_check, thread, hb['nr_threads'], session=None)
                logger(logging.INFO, '%s rules to process' % (len(rules)))
                for rule_idx, rule in enumerate(rules, start=1):
                    did = '%s:%s' % (rule.scope, rule.name)
                    did_key = '{}:{}'.format(rule.scope.internal, rule.name)
                    logger(logging.DEBUG, 'Working on rule %s on DID %s on %s' % (rule.id, did, rule.rse_expression))

                    if (rule_idx % 1000) == 0:
                        logger(logging.INFO, '%s/%s rules processed' % (rule_idx, len(rules)))

                    # We compute the expected eol_at
                    try:
                        rses = parse_expression(rule.rse_expression, filter_={'vo': rule.account.vo})
                    except InvalidRSEExpression:
                        logger(logging.WARNING, 'Rule %s has an RSE expression that results in an empty set: %s' % (rule.id, rule.rse_expression))
                        continue
                    eol_at = rucio.core.lifetime_exception.define_eol(rule.scope, rule.name, rses)
                    if eol_at != rule.eol_at:
                        logger(logging.WARNING, 'The computed eol %s differs from the one recorded %s for rule %s on %s at %s' % (eol_at, rule.eol_at, rule.id,
                                                                                                                                  did, rule.rse_expression))
                        try:
                            update_rule(rule.id, options={'eol_at': eol_at})
                        except RuleNotFound:
                            logger(logging.WARNING, 'Cannot find rule %s on DID %s' % (rule.id, did))
                            continue

                    # Check the exceptions
                    if did_key in lifetime_exceptions:
                        if eol_at > lifetime_exceptions[did_key]:
                            logger(logging.INFO, 'Rule %s on DID %s on %s has longer expiration date than the one requested : %s' % (rule.id, did, rule.rse_expression,
                                                                                                                                     lifetime_exceptions[did_key]))
                        else:
                            # If eol_at < requested extension, update eol_at
                            logger(logging.INFO, 'Updating rule %s on DID %s on %s according to the exception till %s' % (rule.id, did, rule.rse_expression,
                                                                                                                          lifetime_exceptions[did_key]))
                            eol_at = lifetime_exceptions[did_key]
                            try:
                                update_rule(rule.id, options={'eol_at': lifetime_exceptions[did_key]})
                            except RuleNotFound:
                                logger(logging.WARNING, 'Cannot find rule %s on DID %s' % (rule.id, did))
                                continue

                    # Now check that the new eol_at is expired
                    if eol_at and eol_at <= date_check:
                        set_metadata(scope=rule.scope, name=rule.name, key='eol_at', value=eol_at)
                        no_locks = True
                        for lock in get_dataset_locks(rule.scope, rule.name):
                            if lock['rule_id'] == rule[4]:
                                no_locks = False
                                if lock['rse_id'] not in summary:
                                    summary[lock['rse_id']] = {}
                                if did_key not in summary[lock['rse_id']]:
                                    summary[lock['rse_id']][did_key] = {'length': lock['length'] or 0, 'bytes': lock['bytes'] or 0}
                        if no_locks:
                            logger(logging.WARNING, 'Cannot find a lock for rule %s on DID %s' % (rule.id, did))
                        if not dry_run:
                            lifetime = grace_period + rand.randrange(spread_period + 1)
                            logger(logging.INFO, 'Setting %s seconds lifetime for rule %s' % (lifetime, rule.id))
                            options = {'lifetime': lifetime}
                            if purge_replicas:
                                options['purge_replicas'] = True
                            if rule.locked and unlock:
                                logger(logging.INFO, 'Unlocking rule %s', rule.id)
                                options['locked'] = False
                            try:
                                update_rule(rule.id, options=options)
                            except RuleNotFound:
                                logger(logging.WARNING, 'Cannot find rule %s on DID %s' % (rule.id, did))
                                continue
            except Exception:
                exc_type, exc_value, exc_traceback = exc_info()
                logger(logging.CRITICAL, ''.join(format_exception(exc_type, exc_value, exc_traceback)).strip())

            for rse_id in summary:
                tot_size, tot_files, tot_datasets = 0, 0, 0
                for did in summary[rse_id]:
                    tot_datasets += 1
                    tot_files += summary[rse_id][did].get('length', 0)
                    tot_size += summary[rse_id][did].get('bytes', 0)
                vo = get_rse_vo(rse_id=rse_id)
                logger(logging.INFO, 'For RSE %s %s %s datasets will be deleted representing %s files and %s bytes' % (get_rse_name(rse_id=rse_id),
                                                                                                                       '' if vo == 'def' else 'on VO ' + vo,
                                                                                                                       tot_datasets,
                                                                                                                       tot_files,
                                                                                                                       tot_size))

            if once:
                break
            else:
                daemon_sleep(start_time=stime, sleep_time=sleep_time, graceful_stop=GRACEFUL_STOP)

        logger(logging.INFO, 'Graceful stop requested')
        heartbeat.die(executable, hostname, pid, hb_thread)
        logger(logging.INFO, 'Graceful stop done')


def run(threads=1, bulk=100, date_check=None, dry_run=True, grace_period=86400,
        once=True, unlock=False, spread_period=0, purge_replicas=False, sleep_time=60):
    """
    Starts up the atropos threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    if not date_check:
        date_check = datetime.datetime.now()
    else:
        date_check = datetime.datetime.strptime(date_check, '%Y-%m-%d')
    if once:
        logging.info('Will run only one iteration')
    logging.info('starting atropos threads')
    thread_list = [threading.Thread(target=atropos, kwargs={'once': once,
                                                            'thread': i,
                                                            'date_check': date_check,
                                                            'dry_run': dry_run,
                                                            'grace_period': grace_period,
                                                            'bulk': bulk,
                                                            'unlock': unlock,
                                                            'spread_period': spread_period,
                                                            'purge_replicas': purge_replicas,
                                                            'sleep_time': sleep_time}) for i in range(0, threads)]
    [t.start() for t in thread_list]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while thread_list:
        thread_list = [t.join(timeout=3.14) for t in thread_list if t and t.is_alive()]


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()
