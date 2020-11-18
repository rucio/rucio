# -*- coding: utf-8 -*-
# Copyright 2016-2020 CERN
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2016-2018
# - Vincent Garonne <vgaronne@gmail.com>, 2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018
# - Dimitrios Christidis <dimitrios.christidis@cern.ch>, 2018-2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import datetime
import logging
import os
import random
import socket
import threading
import time
from sys import exc_info, stdout
from traceback import format_exception

import rucio.core.lifetime_exception
import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get
from rucio.common.exception import InvalidRSEExpression, RuleNotFound
from rucio.core import heartbeat
from rucio.core.lock import get_dataset_locks
from rucio.core.rse import get_rse_name, get_rse_vo
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rule import get_rules_beyond_eol, update_rule
from rucio.db.sqla.constants import LifetimeExceptionsState

logging.basicConfig(stream=stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

GRACEFUL_STOP = threading.Event()


def atropos(thread, bulk, date_check, dry_run=True, grace_period=86400,
            once=True, unlock=False, spread_period=0, purge_replicas=False):
    """
    Creates an Atropos Worker that gets a list of rules which have an eol_at expired and delete them.

    :param thread: Thread number at startup.
    :param bulk: The number of requests to process.
    :param grace_period: The grace_period for the rules.
    :param once: Run only once.
    """

    sleep_time = 60

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
    logging.debug(prepend_str + 'Starting worker')
    summary = {}
    lifetime_exceptions = {}
    rand = random.Random(hb['assign_thread'])
    for excep in rucio.core.lifetime_exception.list_exceptions(exception_id=None, states=[LifetimeExceptionsState.APPROVED, ], session=None):
        key = '{}:{}'.format(excep['scope'].internal, excep['name'])
        if key not in lifetime_exceptions:
            lifetime_exceptions[key] = excep['expires_at']
        elif lifetime_exceptions[key] < excep['expires_at']:
            lifetime_exceptions[key] = excep['expires_at']
    logging.debug(prepend_str + '%s active exceptions' % len(lifetime_exceptions))
    if not dry_run and date_check > now:
        logging.error(prepend_str + 'Atropos cannot run in non-dry-run mode for date in the future')
    else:
        while not GRACEFUL_STOP.is_set():

            hb = heartbeat.live(executable, hostname, pid, hb_thread)
            prepend_str = 'Thread [%i/%i] : ' % (hb['assign_thread'], hb['nr_threads'])

            stime = time.time()
            try:
                rules = get_rules_beyond_eol(date_check, thread, hb['nr_threads'], session=None)
                logging.info(prepend_str + '%s rules to process' % (len(rules)))
                for rule_idx, rule in enumerate(rules, start=1):
                    did = '%s:%s' % (rule.scope, rule.name)
                    did_key = '{}:{}'.format(rule.scope.internal, rule.name)
                    logging.debug(prepend_str + 'Working on rule %s on DID %s on %s' % (rule.id, did, rule.rse_expression))

                    if (rule_idx % 1000) == 0:
                        logging.info(prepend_str + '%s/%s rules processed' % (rule_idx, len(rules)))

                    # We compute the expected eol_at
                    try:
                        rses = parse_expression(rule.rse_expression, filter={'vo': rule.account.vo})
                    except InvalidRSEExpression:
                        logging.warning(prepend_str + 'Rule %s has an RSE expression that results in an empty set: %s' % (rule.id, rule.rse_expression))
                        continue
                    eol_at = rucio.core.lifetime_exception.define_eol(rule.scope, rule.name, rses)
                    if eol_at != rule.eol_at:
                        logging.warning(prepend_str + 'The computed eol %s differs from the one recorded %s for rule %s on %s at %s' % (eol_at, rule.eol_at, rule.id,
                                                                                                                                        did, rule.rse_expression))
                        try:
                            update_rule(rule.id, options={'eol_at': eol_at})
                        except RuleNotFound:
                            logging.warning(prepend_str + 'Cannot find rule %s on DID %s' % (rule.id, did))
                            continue

                    # Check the exceptions
                    if did_key in lifetime_exceptions:
                        if eol_at > lifetime_exceptions[did_key]:
                            logging.info(prepend_str + 'Rule %s on DID %s on %s has longer expiration date than the one requested : %s' % (rule.id, did, rule.rse_expression,
                                                                                                                                           lifetime_exceptions[did_key]))
                        else:
                            # If eol_at < requested extension, update eol_at
                            logging.info(prepend_str + 'Updating rule %s on DID %s on %s according to the exception till %s' % (rule.id, did, rule.rse_expression,
                                                                                                                                lifetime_exceptions[did_key]))
                            eol_at = lifetime_exceptions[did_key]
                            try:
                                update_rule(rule.id, options={'eol_at': lifetime_exceptions[did_key]})
                            except RuleNotFound:
                                logging.warning(prepend_str + 'Cannot find rule %s on DID %s' % (rule.id, did))
                                continue

                    # Now check that the new eol_at is expired
                    if eol_at and eol_at < date_check:
                        no_locks = True
                        for lock in get_dataset_locks(rule.scope, rule.name):
                            if lock['rule_id'] == rule[4]:
                                no_locks = False
                                if lock['rse_id'] not in summary:
                                    summary[lock['rse_id']] = {}
                                if did_key not in summary[lock['rse_id']]:
                                    summary[lock['rse_id']][did_key] = {'length': lock['length'] or 0, 'bytes': lock['bytes'] or 0}
                        if no_locks:
                            logging.warning(prepend_str + 'Cannot find a lock for rule %s on DID %s' % (rule.id, did))
                        if not dry_run:
                            lifetime = grace_period + rand.randrange(spread_period + 1)
                            logging.info(prepend_str + 'Setting %s seconds lifetime for rule %s' % (lifetime, rule.id))
                            options = {'lifetime': lifetime}
                            if purge_replicas:
                                options['purge_replicas'] = True
                            if rule.locked and unlock:
                                logging.info(prepend_str + 'Unlocking rule %s', rule.id)
                                options['locked'] = False
                            try:
                                update_rule(rule.id, options=options)
                            except RuleNotFound:
                                logging.warning(prepend_str + 'Cannot find rule %s on DID %s' % (rule.id, did))
                                continue
            except Exception:
                exc_type, exc_value, exc_traceback = exc_info()
                logging.critical(''.join(format_exception(exc_type, exc_value, exc_traceback)).strip())

            for rse_id in summary:
                tot_size, tot_files, tot_datasets = 0, 0, 0
                for did in summary[rse_id]:
                    tot_datasets += 1
                    tot_files += summary[rse_id][did].get('length', 0)
                    tot_size += summary[rse_id][did].get('bytes', 0)
                vo = get_rse_vo(rse_id=rse_id)
                logging.info(prepend_str + 'For RSE %s %s %s datasets will be deleted representing %s files and %s bytes' % (get_rse_name(rse_id=rse_id),
                                                                                                                             '' if vo == 'def' else 'on VO ' + vo,
                                                                                                                             tot_datasets,
                                                                                                                             tot_files,
                                                                                                                             tot_size))

            if once:
                break
            else:
                tottime = time.time() - stime
                if tottime < sleep_time:
                    logging.info(prepend_str + 'Will sleep for %s seconds' % (str(sleep_time - tottime)))
                    time.sleep(sleep_time - tottime)
                    continue

        logging.info(prepend_str + 'Graceful stop requested')
        heartbeat.die(executable, hostname, pid, hb_thread)
        logging.info(prepend_str + 'Graceful stop done')


def run(threads=1, bulk=100, date_check=None, dry_run=True, grace_period=86400,
        once=True, unlock=False, spread_period=0, purge_replicas=False):
    """
    Starts up the atropos threads.
    """
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
                                                            'purge_replicas': purge_replicas}) for i in range(0, threads)]
    [t.start() for t in thread_list]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while thread_list:
        thread_list = [t.join(timeout=3.14) for t in thread_list if t and t.isAlive()]


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()
