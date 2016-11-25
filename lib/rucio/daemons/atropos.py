'''
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Cedric Serfon, <cedric.serfon@cern.ch>, 2016
'''

import datetime
import logging
import os
import socket
import threading
import time

from sys import exc_info, stdout, argv
from traceback import format_exception

from rucio.common.config import config_get
from rucio.common.exception import RuleNotFound
from rucio.common.policy import define_eol, get_lifetime_exceptions
from rucio.core import heartbeat
from rucio.core.lock import get_dataset_locks
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rule import get_rules_beyond_eol, update_rule


logging.basicConfig(stream=stdout, level=getattr(logging, config_get('common', 'loglevel').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def atropos(thread, bulk, date_check, dry_run=True, grace_period=86400, once=True):
    """
    Creates an Atropos Worker that gets a list of rules which have an eol_at expired and delete them.

    :param thread: Thread number at startup.
    :param bulk: The number of requests to process.
    :param grace_period: The grace_period for the rules.
    :param once: Run only once.
    """

    sleep_time = 60

    executable = ' '.join(argv)
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    now = datetime.datetime.now()
    hb = heartbeat.live(executable, hostname, pid, hb_thread)
    summary = {}
    lifetime_exceptions = get_lifetime_exceptions()
    prepend_str = 'Thread [%i/%i] : ' % (hb['assign_thread'] + 1, hb['nr_threads'])
    if not dry_run and date_check > now:
        logging.error(prepend_str + 'Atropos cannot run in non-dry-run mode for date in the future')
    else:
        while not graceful_stop.is_set():

            hb = heartbeat.live(executable, hostname, pid, hb_thread)
            prepend_str = 'Thread [%i/%i] : ' % (hb['assign_thread'] + 1, hb['nr_threads'])

            stime = time.time()
            try:
                rules = get_rules_beyond_eol(date_check, thread, hb['nr_threads'] - 1)
                logging.info(prepend_str + '%s rules to process' % (len(rules)))
                rule_idx = 0
                for rule in rules:
                    rule_idx += 1
                    logging.debug(prepend_str + 'Working on rule %s on DID %s:%s on %s' % (rule.id, rule.scope, rule.name, rule.rse_expression))

                    if (rule_idx % 1000) == 0:
                        logging.info(prepend_str + '%s/%s rules processed' % (rule_idx, len(rules)))
                    # We compute the expended eol_at
                    rses = parse_expression(rule.rse_expression)
                    eol_at = define_eol(rule.scope, rule.name, rses)

                    # Check the exceptions
                    if rule.name in lifetime_exceptions:
                        if rule.eol_at > lifetime_exceptions[rule.name]:
                            logging.info(prepend_str + 'Rule %s on DID %s:%s on %s expired. Extension requested till %s' % (rule.id, rule.scope, rule.name, rule.rse_expression,
                                                                                                                            lifetime_exceptions[rule.name]))
                        else:
                            # If eol_at < requested extension, update eol_at
                            logging.info(prepend_str + 'Updating rule %s on DID %s:%s on %s according to the exception till %s' % (rule.id, rule.scope, rule.name, rule.rse_expression,
                                                                                                                                   lifetime_exceptions[rule.name]))
                            try:
                                update_rule(rule.id, options={'eol_at': lifetime_exceptions[rule.name]})
                            except RuleNotFound:
                                logging.warning(prepend_str + 'Cannot find rule %s on DID %s:%s' % (rule.id, rule.scope, rule.name))
                    elif eol_at != rule.eol_at:
                        logging.warning(prepend_str + 'The computed eol %s differs from the one recorded %s for rule %s on %s:%s at %s' % (eol_at, rule.eol_at, rule.id,
                                                                                                                                           rule.scope, rule.name, rule.rse_expression))
                        try:
                            update_rule(rule.id, options={'eol_at': eol_at})
                        except RuleNotFound:
                            logging.warning(prepend_str + 'Cannot find rule %s on DID %s:%s' % (rule.id, rule.scope, rule.name))

                    no_locks = True
                    for lock in get_dataset_locks(rule.scope, rule.name):
                        if lock['rule_id'] == rule[4]:
                            no_locks = False
                            if lock['rse'] not in summary:
                                summary[lock['rse']] = {}
                            if '%s:%s' % (rule.scope, rule.name) not in summary[lock['rse']]:
                                summary[lock['rse']]['%s:%s' % (rule.scope, rule.name)] = {'length': lock['length'] or 0, 'bytes': lock['bytes'] or 0}
                    if no_locks:
                        logging.warning(prepend_str + 'Cannot find a lock for rule %s on DID %s:%s' % (rule.id, rule.scope, rule.name))
                    if not dry_run:
                        logging.info(prepend_str + 'Setting %s seconds lifetime for rule %s' % (grace_period, rule.id))
                        try:
                            update_rule(rule.id, options={'lifetime': grace_period})
                        except RuleNotFound:
                            logging.warning(prepend_str + 'Cannot find rule %s on DID %s:%s' % (rule.id, rule.scope, rule.name))
            except Exception:
                exc_type, exc_value, exc_traceback = exc_info()
                logging.critical(''.join(format_exception(exc_type, exc_value, exc_traceback)).strip())

            for rse in summary:
                tot_size, tot_files, tot_datasets = 0, 0, 0
                for did in summary[rse]:
                    tot_datasets += 1
                    tot_files += summary[rse][did].get('length', 0)
                    tot_size += summary[rse][did].get('bytes', 0)
                logging.info(prepend_str + 'For RSE %s %s datasets will be deleted representing %s files and %s bytes' % (rse, tot_datasets, tot_files, tot_size))

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


def run(threads=1, bulk=100, date_check=None, dry_run=True, grace_period=86400, once=True):
    """
    Starts up the atropos threads.
    """
    if not date_check:
        date_check = datetime.datetime.now()
    else:
        date_check = datetime.datetime.strptime(date_check, '%Y-%m-%d')
    if once:
        logging.info('Will run only one iteration in a single threaded mode')
    logging.info('starting atropos threads')
    thread_list = [threading.Thread(target=atropos, kwargs={'once': once,
                                                            'thread': i,
                                                            'date_check': date_check,
                                                            'dry_run': dry_run,
                                                            'grace_period': grace_period,
                                                            'bulk': bulk}) for i in xrange(0, threads)]
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
