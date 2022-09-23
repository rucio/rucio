# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

"""
Conveyor throttler is a daemon to manage rucio internal queue.
"""

import logging
import math
import threading
import traceback

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.logging import setup_logging
from rucio.common.utils import get_parsed_throttler_mode
from rucio.core import config as config_core
from rucio.core.monitor import record_counter, record_gauge
from rucio.core.request import get_stats_by_activity_direction_state, release_all_waiting_requests, release_waiting_requests_fifo, release_waiting_requests_grouped_fifo
from rucio.core.rse import set_rse_transfer_limits, delete_rse_transfer_limits, RseCollection
from rucio.daemons.common import run_daemon
from rucio.db.sqla.constants import RequestState

graceful_stop = threading.Event()


def throttler(once=False, sleep_time=600, partition_wait_time=10):
    """
    Main loop to check rse transfer limits.
    """

    logging.info('Throttler starting')

    logger_prefix = executable = 'conveyor-throttler'

    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable=executable,
        logger_prefix=logger_prefix,
        partition_wait_time=partition_wait_time,
        sleep_time=sleep_time,
        run_once_fnc=run_once,
        activities=None,
    )


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, sleep_time=600):
    """
    Starts up the conveyer threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    if once:
        logging.info('running throttler one iteration only')
        throttler(once=True, sleep_time=sleep_time)
    else:
        threads = []
        logging.info('starting throttler thread')
        throttler_thread = threading.Thread(target=throttler, kwargs={'once': once, 'sleep_time': sleep_time})
        threads.append(throttler_thread)
        [thread.start() for thread in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while threads:
            threads = [thread.join(timeout=3.14) for thread in threads if thread and thread.is_alive()]


def __get_request_stats(rse_collection: RseCollection, all_activities=False, direction='destination'):
    """
    Retrieve stats about requests and collect transfer limits.

    :param all_activities: Boolean whether requests are grouped by activity or if activities are ignored.
    :param direction:      String whether request statistics are based on source or destination RSEs.
    """
    logging.info("Throttler retrieve requests statistics")

    result_dict = {}
    if direction == 'destination' or direction == 'source':
        results = get_stats_by_activity_direction_state(
            state=[RequestState.QUEUED,
                   RequestState.SUBMITTING,
                   RequestState.SUBMITTED,
                   RequestState.WAITING],
            all_activities=all_activities,
            direction=direction
        )

        for result in results:
            account = result.account
            state = result.state
            counter = result.counter

            rse = rse_collection[result.rse_id].ensure_loaded(load_transfer_limits=True, load_name=True, load_columns=True)
            if all_activities:
                activity = 'all_activities'
            else:
                activity = result.activity

            limit = rse.transfer_limits.get(activity, {})
            threshold = limit.get('max_transfers')
            if threshold or (counter and (state == RequestState.WAITING)):
                stat = result_dict.setdefault(rse, {}).setdefault(activity, {})

                if not stat:
                    stat.update({
                        'waiting': 0,
                        'transfer': 0,
                        'threshold': threshold,
                        'strategy': limit.get('strategy'),
                        'deadline': limit.get('deadline'),
                        'volume': limit.get('volume'),
                        'accounts': {},
                    })

                if account not in stat['accounts']:
                    stat['accounts'][account] = {'waiting': 0, 'transfer': 0}

                if state == RequestState.WAITING:
                    stat['waiting'] += counter
                    stat['accounts'][account]['waiting'] += counter
                else:
                    stat['transfer'] += counter
                    stat['accounts'][account]['transfer'] += counter

    return result_dict


def run_once(worker_number=0, logger=logging.log, session=None, **kwargs):
    """
    Schedule requests
    """
    if worker_number != 0:
        logger(logging.INFO, 'Throttler thread id is not 0, will sleep. Only thread 0 will work')
        return True
    logger(logging.INFO, "Throttler - schedule requests")
    try:
        rse_collection = RseCollection()
        throttler_mode = config_core.get('throttler', 'mode', default='DEST_PER_ACT', use_cache=False)
        direction, all_activities = get_parsed_throttler_mode(throttler_mode)
        result_dict = __get_request_stats(rse_collection, all_activities, direction)
        for rse, stats in result_dict.items():
            # dest_rse is not blocklisted for write or src_rse is not blocklisted for read
            if (direction == 'destination' and rse.columns.availability & 2) or (direction == 'source' and rse.columns.availability & 4):
                _release_requests(stats, direction, rse, all_activities=all_activities, logger=logger, session=session)
    except Exception:
        logger(logging.CRITICAL, "Failed to schedule requests, error: %s" % (traceback.format_exc()))
    return True


def _release_requests(stats, direction, rse, all_activities, logger, session):
    """
    Release requests per activity.

    :param stats:          Request statistics
    :param direction:      String whether request statistics are based on source or destination RSEs.
    :param rse.name:       RSE name.
    :param rse.id:         RSE id.
    """
    if all_activities:
        stats = (('all_activities', stats['all_activities']),)
    else:
        stats = ((activity, stat) for activity, stat in stats.items() if activity != 'all_activities')

    for activity, stat in stats:
        threshold = stat['threshold']
        transfer = stat['transfer']
        waiting = stat['waiting']
        strategy = stat['strategy']
        deadline = stat.get('deadline')
        volume = stat.get('volume')
        if waiting:
            logger(logging.DEBUG, "Request status for %s at %s: %s" % (activity, rse.name, stat))
            if threshold is None:
                logger(logging.DEBUG, "Throttler remove limits(threshold: %s) and release all waiting requests for activity %s, rse.id %s" % (threshold, activity, rse.id))
                delete_rse_transfer_limits(rse.id, activity=activity, session=session)
                release_all_waiting_requests(rse.id, activity=None if all_activities else activity, direction=direction, session=session)
                record_counter('daemons.conveyor.throttler.delete_rse_transfer_limits.{activity}.{rse}', labels={'activity': activity, 'rse': rse.name})
            elif transfer + waiting > threshold:
                logger(logging.DEBUG, "Throttler set limits for activity %s, rse %s" % (activity, rse.name))
                set_rse_transfer_limits(rse.id, activity=activity, max_transfers=threshold, transfers=transfer, waitings=waiting, session=session)
                record_gauge('daemons.conveyor.throttler.set_rse_transfer_limits.{activity}.{rse}.{limit_attr}', threshold, labels={'activity': activity, 'rse': rse.name, 'limit_attr': 'max_transfers'})
                record_gauge('daemons.conveyor.throttler.set_rse_transfer_limits.{activity}.{rse}.{limit_attr}', transfer, labels={'activity': activity, 'rse': rse.name, 'limit_attr': 'transfers'})
                record_gauge('daemons.conveyor.throttler.set_rse_transfer_limits.{activity}.{rse}.{limit_attr}', waiting, labels={'activity': activity, 'rse': rse.name, 'limit_attr': 'waiting'})
                if transfer < 0.8 * threshold:
                    # release requests on account
                    to_release = threshold - transfer
                    if all_activities:
                        if strategy == 'grouped_fifo':
                            release_waiting_requests_grouped_fifo(rse.id, count=to_release, direction=direction, volume=volume, deadline=deadline, session=session)
                        elif strategy == 'fifo':
                            release_waiting_requests_fifo(rse.id, count=to_release, direction=direction, session=session)
                        continue

                    nr_accounts = len(stat['accounts'])
                    if nr_accounts < 1:
                        nr_accounts = 1
                    threshold_per_account = math.ceil(threshold / nr_accounts)
                    to_release_per_account = math.ceil(to_release / nr_accounts)
                    accounts = stat['accounts']
                    for account in accounts:
                        if nr_accounts == 1:
                            logger(logging.DEBUG, "Throttler release %s waiting requests for activity %s, rse %s, account %s " % (to_release, activity, rse.name, account))
                            release_waiting_requests_fifo(rse.id, activity=None if all_activities else activity, account=account, count=to_release, direction=direction, session=session)
                            record_gauge('daemons.conveyor.throttler.release_waiting_requests.{activity}.{rse}.{account}', to_release, labels={'activity': activity, 'rse': rse.name, 'account': account})
                        elif accounts[account]['transfer'] > threshold_per_account:
                            logger(logging.DEBUG, "Throttler will not release  %s waiting requests for activity %s, rse %s, account %s: It queued more transfers than its share " %
                                   (accounts[account]['waiting'], activity, rse.name, account))
                            nr_accounts -= 1
                            to_release_per_account = math.ceil(to_release / nr_accounts)
                        elif accounts[account]['waiting'] < to_release_per_account:
                            logger(logging.DEBUG, "Throttler release %s waiting requests for activity %s, rse %s, account %s " % (accounts[account]['waiting'], activity, rse.name, account))
                            release_waiting_requests_fifo(rse.id, activity=None if all_activities else activity, account=account, count=accounts[account]['waiting'], direction=direction, session=session)
                            record_gauge('daemons.conveyor.throttler.release_waiting_requests.{activity}.{rse}.{account}', accounts[account]['waiting'], labels={'activity': activity, 'rse': rse.name, 'account': account})
                            to_release = to_release - accounts[account]['waiting']
                            nr_accounts -= 1
                            to_release_per_account = math.ceil(to_release / nr_accounts)
                        else:
                            logger(logging.DEBUG, "Throttler release %s waiting requests for activity %s, rse %s, account %s " % (to_release_per_account, activity, rse.name, account))
                            release_waiting_requests_fifo(rse.id, activity=None if all_activities else activity, account=account, count=to_release_per_account, direction=direction, session=session)
                            record_gauge('daemons.conveyor.throttler.release_waiting_requests.{activity}.{rse}.{account}', to_release_per_account, labels={'activity': activity, 'rse': rse.name, 'account': account})
                            to_release = to_release - to_release_per_account
                            nr_accounts -= 1
                else:
                    logger(logging.DEBUG, "Throttler has done nothing for activity %s on rse %s (transfer > 0.8 * threshold)" % (activity, rse.name))
            elif waiting > 0:
                logger(logging.DEBUG, "Throttler remove limits(threshold: %s) and release all waiting requests for activity %s, rse %s" % (threshold, activity, rse.name))
                delete_rse_transfer_limits(rse.id, activity=activity, session=session)
                release_all_waiting_requests(rse.id, activity=None if all_activities else activity, direction=direction, session=session)
                record_counter('daemons.conveyor.throttler.delete_rse_transfer_limits.{activity}.{rse}', labels={'activity': activity, 'rse': rse.name})
