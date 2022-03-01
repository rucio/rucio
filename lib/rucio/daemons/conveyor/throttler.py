# -*- coding: utf-8 -*-
# Copyright 2016-2022 CERN
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
# - Wen Guan <wen.guan@cern.ch>, 2016
# - Vincent Garonne <vincent.garonne@cern.ch>, 2016-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2017-2021
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020-2021
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021-2022

"""
Conveyor throttler is a daemon to manage rucio internal queue.
"""

from __future__ import division

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
from rucio.core.rse import get_rse, set_rse_transfer_limits, delete_rse_transfer_limits, get_rse_transfer_limits
from rucio.daemons.conveyor.common import run_conveyor_daemon
from rucio.db.sqla.constants import RequestState

graceful_stop = threading.Event()


def throttler(once=False, sleep_time=600, partition_wait_time=10):
    """
    Main loop to check rse transfer limits.
    """

    logging.info('Throttler starting')

    logger_prefix = executable = 'conveyor-throttler'

    run_conveyor_daemon(
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


def __get_request_stats(all_activities=False, direction='destination'):
    """
    Retrieve stats about requests and collect transfer limits.

    :param all_activities: Boolean whether requests are grouped by activity or if activities are ignored.
    :param direction:      String whether request statistics are based on source or destination RSEs.
    """
    logging.info("Throttler retrieve requests statistics")

    results = get_stats_by_activity_direction_state(state=[RequestState.QUEUED,
                                                           RequestState.SUBMITTING,
                                                           RequestState.SUBMITTED,
                                                           RequestState.WAITING], all_activities=all_activities, direction=direction)
    result_dict = {}
    limits = get_rse_transfer_limits()
    for result in results:
        if direction == 'destination' or direction == 'source':
            account = result[0]
            state = result[1]
            rse = result[2]
            counter = result[3]
            rse_id = result[4]

            if all_activities:
                threshold = limits.get('all_activities', {}).get(rse_id, {}).get('max_transfers')
                if threshold or (counter and (state == RequestState.WAITING)):
                    if rse_id not in result_dict:
                        result_dict[rse_id] = {'waiting': 0,
                                               'transfer': 0,
                                               'threshold': threshold,
                                               'rse': rse,
                                               'strategy': limits.get('all_activities', {}).get(rse_id, {}).get('strategy'),
                                               'deadline': limits.get('all_activities', {}).get(rse_id, {}).get('deadline'),
                                               'volume': limits.get('all_activities', {}).get(rse_id, {}).get('volume'),
                                               'activities': {}}
                    if state == RequestState.WAITING:
                        result_dict[rse_id]['waiting'] += counter
                    else:
                        result_dict[rse_id]['transfer'] += counter
            else:
                activity = result[5]
                threshold = limits.get(activity, {}).get(rse_id, {}).get('max_transfers')
                if threshold or (counter and (state == RequestState.WAITING)):
                    if rse_id not in result_dict:
                        result_dict[rse_id] = {
                            'rse': rse,
                            'activities': {}
                        }

                    if activity not in result_dict[rse_id]['activities']:
                        result_dict[rse_id]['activities'][activity] = {'waiting': 0,
                                                                       'transfer': 0,
                                                                       'strategy': limits.get(activity, {}).get(rse_id, {}).get('strategy'),
                                                                       'deadline': limits.get('all_activities', {}).get(rse_id, {}).get('deadline'),
                                                                       'volume': limits.get('all_activities', {}).get(rse_id, {}).get('volume'),
                                                                       'threshold': threshold,
                                                                       'accounts': {}}
                    if account not in result_dict[rse_id]['activities'][activity]['accounts']:
                        result_dict[rse_id]['activities'][activity]['accounts'][account] = {'waiting': 0, 'transfer': 0}
                    if state == RequestState.WAITING:
                        result_dict[rse_id]['activities'][activity]['accounts'][account]['waiting'] += counter
                        result_dict[rse_id]['activities'][activity]['waiting'] += counter
                    else:
                        result_dict[rse_id]['activities'][activity]['accounts'][account]['transfer'] += counter
                        result_dict[rse_id]['activities'][activity]['transfer'] += counter
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
        throttler_mode = config_core.get('throttler', 'mode', default='DEST_PER_ACT', use_cache=False)
        direction, all_activities = get_parsed_throttler_mode(throttler_mode)
        result_dict = __get_request_stats(all_activities, direction)
        if direction == 'destination' or direction == 'source':
            for rse_id in result_dict:
                rse_name = result_dict[rse_id]['rse']
                availability = get_rse(rse_id).availability
                # dest_rse is not blocklisted for write or src_rse is not blocklisted for read
                if (direction == 'destination' and availability & 2) or (direction == 'source' and availability & 4):
                    if all_activities:
                        __release_all_activities(result_dict[rse_id], direction, rse_name, rse_id, logger=logger, session=session)
                    else:
                        __release_per_activity(result_dict[rse_id], direction, rse_name, rse_id, logger=logger, session=session)
    except Exception:
        logger(logging.CRITICAL, "Failed to schedule requests, error: %s" % (traceback.format_exc()))
    return True


def __release_all_activities(stats, direction, rse_name, rse_id, logger, session):
    """
    Release requests if activities should be ignored.

    :param stats:          Request statistics
    :param direction:      String whether request statistics are based on source or destination RSEs.
    :param rse_name:       RSE name.
    :param rse_id:         RSE id.
    """
    threshold = stats['threshold']
    transfer = stats['transfer']
    waiting = stats['waiting']
    strategy = stats['strategy']
    if threshold is not None and transfer + waiting > threshold:
        record_gauge('daemons.conveyor.throttler.set_rse_transfer_limits.{activity}.{rse}.{limit_attr}', threshold, labels={'activity': 'all_activities', 'rse': rse_name, 'limit_attr': 'max_transfers'})
        record_gauge('daemons.conveyor.throttler.set_rse_transfer_limits.{activity}.{rse}.{limit_attr}', transfer, labels={'activity': 'all_activities', 'rse': rse_name, 'limit_attr': 'transfers'})
        record_gauge('daemons.conveyor.throttler.set_rse_transfer_limits.{activity}.{rse}.{limit_attr}', waiting, labels={'activity': 'all_activities', 'rse': rse_name, 'limit_attr': 'waiting'})
        if transfer < 0.8 * threshold:
            to_be_released = threshold - transfer
            if strategy == 'grouped_fifo':
                deadline = stats.get('deadline')
                volume = stats.get('volume')
                release_waiting_requests_grouped_fifo(rse_id, count=to_be_released, direction=direction, volume=volume, deadline=deadline, session=session)
            elif strategy == 'fifo':
                release_waiting_requests_fifo(rse_id, count=to_be_released, direction=direction, session=session)
        else:
            logger(logging.DEBUG, "Throttler has done nothing on rse %s (transfer > 0.8 * threshold)" % rse_name)
    elif waiting > 0 or not threshold:
        logger(logging.DEBUG, "Throttler remove limits(threshold: %s) and release all waiting requests, rse %s" % (threshold, rse_name))
        delete_rse_transfer_limits(rse_id, activity='all_activities', session=session)
        release_all_waiting_requests(rse_id, direction=direction, session=session)
        record_counter('daemons.conveyor.throttler.delete_rse_transfer_limits.{activity}.{rse}', labels={'activity': 'all_activities', 'rse': rse_name})


def __release_per_activity(stats, direction, rse_name, rse_id, logger, session):
    """
    Release requests per activity.

    :param stats:          Request statistics
    :param direction:      String whether request statistics are based on source or destination RSEs.
    :param rse_name:       RSE name.
    :param rse_id:         RSE id.
    """
    for activity in stats['activities']:
        threshold = stats['activities'][activity]['threshold']
        transfer = stats['activities'][activity]['transfer']
        waiting = stats['activities'][activity]['waiting']
        if waiting:
            logger(logging.DEBUG, "Request status for %s at %s: %s" % (activity, rse_name,
                                                                       stats['activities'][activity]))
            if threshold is None:
                logger(logging.DEBUG, "Throttler remove limits(threshold: %s) and release all waiting requests for activity %s, rse_id %s" % (threshold, activity, rse_id))
                delete_rse_transfer_limits(rse_id, activity=activity, session=session)
                release_all_waiting_requests(rse_id, activity=activity, direction=direction, session=session)
                record_counter('daemons.conveyor.throttler.delete_rse_transfer_limits.{activity}.{rse}', labels={'activity': activity, 'rse': rse_name})
            elif transfer + waiting > threshold:
                logger(logging.DEBUG, "Throttler set limits for activity %s, rse %s" % (activity, rse_name))
                set_rse_transfer_limits(rse_id, activity=activity, max_transfers=threshold, transfers=transfer, waitings=waiting, session=session)
                record_gauge('daemons.conveyor.throttler.set_rse_transfer_limits.{activity}.{rse}.{limit_attr}', threshold, labels={'activity': activity, 'rse': rse_name, 'limit_attr': 'max_transfers'})
                record_gauge('daemons.conveyor.throttler.set_rse_transfer_limits.{activity}.{rse}.{limit_attr}', transfer, labels={'activity': activity, 'rse': rse_name, 'limit_attr': 'transfers'})
                record_gauge('daemons.conveyor.throttler.set_rse_transfer_limits.{activity}.{rse}.{limit_attr}', waiting, labels={'activity': activity, 'rse': rse_name, 'limit_attr': 'waiting'})
                if transfer < 0.8 * threshold:
                    # release requests on account
                    nr_accounts = len(stats['activities'][activity]['accounts'])
                    if nr_accounts < 1:
                        nr_accounts = 1
                    to_release = threshold - transfer
                    threshold_per_account = math.ceil(threshold / nr_accounts)
                    to_release_per_account = math.ceil(to_release / nr_accounts)
                    accounts = stats['activities'][activity]['accounts']
                    for account in accounts:
                        if nr_accounts == 1:
                            logger(logging.DEBUG, "Throttler release %s waiting requests for activity %s, rse %s, account %s " % (to_release, activity, rse_name, account))
                            release_waiting_requests_fifo(rse_id, activity=activity, account=account, count=to_release, direction=direction, session=session)
                            record_gauge('daemons.conveyor.throttler.release_waiting_requests.{activity}.{rse}.{account}', to_release, labels={'activity': activity, 'rse': rse_name, 'account': account})
                        elif accounts[account]['transfer'] > threshold_per_account:
                            logger(logging.DEBUG, "Throttler will not release  %s waiting requests for activity %s, rse %s, account %s: It queued more transfers than its share " %
                                   (accounts[account]['waiting'], activity, rse_name, account))
                            nr_accounts -= 1
                            to_release_per_account = math.ceil(to_release / nr_accounts)
                        elif accounts[account]['waiting'] < to_release_per_account:
                            logger(logging.DEBUG, "Throttler release %s waiting requests for activity %s, rse %s, account %s " % (accounts[account]['waiting'], activity, rse_name, account))
                            release_waiting_requests_fifo(rse_id, activity=activity, account=account, count=accounts[account]['waiting'], direction=direction, session=session)
                            record_gauge('daemons.conveyor.throttler.release_waiting_requests.{activity}.{rse}.{account}', accounts[account]['waiting'], labels={'activity': activity, 'rse': rse_name, 'account': account})
                            to_release = to_release - accounts[account]['waiting']
                            nr_accounts -= 1
                            to_release_per_account = math.ceil(to_release / nr_accounts)
                        else:
                            logger(logging.DEBUG, "Throttler release %s waiting requests for activity %s, rse %s, account %s " % (to_release_per_account, activity, rse_name, account))
                            release_waiting_requests_fifo(rse_id, activity=activity, account=account, count=to_release_per_account, direction=direction, session=session)
                            record_gauge('daemons.conveyor.throttler.release_waiting_requests.{activity}.{rse}.{account}', to_release_per_account, labels={'activity': activity, 'rse': rse_name, 'account': account})
                            to_release = to_release - to_release_per_account
                            nr_accounts -= 1
                else:
                    logger(logging.DEBUG, "Throttler has done nothing for activity %s on rse %s (transfer > 0.8 * threshold)" % (activity, rse_name))
            elif waiting > 0:
                logger(logging.DEBUG, "Throttler remove limits(threshold: %s) and release all waiting requests for activity %s, rse %s" % (threshold, activity, rse_name))
                delete_rse_transfer_limits(rse_id, activity=activity, session=session)
                release_all_waiting_requests(rse_id, activity=activity, direction=direction, session=session)
                record_counter('daemons.conveyor.throttler.delete_rse_transfer_limits.{activity}.{rse}', labels={'activity': activity, 'rse': rse_name})
