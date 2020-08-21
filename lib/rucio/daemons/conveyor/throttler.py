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
# - Wen Guan <wen.guan@cern.ch>, 2016
# - Vincent Garonne <vincent.garonne@cern.ch>, 2016-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

"""
Conveyor throttler is a daemon to manage rucio internal queue.
"""

from __future__ import division

import logging
import math
import os
import socket
import sys
import threading
import time
import traceback

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get
from rucio.common.utils import get_parsed_throttler_mode
from rucio.core import heartbeat, config as config_core
from rucio.core.monitor import record_counter, record_gauge
from rucio.core.request import get_stats_by_activity_direction_state, release_all_waiting_requests, release_waiting_requests_fifo, release_waiting_requests_grouped_fifo
from rucio.core.rse import get_rse, set_rse_transfer_limits, delete_rse_transfer_limits, get_rse_transfer_limits
from rucio.db.sqla.constants import RequestState

logging.basicConfig(stream=sys.stdout,
                    level=getattr(logging,
                                  config_get('common', 'loglevel',
                                             raise_exception=False,
                                             default='DEBUG').upper()),
                    format='%(asctime)s\t%(process)d\t%(levelname)s\t%(message)s')

graceful_stop = threading.Event()


def throttler(once=False, sleep_time=600):
    """
    Main loop to check rse transfer limits.
    """

    logging.info('Throttler starting')

    executable = 'conveyor-throttler'
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    # Make an initial heartbeat so that all throttlers have the correct worker number on the next try
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
    logging.info(prepend_str + 'Throttler started - timeout (%s)' % (sleep_time))

    current_time = time.time()
    graceful_stop.wait(10)

    while not graceful_stop.is_set():

        try:
            heart_beat = heartbeat.live(executable, hostname, pid, hb_thread, older_than=3600)
            prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
            if heart_beat['assign_thread'] != 0:
                logging.info(prepend_str + 'Throttler thread id is not 0, will sleep. Only thread 0 will work')
                if once:
                    break
                if time.time() < current_time + sleep_time:
                    graceful_stop.wait(int((current_time + sleep_time) - time.time()))
                current_time = time.time()
                continue

            logging.info(prepend_str + "Throttler - schedule requests")
            __schedule_requests()

            if once:
                break
            if time.time() < current_time + sleep_time:
                graceful_stop.wait(int((current_time + sleep_time) - time.time()))
            current_time = time.time()
        except Exception:
            logging.critical(prepend_str + 'Throtter crashed %s' % (traceback.format_exc()))

        if once:
            break

    logging.info(prepend_str + 'Throtter - graceful stop requested')

    heartbeat.die(executable, hostname, pid, hb_thread)

    logging.info(prepend_str + 'Throtter - graceful stop done')


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, sleep_time=600):
    """
    Starts up the conveyer threads.
    """
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
            threads = [thread.join(timeout=3.14) for thread in threads if thread and thread.isAlive()]


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


def __schedule_requests():
    """
    Schedule requests
    """
    try:
        throttler_mode = config_core.get('throttler', 'mode', default='DEST_PER_ACT', use_cache=False)
        direction, all_activities = get_parsed_throttler_mode(throttler_mode)
        result_dict = __get_request_stats(all_activities, direction)
        if direction == 'destination' or direction == 'source':
            for rse_id in result_dict:
                rse_name = result_dict[rse_id]['rse']
                availability = get_rse(rse_id).availability
                # dest_rse is not blacklisted for write or src_rse is not blacklisted for read
                if (direction == 'destination' and availability & 2) or (direction == 'source' and availability & 4):
                    if all_activities:
                        __release_all_activities(result_dict[rse_id], direction, rse_name, rse_id)
                    else:
                        __release_per_activity(result_dict[rse_id], direction, rse_name, rse_id)
    except Exception:
        logging.critical("Failed to schedule requests, error: %s" % (traceback.format_exc()))


def __release_all_activities(stats, direction, rse_name, rse_id):
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
        record_gauge('daemons.conveyor.throttler.set_rse_transfer_limits.%s.max_transfers' % (rse_name), threshold)
        record_gauge('daemons.conveyor.throttler.set_rse_transfer_limits.%s.transfers' % (rse_name), transfer)
        record_gauge('daemons.conveyor.throttler.set_rse_transfer_limits.%s.waitings' % (rse_name), waiting)
        if transfer < 0.8 * threshold:
            to_be_released = threshold - transfer
            if strategy == 'grouped_fifo':
                deadline = stats.get('deadline')
                volume = stats.get('volume')
                release_waiting_requests_grouped_fifo(rse_id, count=to_be_released, direction=direction, volume=volume, deadline=deadline)
            elif strategy == 'fifo':
                release_waiting_requests_fifo(rse_id, count=to_be_released, direction=direction)
        else:
            logging.debug("Throttler has done nothing on rse %s (transfer > 0.8 * threshold)" % rse_name)
    elif waiting > 0 or not threshold:
        logging.debug("Throttler remove limits(threshold: %s) and release all waiting requests, rse %s" % (threshold, rse_name))
        delete_rse_transfer_limits(rse_id, activity='all_activities')
        release_all_waiting_requests(rse_id, direction=direction)
        record_counter('daemons.conveyor.throttler.delete_rse_transfer_limits.%s' % (rse_name))


def __release_per_activity(stats, direction, rse_name, rse_id):
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
            logging.debug("Request status for %s at %s: %s" % (activity, rse_name,
                                                               stats['activities'][activity]))
            if threshold is None:
                logging.debug("Throttler remove limits(threshold: %s) and release all waiting requests for activity %s, rse_id %s" % (threshold, activity, rse_id))
                delete_rse_transfer_limits(rse_id, activity=activity)
                release_all_waiting_requests(rse_id, activity=activity, direction=direction)
                record_counter('daemons.conveyor.throttler.delete_rse_transfer_limits.%s.%s' % (activity, rse_name))
            elif transfer + waiting > threshold:
                logging.debug("Throttler set limits for activity %s, rse %s" % (activity, rse_name))
                set_rse_transfer_limits(rse_id, activity=activity, max_transfers=threshold, transfers=transfer, waitings=waiting)
                record_gauge('daemons.conveyor.throttler.set_rse_transfer_limits.%s.%s.max_transfers' % (activity, rse_name), threshold)
                record_gauge('daemons.conveyor.throttler.set_rse_transfer_limits.%s.%s.transfers' % (activity, rse_name), transfer)
                record_gauge('daemons.conveyor.throttler.set_rse_transfer_limits.%s.%s.waitings' % (activity, rse_name), waiting)
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
                            logging.debug("Throttler release %s waiting requests for activity %s, rse %s, account %s " % (to_release, activity, rse_name, account))
                            release_waiting_requests_fifo(rse_id, activity=activity, account=account, count=to_release, direction=direction)
                            record_gauge('daemons.conveyor.throttler.release_waiting_requests.%s.%s.%s' % (activity, rse_name, account), to_release)
                        elif accounts[account]['transfer'] > threshold_per_account:
                            logging.debug("Throttler will not release  %s waiting requests for activity %s, rse %s, account %s: It queued more transfers than its share " %
                                          (accounts[account]['waiting'], activity, rse_name, account))
                            nr_accounts -= 1
                            to_release_per_account = math.ceil(to_release / nr_accounts)
                        elif accounts[account]['waiting'] < to_release_per_account:
                            logging.debug("Throttler release %s waiting requests for activity %s, rse %s, account %s " % (accounts[account]['waiting'], activity, rse_name, account))
                            release_waiting_requests_fifo(rse_id, activity=activity, account=account, count=accounts[account]['waiting'], direction=direction)
                            record_gauge('daemons.conveyor.throttler.release_waiting_requests.%s.%s.%s' % (activity, rse_name, account), accounts[account]['waiting'])
                            to_release = to_release - accounts[account]['waiting']
                            nr_accounts -= 1
                            to_release_per_account = math.ceil(to_release / nr_accounts)
                        else:
                            logging.debug("Throttler release %s waiting requests for activity %s, rse %s, account %s " % (to_release_per_account, activity, rse_name, account))
                            release_waiting_requests_fifo(rse_id, activity=activity, account=account, count=to_release_per_account, direction=direction)
                            record_gauge('daemons.conveyor.throttler.release_waiting_requests.%s.%s.%s' % (activity, rse_name, account), to_release_per_account)
                            to_release = to_release - to_release_per_account
                            nr_accounts -= 1
                else:
                    logging.debug("Throttler has done nothing for activity %s on rse %s (transfer > 0.8 * threshold)" % (activity, rse_name))
            elif waiting > 0:
                logging.debug("Throttler remove limits(threshold: %s) and release all waiting requests for activity %s, rse %s" % (threshold, activity, rse_name))
                delete_rse_transfer_limits(rse_id, activity=activity)
                release_all_waiting_requests(rse_id, activity=activity, direction=direction)
                record_counter('daemons.conveyor.throttler.delete_rse_transfer_limits.%s.%s' % (activity, rse_name))
