# Copyright 2016-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Wen Guan <wguan.icedew@gmail.com>, 2016
# - Vincent Garonne <vgaronne@gmail.com>, 2016-2018
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Cedric Serfon <cedric.serfon@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
#
# PY3K COMPATIBLE

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


from rucio.common.config import config_get
from rucio.core import heartbeat
from rucio.core.monitor import record_counter, record_gauge
from rucio.core.request import get_stats_by_activity_dest_state, release_waiting_requests
from rucio.core.rse import get_rse, set_rse_transfer_limits, delete_rse_transfer_limits
from rucio.core.transfer_limits import get_config_limit
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

    executable = 'throttler'
    hostname = socket.getfqdn()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heartbeat.sanity_check(executable=executable, hostname=hostname)
    # Make an initial heartbeat so that all throttlers have the correct worker number on the next try
    heart_beat = heartbeat.live(executable, hostname, pid, hb_thread)
    prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'] + 1, heart_beat['nr_threads'])
    logging.info(prepend_str + 'Throttler started - timeout (%s)' % (sleep_time))

    current_time = time.time()
    graceful_stop.wait(10)

    while not graceful_stop.is_set():

        try:
            heart_beat = heartbeat.live(executable, hostname, pid, hb_thread, older_than=3600)
            prepend_str = 'Thread [%i/%i] : ' % (heart_beat['assign_thread'] + 1, heart_beat['nr_threads'])
            if heart_beat['assign_thread'] != 0:
                logging.info(prepend_str + 'Throttler thread id is not 1, will sleep. Only thread 1 will work')
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
    threads = []
    logging.info('starting throttler thread')
    throttler_thread = threading.Thread(target=throttler, kwargs={'once': once, 'sleep_time': sleep_time})

    threads.append(throttler_thread)
    [thread.start() for thread in threads]

    logging.info('waiting for interrupts')

    # Interruptible joins require a timeout.
    while threads:
        threads = [thread.join(timeout=3.14) for thread in threads if thread and thread.isAlive()]


def __schedule_requests():
    """
    Schedule requests
    """
    try:
        logging.info("Throttler retrieve requests statistics")
        results = get_stats_by_activity_dest_state(state=[RequestState.QUEUED,
                                                          RequestState.SUBMITTING,
                                                          RequestState.SUBMITTED,
                                                          RequestState.WAITING])
        result_dict = {}
        for activity, dest_rse_id, account, state, rse, counter in results:
            threshold = get_config_limit(activity, dest_rse_id)

            if threshold or (counter and (state == RequestState.WAITING)):
                if activity not in result_dict:
                    result_dict[activity] = {}
                if dest_rse_id not in result_dict[activity]:
                    result_dict[activity][dest_rse_id] = {'waiting': 0,
                                                          'transfer': 0,
                                                          'threshold': threshold,
                                                          'accounts': {},
                                                          'rse': rse}
                if account not in result_dict[activity][dest_rse_id]['accounts']:
                    result_dict[activity][dest_rse_id]['accounts'][account] = {'waiting': 0, 'transfer': 0}
                if state == RequestState.WAITING:
                    result_dict[activity][dest_rse_id]['accounts'][account]['waiting'] += counter
                    result_dict[activity][dest_rse_id]['waiting'] += counter
                else:
                    result_dict[activity][dest_rse_id]['accounts'][account]['transfer'] += counter
                    result_dict[activity][dest_rse_id]['transfer'] += counter

        for activity in result_dict:
            for dest_rse_id in result_dict[activity]:
                rse_name = result_dict[activity][dest_rse_id]['rse']
                availability = get_rse(rse_name).availability
                if availability & 2:  # dest_rse is not blacklisted for write
                    threshold = result_dict[activity][dest_rse_id]['threshold']
                    transfer = result_dict[activity][dest_rse_id]['transfer']
                    waiting = result_dict[activity][dest_rse_id]['waiting']
                    if waiting:
                        logging.debug("Request status for %s at %s: %s" % (activity, rse_name,
                                                                           result_dict[activity][dest_rse_id]))
                    if threshold is None:
                        logging.debug("Throttler remove limits(threshold: %s) and release all waiting requests for activity %s, rse_id %s" % (threshold, activity, dest_rse_id))
                        delete_rse_transfer_limits(rse=None, activity=activity, rse_id=dest_rse_id)
                        release_waiting_requests(rse=None, activity=activity, rse_id=dest_rse_id)
                        record_counter('daemons.conveyor.throttler.delete_rse_transfer_limits.%s.%s' % (activity, rse_name))
                    elif transfer + waiting > threshold:
                        logging.debug("Throttler set limits for activity %s, rse %s" % (activity, rse_name))
                        set_rse_transfer_limits(rse=None, activity=activity, rse_id=dest_rse_id, max_transfers=threshold, transfers=transfer, waitings=waiting)
                        record_gauge('daemons.conveyor.throttler.set_rse_transfer_limits.%s.%s.max_transfers' % (activity, rse_name), threshold)
                        record_gauge('daemons.conveyor.throttler.set_rse_transfer_limits.%s.%s.transfers' % (activity, rse_name), transfer)
                        record_gauge('daemons.conveyor.throttler.set_rse_transfer_limits.%s.%s.waitings' % (activity, rse_name), waiting)
                        if transfer < 0.8 * threshold:
                            # release requests on account
                            nr_accounts = len(result_dict[activity][dest_rse_id]['accounts'])
                            if nr_accounts < 1:
                                nr_accounts = 1
                            to_release = threshold - transfer
                            threshold_per_account = math.ceil(threshold / nr_accounts)
                            to_release_per_account = math.ceil(to_release / nr_accounts)
                            accounts = result_dict[activity][dest_rse_id]['accounts']
                            for account in accounts:
                                if nr_accounts == 1:
                                    logging.debug("Throttler release %s waiting requests for activity %s, rse %s, account %s " % (to_release, activity, rse_name, account))
                                    release_waiting_requests(rse=None, activity=activity, rse_id=dest_rse_id, account=account, count=to_release)
                                    record_gauge('daemons.conveyor.throttler.release_waiting_requests.%s.%s.%s' % (activity, rse_name, account), to_release)
                                elif accounts[account]['transfer'] > threshold_per_account:
                                    logging.debug("Throttler will not release  %s waiting requests for activity %s, rse %s, account %s: It queued more transfers than its share " %
                                                  (accounts[account]['waiting'], activity, rse_name, account))
                                    nr_accounts -= 1
                                    to_release_per_account = math.ceil(to_release / nr_accounts)
                                elif accounts[account]['waiting'] < to_release_per_account:
                                    logging.debug("Throttler release %s waiting requests for activity %s, rse %s, account %s " % (accounts[account]['waiting'], activity, rse_name, account))
                                    release_waiting_requests(rse=None, activity=activity, rse_id=dest_rse_id, account=account, count=accounts[account]['waiting'])
                                    record_gauge('daemons.conveyor.throttler.release_waiting_requests.%s.%s.%s' % (activity, rse_name, account), accounts[account]['waiting'])
                                    to_release = to_release - accounts[account]['waiting']
                                    nr_accounts -= 1
                                    to_release_per_account = math.ceil(to_release / nr_accounts)
                                else:
                                    logging.debug("Throttler release %s waiting requests for activity %s, rse %s, account %s " % (to_release_per_account, activity, rse_name, account))
                                    release_waiting_requests(rse=None, activity=activity, rse_id=dest_rse_id, account=account, count=to_release_per_account)
                                    record_gauge('daemons.conveyor.throttler.release_waiting_requests.%s.%s.%s' % (activity, rse_name, account), to_release_per_account)
                                    to_release = to_release - to_release_per_account
                                    nr_accounts -= 1
                        else:
                            logging.debug("Throttler has done nothing for activity %s on rse %s (transfer > 0.8 * threshold)" % (activity, rse_name))

                    elif waiting > 0:
                        logging.debug("Throttler remove limits(threshold: %s) and release all waiting requests for activity %s, rse %s" % (threshold, activity, rse_name))
                        delete_rse_transfer_limits(rse=None, activity=activity, rse_id=dest_rse_id)
                        release_waiting_requests(rse=None, activity=activity, rse_id=dest_rse_id)
                        record_counter('daemons.conveyor.throttler.delete_rse_transfer_limits.%s.%s' % (activity, rse_name))
    except Exception:
        logging.critical("Failed to schedule requests, error: %s" % (traceback.format_exc()))
