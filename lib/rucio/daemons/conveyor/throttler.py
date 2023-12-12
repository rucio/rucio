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
import threading
import traceback
from collections import defaultdict
from types import FrameType
from typing import TYPE_CHECKING, Optional

import math
from sqlalchemy import null

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.logging import setup_logging
from rucio.core.monitor import MetricManager
from rucio.core.request import (get_request_stats, release_all_waiting_requests, release_waiting_requests_fifo,
                                release_waiting_requests_grouped_fifo, set_transfer_limit_stats, re_sync_all_transfer_limits,
                                reset_stale_waiting_requests)
from rucio.core.rse import RseCollection
from rucio.core.transfer import applicable_rse_transfer_limits
from rucio.daemons.common import db_workqueue, ProducerConsumerDaemon
from rucio.db.sqla.constants import RequestState, TransferLimitDirection

if TYPE_CHECKING:
    from rucio.daemons.common import HeartbeatHandler

GRACEFUL_STOP = threading.Event()
METRICS = MetricManager(module=__name__)
DAEMON_NAME = 'conveyor-throttler'


def throttler(
        once=False,
        sleep_time=600,
        partition_wait_time=10
):
    """
    Main loop to check rse transfer limits.
    """

    logging.info('Throttler starting')

    @db_workqueue(
        once=once,
        graceful_stop=GRACEFUL_STOP,
        executable=DAEMON_NAME,
        partition_wait_time=partition_wait_time,
        sleep_time=sleep_time)
    def _db_producer(*, activity: str, heartbeat_handler: "HeartbeatHandler"):
        worker_number, total_workers, logger = heartbeat_handler.live()
        if worker_number != 0:
            logger(logging.INFO, 'Throttler thread id is not 0, will sleep. Only thread 0 will work')
            return True, None

        re_sync_all_transfer_limits()
        rse_collection = RseCollection()
        release_groups = _get_request_stats(rse_collection, logger=logger)
        return True, release_groups

    def _consumer(release_groups):
        if release_groups is None:
            return
        logger = logging.log
        logger(logging.INFO, "Throttler - schedule requests")
        try:
            _handle_requests(release_groups, logger=logger)
        except Exception:
            logger(logging.CRITICAL, "Failed to schedule requests, error: %s" % (traceback.format_exc()))
        reset_stale_waiting_requests()

    ProducerConsumerDaemon(
        producers=[_db_producer],
        consumers=[_consumer],
        graceful_stop=GRACEFUL_STOP,
    ).run()


def stop(signum: Optional[int] = None, frame: Optional[FrameType] = None) -> None:
    """
    Graceful exit.
    """

    GRACEFUL_STOP.set()


def run(once=False, sleep_time=600):
    """
    Starts up the conveyer threads.
    """
    setup_logging(process_name=DAEMON_NAME)

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    throttler(once=once, sleep_time=sleep_time)


class RequestGrouper:

    class RseStatistic:
        def __init__(self):
            self.sources_with_limits = set()
            self.destinations_with_limits = set()
            self.unavailable_sources = set()
            self.unavailable_destinations = set()
            self.has_any_per_activity_limit = False
            self.any_source_has_per_activity_limit = False
            self.any_destination_has_per_activity_limit = False

    def __init__(self):
        self.waiting_transfer_groups = {}
        self.rse_stats = defaultdict(self.RseStatistic)

    def record_waiting_request_group(self, source_rse, dest_rse, activity, applicable_limits):
        """
        Record a group of requests in waiting state, while computing some statistics about them.
        """

        src_info = self.rse_stats[source_rse]
        dst_info = self.rse_stats[dest_rse]

        if dest_rse and not dest_rse.columns['availability_write']:
            src_info.unavailable_destinations.add(dest_rse)
        if source_rse and not source_rse.columns['availability_read']:
            dst_info.unavailable_sources.add(source_rse)
        for limit_stat in applicable_limits:
            limit = limit_stat['limit']
            limit_is_per_activity = limit['activity'] is not None
            if source_rse and limit['direction'] == TransferLimitDirection.SOURCE:
                src_info.has_any_per_activity_limit |= limit_is_per_activity
                dst_info.sources_with_limits.add(source_rse)
                dst_info.any_source_has_per_activity_limit |= limit_is_per_activity
            else:
                dst_info.has_any_per_activity_limit |= limit_is_per_activity
                src_info.destinations_with_limits.add(dest_rse)
                src_info.any_destination_has_per_activity_limit |= limit_is_per_activity

        self.waiting_transfer_groups[source_rse, dest_rse, activity] = applicable_limits

    def merged_groups(self):
        """
        Merge groups which can be handled together
        """

        merged_groups = {}
        for (source_rse, dest_rse, activity), applicable_limits in self.waiting_transfer_groups.items():

            src_info = self.rse_stats[source_rse]
            dst_info = self.rse_stats[dest_rse]

            if not dst_info.sources_with_limits and not dst_info.unavailable_sources:
                # None of the RSEs used as sources towards dest_rse has a limit configured
                # And none of them is unavailable.
                # It is possible to handle all waiting requests from any source in a single bulk
                source_rse = None

            if source_rse and not src_info.destinations_with_limits and not src_info.unavailable_destinations:
                # All waiting requests from this source to any of the destination rses can be handled together
                dest_rse = None

            if source_rse and dest_rse:
                if not dst_info.has_any_per_activity_limit and not src_info.has_any_per_activity_limit:
                    # All limits for this source/destination pair are configured per "all_activities",
                    # We can thus handle all activities in a single bulk.
                    activity = None
            elif dest_rse:
                if not dst_info.has_any_per_activity_limit and not dst_info.any_source_has_per_activity_limit:
                    # All limits, on all sources est_rse are configured
                    # per "all_activities". We don't need to handle each activity separately.
                    activity = None
            elif source_rse:
                if not src_info.has_any_per_activity_limit and not src_info.any_destination_has_per_activity_limit:
                    activity = None

            merged_groups.setdefault((source_rse, dest_rse, activity), applicable_limits)

        return merged_groups


def _get_request_stats(rse_collection: RseCollection, *, logger=logging.log):
    """
    Group waiting requests into arbitrary groups for bulk handling.
    The current grouping (source rse + dest rse + activity) was dictated
    by SQL queries used to release requests later in the throttler.
    Any combination of the group attributes can be None. For example,
    if activity and source rse are None, later code will work on all
    requests towards their common destination rse in one go.

    For each group, find the limits which apply to that group. The same
    limit can be shared by multiple groups.

    For each limit, compute the total number of active and waiting transfers
    subject to that limit.
    """
    logging.info("Throttler retrieve requests statistics")

    db_stats = get_request_stats(
        state=[RequestState.QUEUED,
               RequestState.SUBMITTING,
               RequestState.SUBMITTED,
               RequestState.WAITING],
    )

    # for each active limit, compute how many waiting and active transfers are currently in the database
    limit_stats = {}
    # for each group of (source_rse, destination_rse, activity) of waiting requests, find the limits which must be enforced
    grouper = RequestGrouper()
    for db_stat in db_stats:
        account = db_stat.account
        state = db_stat.state
        counter = db_stat.counter
        activity = db_stat.activity

        try:
            dest_rse = rse_collection[db_stat.dest_rse_id].ensure_loaded(load_transfer_limits=True, load_name=True, load_columns=True)
        except exception.RSENotFound:
            logger(logging.INFO, "Destination RSE {} not found. Probably deleted.", db_stat.dest_rse_id)
            continue
        source_rse = None
        if db_stat.source_rse_id:
            try:
                source_rse = rse_collection[db_stat.source_rse_id].ensure_loaded(load_transfer_limits=True, load_name=True, load_columns=True)
            except exception.RSENotFound:
                logger(logging.INFO, "Source RSE {} not found. Probably deleted.", db_stat.source_rse_id)
                continue

        source_limits = list(applicable_rse_transfer_limits(activity=activity, source_rse=source_rse))
        dest_limits = list(applicable_rse_transfer_limits(activity=activity, dest_rse=dest_rse))
        limits = source_limits + dest_limits

        if counter and (limits or state == RequestState.WAITING):
            applicable_limits = []
            for limit in limits:
                limit_stat = limit_stats.setdefault(limit['id'], {})
                applicable_limits.append(limit_stat)

                if not limit_stat:
                    limit_stat.update({
                        'limit': limit,
                        'stat': {
                            'waiting': 0,
                            'active': 0,
                            'accounts': {},
                        }
                    })

                if account is None:
                    # account == None results in SQL queries which doesn't filter on account at all.
                    # While account == null() explicitly filters on "account is NULL" in the database.
                    # Here we want the second case.
                    account = null()

                stat = limit_stat['stat']
                if account not in stat['accounts']:
                    stat['accounts'][account] = {'waiting': 0, 'active': 0}

                if state == RequestState.WAITING:
                    stat['waiting'] += counter
                    stat['accounts'][account]['waiting'] += counter
                else:
                    stat['active'] += counter
                    stat['accounts'][account]['active'] += counter

            if state == RequestState.WAITING:
                grouper.record_waiting_request_group(
                    source_rse=source_rse,
                    dest_rse=dest_rse,
                    activity=activity,
                    applicable_limits=applicable_limits,
                )

    # Find the residual capacity in each of the limits
    for limit_stat in limit_stats.values():
        stat = limit_stat['stat']
        limit = limit_stat['limit']

        waiting = stat['waiting']
        active = stat['active']

        max_transfers = limit['max_transfers']

        rse_expression = limit['rse_expression']
        log_str = f'limit {"from" if limit["direction"] == "source" else "to"} {rse_expression} activity {limit["activity"]}'

        if max_transfers is None:
            # The limit was explicitly set to NULL. Release all waiting requests.
            residual_capacity = math.inf
        elif active < 0.8 * max_transfers:
            residual_capacity = max_transfers - active
        elif 0.8 * max_transfers <= active < max_transfers:
            # Don't release requests yet. We desire to release transfers in bigger bulks than the currently available capacity.
            logger(logging.DEBUG, "%s: will do nothing (active >= 0.8 * max_transfers)", log_str)
            residual_capacity = 0
        else:  # active >= max_transfers
            residual_capacity = 0
        stat['residual_capacity'] = residual_capacity

        activity = limit['activity'] or 'all_activities'
        METRICS.gauge('rse_transfer_limits.{activity}.{rse}.{limit_attr}').labels(activity=activity, rse=rse_expression, limit_attr='residual_capacity').set(residual_capacity)
        METRICS.gauge('rse_transfer_limits.{activity}.{rse}.{limit_attr}').labels(activity=activity, rse=rse_expression, limit_attr='max_transfers').set(max_transfers)
        METRICS.gauge('rse_transfer_limits.{activity}.{rse}.{limit_attr}').labels(activity=activity, rse=rse_expression, limit_attr='active').set(active)
        METRICS.gauge('rse_transfer_limits.{activity}.{rse}.{limit_attr}').labels(activity=activity, rse=rse_expression, limit_attr='waiting').set(waiting)

        if waiting:
            logger(logging.DEBUG, "%s: can release %s out of %s waiting requests", log_str, residual_capacity, waiting)

        if waiting != limit['waitings'] or active != limit['transfers']:
            set_transfer_limit_stats(limit['id'], waitings=waiting, transfers=active)

        for account, to_release_for_account in _split_threshold_per_account(stat['accounts'], total_to_release=residual_capacity):
            stat['accounts'][account]['residual_capacity'] = to_release_for_account

    release_groups = grouper.merged_groups()
    return release_groups


def _split_threshold_per_account(per_account_stats, total_to_release):
    """
    Compute how many requests to release for each account. Try to achieve a fair share of transfers between accounts.
    :param per_account_stats: a dict with how many active and waiting transfers each account has
    :param total_to_release: the total threshold allowed to be released
    :return: for each account, how many requests to release
    """

    if not per_account_stats:
        return None, total_to_release

    nr_accounts = len(per_account_stats)
    remaining_to_release = total_to_release
    remaining_accounts = nr_accounts
    for account, account_stat in sorted(per_account_stats.items(), key=lambda i: i[1]['waiting']):
        threshold_per_account = math.ceil(remaining_to_release / remaining_accounts)

        waiting = account_stat['waiting']
        to_release_for_account = min(waiting, threshold_per_account)

        yield account, to_release_for_account

        remaining_accounts -= 1
        remaining_to_release -= to_release_for_account


def _combine_limits(applicable_limits):
    """
    Take multiple limits and combines them into one single (strictest) limit which
    respects the constraints of each initial limits. This is to handle cases like:
    - source rse only allows 5 transfers; destination allows 10 -> keep the stricter limit (here: 5 transfers)
    - an RSE has multiple limits due to overlapping rse expressions -> also keep the stricter limit

    Rules:
    - for `to_release`: pick the minimum available residual capacity
    - for `max_transfers` and 'volume': just pick the minimum
    - prioritize `grouped_fifo` strategy over `fifo` (fifo being the default when not set)
    - keep the closest deadline
    """
    strategy_priorities = {
        'grouped_fifo': 1,
        'fifo': 2,
        None: 3,
    }
    to_release = math.inf
    max_transfers = None
    strategy = 'fifo'
    volume = None
    deadline = None
    for limit_stat in applicable_limits:
        limit = limit_stat['limit']
        stat = limit_stat['stat']

        to_release = min(stat['residual_capacity'], to_release)
        max_transfers = min(limit['max_transfers'], max_transfers, key=lambda x: x if x is not None else math.inf)
        strategy = min(limit['strategy'], strategy, key=lambda x: strategy_priorities.get(x, math.inf))
        volume = min(limit['volume'], volume, key=lambda x: x if x is not None else math.inf)
        deadline = min(limit['deadline'], deadline, key=lambda x: x if x is not None else math.inf)

    return to_release, strategy, volume, deadline


def _handle_requests(release_groups, logger):
    """
    Release (set to queued state) waiting requests in groups defined by release_groups.

    The same limit can be shared by multiple groups. Because of that, releasing requests
    from one group can impact how many requests may be released in other groups subjected
    to the same limit.
    """

    for (source_rse, dest_rse, activity), applicable_limits in release_groups.items():

        # Skip if dest_rse is blocklisted for write or src_rse is blocklisted for read
        if dest_rse and not dest_rse.columns['availability_write']:
            continue
        if source_rse and not source_rse.columns['availability_read']:
            continue

        source_rse_id = source_rse.id if source_rse else None
        dest_rse_id = dest_rse.id if dest_rse else None

        log_str = (f' for activity "{activity}"' if activity else '') + \
                  (f' from rse {source_rse}' if source_rse else '') + \
                  (f' to rse {dest_rse}' if dest_rse else '')

        to_release, strategy, volume, deadline = _combine_limits(applicable_limits)
        if not to_release:
            logger(logging.DEBUG, "no requests can be released%s", log_str)
            total_released = 0
        elif to_release == math.inf:
            logger(logging.DEBUG, "will release all waiting requests%s", log_str)
            total_released = release_all_waiting_requests(dest_rse_id=dest_rse_id, source_rse_id=source_rse_id, activity=activity)
        elif strategy == 'grouped_fifo':
            logger(logging.DEBUG, "will release %s remaining requests%s", to_release, log_str)
            additional_kwargs = {}
            if volume is not None:
                additional_kwargs['volume'] = volume
            if deadline is not None:
                additional_kwargs['deadline'] = deadline
            total_released = release_waiting_requests_grouped_fifo(
                source_rse_id=source_rse_id,
                dest_rse_id=dest_rse_id,
                count=to_release,
                **additional_kwargs,
            )
        else:
            total_released = 0
            to_release_for_account = {}
            limits_by_account = {}
            for limit_stat in applicable_limits:
                for account, account_limit in limit_stat['stat']['accounts'].items():
                    to_release_for_account[account] = min(to_release_for_account.get(account, to_release), account_limit['residual_capacity'])
                    limits_by_account.setdefault(account, []).append(account_limit)

            for account, to_release_account in to_release_for_account.items():
                if not to_release_account:
                    continue

                logger(logging.DEBUG, 'releasing %s waiting requests%s%s', to_release_account, log_str, f' account {account}' if account is not None else '')
                nb_released = release_waiting_requests_fifo(
                    source_rse_id=source_rse_id,
                    dest_rse_id=dest_rse_id,
                    count=to_release_account,
                    activity=activity,
                    account=account,
                )
                total_released += nb_released

                for stat in limits_by_account[account]:
                    stat['residual_capacity'] -= nb_released

        if total_released:
            for limit_stat in applicable_limits:
                rse_expression = limit_stat['limit']['rse_expression']
                limit_stat['stat']['residual_capacity'] -= total_released
                METRICS.counter('released_waiting_requests.{activity}.{rse}').labels(activity=activity, rse=rse_expression).inc(total_released)
