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
# - Martin Barisits <martin.barisits@cern.ch>, 2016
# - Cedric Serfon <cedric.serfon@cern.ch>, 2017-2022
# - Vincent Garonne <vincent.garonne@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Thomas Beermann <thomas.beermann@cern.ch>, 2021

"""
BB8 is a daemon the re-balance data between RSEs.
"""

import logging
import socket
import threading
import time
import os

from sqlalchemy import func, or_, and_
from rucio.db.sqla.session import read_session

from rucio.db.sqla import models
from rucio.db.sqla.constants import RuleState, LockState
from rucio.common.exception import InvalidRSEExpression
from rucio.common.logging import formatted_logger, setup_logging
from rucio.core import config as config_core
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.heartbeat import live, die, sanity_check, list_payload_counts
from rucio.core.rse import get_rse_usage
from rucio.daemons.bb8.common import rebalance_rse


GRACEFUL_STOP = threading.Event()


def rule_rebalancer(rse_expression, move_subscriptions=False, use_dump=False, sleep_time=300, once=True, dry_run=False):
    """
    Main loop to rebalancer rules automatically
    """

    total_rebalance_volume = 0
    executable = 'rucio-bb8'
    hostname = socket.gethostname()
    pid = os.getpid()
    hb_thread = threading.current_thread()
    heart_beat = live(executable, hostname, pid, hb_thread)
    prepend_str = 'bb8[%i/%i] ' % (heart_beat['assign_thread'], heart_beat['nr_threads'])
    logger = formatted_logger(logging.log, prepend_str + '%s')
    logger(logging.DEBUG, 'rse_expression: %s', rse_expression)
    logger(logging.INFO, 'BB8 started')

    while not GRACEFUL_STOP.is_set():
        logger(logging.INFO, 'Starting new cycle')
        heart_beat = live(executable, hostname, pid, hb_thread)
        start_time = time.time()
        total_rebalance_volume = 0
        tolerance = config_core.get('bb8', 'tolerance', default=0.05)
        max_total_rebalance_volume = config_core.get('bb8', 'max_total_rebalance_volume', default=10 * 1E12)
        max_rse_rebalance_volume = config_core.get('bb8', 'max_rse_rebalance_volume', default=500 * 1E9)
        min_total = config_core.get('bb8', 'min_total', default=20 * 1E9)
        payload_cnt = list_payload_counts(executable, older_than=600, hash_executable=None, session=None)
        if rse_expression in payload_cnt:
            logger(logging.WARNING, 'One BB8 instance already running with the same RSE expression. Stopping')
            break
        else:
            # List the RSEs represented by rse_expression
            try:
                rses = [rse for rse in parse_expression(rse_expression)]
                list_rses2 = [rse['rse'] for rse in rses]
            except InvalidRSEExpression as err:
                logger(logging.ERROR, err)
                break
            # List the RSEs represented by all the RSE expressions stored in heartbeat payload
            list_rses1 = []
            for rse_exp in payload_cnt:
                if rse_exp:
                    list_rses1 = [rse['rse'] for rse in parse_expression(rse_exp)]
            for rse in list_rses2:
                if rse in list_rses1:
                    logger(logging.WARNING, 'Overlapping RSE expressions %s vs %s. Stopping', rse_exp, rse_expression)
                    break

            logger(logging.INFO, 'Will process rebalancing on %s', rse_expression)
            heart_beat = live(executable, hostname, pid, hb_thread, older_than=max(600, sleep_time), hash_executable=None, payload=rse_expression, session=None)
            total_primary = 0
            total_secondary = 0
            total_total = 0
            global_ratio = float(0)
            for rse in rses:
                logger(logging.DEBUG, 'Getting RSE usage on %s', rse['rse'])
                rse_usage = get_rse_usage(rse_id=rse['id'])
                usage_dict = {}
                for item in rse_usage:
                    # TODO Check last update
                    usage_dict[item['source']] = {'used': item['used'], 'free': item['free'], 'total': item['total']}

                try:
                    rse['primary'] = usage_dict['rucio']['used'] - usage_dict['expired']['used']
                    rse['secondary'] = usage_dict['expired']['used']
                    rse['total'] = usage_dict['storage']['total'] - usage_dict['min_free_space']['used']
                    rse['ratio'] = float(rse['primary']) / float(rse['total'])
                except KeyError as err:
                    logger(logging.ERROR, 'Missing source usage %s for RSE %s. Exiting', err, rse['rse'])
                    break
                total_primary += rse['primary']
                total_secondary += rse['secondary']
                total_total += float(rse['total'])
                rse['receive_volume'] = 0  # Already rebalanced volume in this run
                global_ratio = float(total_primary) / float(total_total)
                logger(logging.INFO, 'Global ratio: %f' % (global_ratio))

            for rse in sorted(rses, key=lambda k: k['ratio']):
                logger(logging.INFO, '%s Sec/Prim local ratio (%f) vs global %s', rse['rse'], rse['ratio'], global_ratio)
            rses_over_ratio = sorted([rse for rse in rses if rse['ratio'] > global_ratio + global_ratio * tolerance], key=lambda k: k['ratio'], reverse=True)
            rses_under_ratio = sorted([rse for rse in rses if rse['ratio'] < global_ratio - global_ratio * tolerance], key=lambda k: k['ratio'], reverse=False)

            # Excluding RSEs
            logger(logging.DEBUG, 'Excluding RSEs as destination which are too small by size:')
            for des in rses_under_ratio:
                if des['total'] < min_total:
                    logger(logging.DEBUG, 'Excluding %s', des['rse'])
                    rses_under_ratio.remove(des)
            logger(logging.DEBUG, 'Excluding RSEs as sources which are too small by size:')
            for src in rses_over_ratio:
                if src['total'] < min_total:
                    logger(logging.DEBUG, 'Excluding %s', src['rse'])
                    rses_over_ratio.remove(src)
            logger(logging.DEBUG, 'Excluding RSEs as destinations which are not available for write:')
            for des in rses_under_ratio:
                if des['availability'] & 2 == 0:
                    logger(logging.DEBUG, 'Excluding %s', des['rse'])
                    rses_under_ratio.remove(des)
            logger(logging.DEBUG, 'Excluding RSEs as sources which are not available for read:')
            for src in rses_over_ratio:
                if src['availability'] & 4 == 0:
                    logger(logging.DEBUG, 'Excluding %s', src['rse'])
                    rses_over_ratio.remove(src)

            # Gets the number of active transfers per location
            dict_locks = get_active_locks(session=None)

            # Loop over RSEs over the ratio
            for index, source_rse in enumerate(rses_over_ratio):

                # The volume that would be rebalanced, not real availability of the data:
                available_source_rebalance_volume = int((source_rse['primary'] - global_ratio * source_rse['secondary']) / (global_ratio + 1))
                if available_source_rebalance_volume > max_rse_rebalance_volume:
                    available_source_rebalance_volume = max_rse_rebalance_volume
                if available_source_rebalance_volume > max_total_rebalance_volume - total_rebalance_volume:
                    available_source_rebalance_volume = max_total_rebalance_volume - total_rebalance_volume

                # Select a target:
                for destination_rse in rses_under_ratio:
                    if available_source_rebalance_volume > 0:
                        vo_str = ' on VO {}'.format(destination_rse['vo']) if destination_rse['vo'] != 'def' else ''
                        if index == 0 and destination_rse['id'] in dict_locks:
                            replicating_volume = dict_locks[destination_rse['id']]['bytes']
                            logger(logging.DEBUG, 'Already %f TB replicating to %s%s', replicating_volume / 1E12, destination_rse['rse'], vo_str)
                            destination_rse['receive_volume'] += replicating_volume
                        if destination_rse['receive_volume'] >= max_rse_rebalance_volume:
                            continue
                        available_target_rebalance_volume = max_rse_rebalance_volume - destination_rse['receive_volume']
                        if available_target_rebalance_volume >= available_source_rebalance_volume:
                            available_target_rebalance_volume = available_source_rebalance_volume

                        logger(logging.INFO, 'Rebalance %d TB from %s(%f) to %s(%f)%s', available_target_rebalance_volume / 1E12, source_rse['rse'], source_rse['ratio'], destination_rse['rse'], destination_rse['ratio'], vo_str)
                        expr = destination_rse['rse']
                        rebalance_rse(rse_id=source_rse['id'], max_bytes=available_target_rebalance_volume, dry_run=dry_run, comment='Background rebalancing', force_expression=expr, logger=logger)

                        destination_rse['receive_volume'] += available_target_rebalance_volume
                        total_rebalance_volume += available_target_rebalance_volume
                        available_source_rebalance_volume -= available_target_rebalance_volume

        if once:
            break

        end_time = time.time()
        time_diff = end_time - start_time
        if time_diff < sleep_time:
            logger(logging.INFO, 'Sleeping for a while : %f seconds', sleep_time - time_diff)
            GRACEFUL_STOP.wait(sleep_time - time_diff)

    die(executable='rucio-bb8', hostname=hostname, pid=pid, thread=hb_thread)


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """

    GRACEFUL_STOP.set()


def run(once, rse_expression, move_subscriptions=False, use_dump=False, sleep_time=300, threads=1, dry_run=False):
    """
    Starts up the BB8 rebalancing threads.
    """

    setup_logging()
    hostname = socket.gethostname()
    sanity_check(executable='rucio-bb8', hostname=hostname)

    if once:
        rule_rebalancer(rse_expression=rse_expression, move_subscriptions=move_subscriptions, use_dump=use_dump, once=once)
    else:
        logging.info('BB8 starting %s threads', str(threads))
        threads = [threading.Thread(target=rule_rebalancer, kwargs={'once': once, 'rse_expression': rse_expression, 'sleep_time': sleep_time, 'dry_run': dry_run}) for _ in range(0, threads)]
        [thread.start() for thread in threads]
        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [thread.join(timeout=3.14) for thread in threads]


@read_session
def get_active_locks(session=None):
    locks_dict = {}
    rule_ids = session.query(models.ReplicationRule.id).filter(or_(models.ReplicationRule.state == RuleState.REPLICATING, models.ReplicationRule.state == RuleState.STUCK),
                                                               models.ReplicationRule.comments == 'Background rebalancing').all()
    for row in rule_ids:
        rule_id = row[0]
        query = session.query(func.count(), func.sum(models.ReplicaLock.bytes), models.ReplicaLock.state, models.ReplicaLock.rse_id).\
            filter(and_(models.ReplicaLock.rule_id == rule_id, models.ReplicaLock.state != LockState.OK)).group_by(models.ReplicaLock.state, models.ReplicaLock.rse_id)
        for lock in query.all():
            cnt, size, _, rse_id = lock
            if rse_id not in locks_dict:
                locks_dict[rse_id] = {'bytes': 0, 'locks': 0}
            locks_dict[rse_id]['locks'] += cnt
            locks_dict[rse_id]['bytes'] += size
    return locks_dict
