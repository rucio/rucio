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
BB8 is a daemon the re-balance data between RSEs.
"""

import functools
import logging
import socket
import threading
from typing import TYPE_CHECKING

from rucio.common.config import config_get_float
from rucio.common.exception import InvalidRSEExpression
from rucio.common.logging import setup_logging
from rucio.core.heartbeat import sanity_check, list_payload_counts
from rucio.core.rse import get_rse_usage
from rucio.core.rse_expression_parser import parse_expression
from rucio.daemons.bb8.common import rebalance_rse, get_active_locks
from rucio.daemons.common import run_daemon

if TYPE_CHECKING:
    from types import FrameType
    from typing import Optional

    from rucio.daemons.common import HeartbeatHandler

graceful_stop = threading.Event()
DAEMON_NAME = "rucio-bb8"


def rule_rebalancer(
    rse_expression: str,
    move_subscriptions: bool = False,
    use_dump: bool = False,
    sleep_time: int = 300,
    once: bool = True,
    dry_run: bool = False,
) -> None:
    """
    Create a rule_rebalancer worker

    :param rse_expression: The RSE expression where the rule rebalancing is applied.
    :param move_subscription: To allow rebalancing of subscription rules. Not implemented yet.
    :param use_dump: To use dump instead of DB query.
    :param sleep_time: Time between two cycles.
    :param once: Run only once.
    :param dry_run: To run in dry run mode (i.e. rules are not created).
    """
    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable=DAEMON_NAME,
        partition_wait_time=1,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            rse_expression=rse_expression,
            move_subscriptions=move_subscriptions,
            use_dump=use_dump,
            dry_run=dry_run,
        ),
    )


def run_once(
    heartbeat_handler: "HeartbeatHandler",
    rse_expression: str,
    move_subscriptions: bool,
    use_dump: bool,
    dry_run: bool,
    **_kwargs
) -> bool:

    must_sleep = False
    total_rebalance_volume = 0
    worker_number, total_workers, logger = heartbeat_handler.live()
    logger(logging.DEBUG, "Running BB8 on rse_expression: %s", rse_expression)
    tolerance = config_get_float("bb8", "tolerance", default=0.05)
    max_total_rebalance_volume = config_get_float(
        "bb8", "max_total_rebalance_volume", default=10 * 1e12
    )
    max_rse_rebalance_volume = config_get_float(
        "bb8", "max_rse_rebalance_volume", default=500 * 1e9
    )
    min_total = config_get_float("bb8", "min_total", default=20 * 1e9)
    payload_cnt = list_payload_counts(
        executable=DAEMON_NAME, older_than=600, hash_executable=None, session=None
    )
    if rse_expression in payload_cnt:
        logger(
            logging.WARNING,
            "One BB8 instance already running with the same RSE expression. Stopping",
        )
        must_sleep = True
        return must_sleep
    else:
        # List the RSEs represented by rse_expression
        try:
            rses = [rse for rse in parse_expression(rse_expression)]
            list_rses2 = [rse["rse"] for rse in rses]
        except InvalidRSEExpression as err:
            logger(logging.ERROR, err)
            return must_sleep
        # List the RSEs represented by all the RSE expressions stored in heartbeat payload
        list_rses1 = []
        for rse_exp in payload_cnt:
            if rse_exp:
                list_rses1 = [rse["rse"] for rse in parse_expression(rse_exp)]
        for rse in list_rses2:
            if rse in list_rses1:
                logger(
                    logging.WARNING,
                    "Overlapping RSE expressions %s vs %s. Stopping",
                    rse_exp,
                    rse_expression,
                )
                return must_sleep

        logger(logging.INFO, "Will process rebalancing on %s", rse_expression)
        worker_number, total_workers, logger = heartbeat_handler.live()
        total_primary = 0
        total_secondary = 0
        total_total = 0
        global_ratio = float(0)
        for rse in rses:
            logger(logging.DEBUG, "Getting RSE usage on %s", rse["rse"])
            rse_usage = get_rse_usage(rse_id=rse["id"])
            usage_dict = {}
            for item in rse_usage:
                # TODO Check last update
                usage_dict[item["source"]] = {
                    "used": item["used"],
                    "free": item["free"],
                    "total": item["total"],
                }

            try:
                rse["primary"] = (
                    usage_dict["rucio"]["used"] - usage_dict["expired"]["used"]
                )
                rse["secondary"] = usage_dict["expired"]["used"]
                rse["total"] = (
                    usage_dict["storage"]["total"]
                    - usage_dict["min_free_space"]["used"]
                )
                rse["ratio"] = float(rse["primary"]) / float(rse["total"])
            except KeyError as err:
                logger(
                    logging.ERROR,
                    "Missing source usage %s for RSE %s. Exiting",
                    err,
                    rse["rse"],
                )
                break
            total_primary += rse["primary"]
            total_secondary += rse["secondary"]
            total_total += float(rse["total"])
            rse["receive_volume"] = 0  # Already rebalanced volume in this run
            global_ratio = float(total_primary) / float(total_total)
            logger(logging.INFO, "Global ratio: %f" % (global_ratio))

        for rse in sorted(rses, key=lambda k: k["ratio"]):
            logger(
                logging.INFO,
                "%s Sec/Prim local ratio (%f) vs global %s",
                rse["rse"],
                rse["ratio"],
                global_ratio,
            )
        rses_over_ratio = sorted(
            [
                rse
                for rse in rses
                if rse["ratio"] > global_ratio + global_ratio * tolerance
            ],
            key=lambda k: k["ratio"],
            reverse=True,
        )
        rses_under_ratio = sorted(
            [
                rse
                for rse in rses
                if rse["ratio"] < global_ratio - global_ratio * tolerance
            ],
            key=lambda k: k["ratio"],
            reverse=False,
        )

        # Excluding RSEs
        logger(
            logging.DEBUG, "Excluding RSEs as destination which are too small by size:"
        )
        for des in rses_under_ratio:
            if des["total"] < min_total:
                logger(logging.DEBUG, "Excluding %s", des["rse"])
                rses_under_ratio.remove(des)
        logger(logging.DEBUG, "Excluding RSEs as sources which are too small by size:")
        for src in rses_over_ratio:
            if src["total"] < min_total:
                logger(logging.DEBUG, "Excluding %s", src["rse"])
                rses_over_ratio.remove(src)
        logger(
            logging.DEBUG,
            "Excluding RSEs as destinations which are not available for write:",
        )
        for des in rses_under_ratio:
            if not des["availability_write"]:
                logger(logging.DEBUG, "Excluding %s", des["rse"])
                rses_under_ratio.remove(des)
        logger(
            logging.DEBUG, "Excluding RSEs as sources which are not available for read:"
        )
        for src in rses_over_ratio:
            if not src["availability_read"]:
                logger(logging.DEBUG, "Excluding %s", src["rse"])
                rses_over_ratio.remove(src)

        # Gets the number of active transfers per location
        dict_locks = get_active_locks(session=None)

        # Loop over RSEs over the ratio
        for index, source_rse in enumerate(rses_over_ratio):

            # The volume that would be rebalanced, not real availability of the data:
            available_source_rebalance_volume = int(
                (source_rse["primary"] - global_ratio * source_rse["secondary"])
                / (global_ratio + 1)
            )
            if available_source_rebalance_volume > max_rse_rebalance_volume:
                available_source_rebalance_volume = max_rse_rebalance_volume
            if (
                available_source_rebalance_volume
                > max_total_rebalance_volume - total_rebalance_volume
            ):
                available_source_rebalance_volume = (
                    max_total_rebalance_volume - total_rebalance_volume
                )

            # Select a target:
            for destination_rse in rses_under_ratio:
                if available_source_rebalance_volume > 0:
                    vo_str = (
                        " on VO {}".format(destination_rse["vo"])
                        if destination_rse["vo"] != "def"
                        else ""
                    )
                    if index == 0 and destination_rse["id"] in dict_locks:
                        replicating_volume = dict_locks[destination_rse["id"]]["bytes"]
                        logger(
                            logging.DEBUG,
                            "Already %f TB replicating to %s%s",
                            replicating_volume / 1e12,
                            destination_rse["rse"],
                            vo_str,
                        )
                        destination_rse["receive_volume"] += replicating_volume
                    if destination_rse["receive_volume"] >= max_rse_rebalance_volume:
                        continue
                    available_target_rebalance_volume = (
                        max_rse_rebalance_volume - destination_rse["receive_volume"]
                    )
                    if (
                        available_target_rebalance_volume
                        >= available_source_rebalance_volume
                    ):
                        available_target_rebalance_volume = (
                            available_source_rebalance_volume
                        )

                    logger(
                        logging.INFO,
                        "Rebalance %d TB from %s(%f) to %s(%f)%s",
                        available_target_rebalance_volume / 1e12,
                        source_rse["rse"],
                        source_rse["ratio"],
                        destination_rse["rse"],
                        destination_rse["ratio"],
                        vo_str,
                    )
                    expr = destination_rse["rse"]
                    rebalance_rse(
                        rse_id=source_rse["id"],
                        max_bytes=available_target_rebalance_volume,
                        dry_run=dry_run,
                        comment="Background rebalancing",
                        force_expression=expr,
                        logger=logger,
                    )

                    destination_rse[
                        "receive_volume"
                    ] += available_target_rebalance_volume
                    total_rebalance_volume += available_target_rebalance_volume
                    available_source_rebalance_volume -= (
                        available_target_rebalance_volume
                    )

    must_sleep = True
    return must_sleep


def stop(signum: "Optional[int]" = None, frame: "Optional[FrameType]" = None) -> None:
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(
    once: bool,
    rse_expression: str,
    move_subscriptions: bool = False,
    use_dump: bool = False,
    sleep_time: int = 300,
    threads: int = 1,
    dry_run: bool = False,
) -> None:
    """
    Starts up the BB8 rebalancing threads.
    """

    setup_logging(process_name=DAEMON_NAME)
    hostname = socket.gethostname()
    sanity_check(executable=DAEMON_NAME, hostname=hostname)
    logging.info("BB8 starting %s threads", str(threads))
    threads = [
        threading.Thread(
            target=rule_rebalancer,
            kwargs={
                "once": once,
                "rse_expression": rse_expression,
                "sleep_time": sleep_time,
                "dry_run": dry_run,
            },
        )
        for _ in range(0, threads)
    ]
    [thread.start() for thread in threads]
    # Interruptible joins require a timeout.
    while threads[0].is_alive():
        [thread.join(timeout=3.14) for thread in threads]
