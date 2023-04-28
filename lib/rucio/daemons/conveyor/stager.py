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
Conveyor stager is a daemon to manage stagein file transfers.
"""

import logging
import threading
from typing import TYPE_CHECKING

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.config import config_get_bool
from rucio.common.logging import setup_logging
from rucio.core.monitor import MetricManager
from rucio.daemons.conveyor.common import get_conveyor_rses
from rucio.daemons.conveyor.submitter import submitter
from rucio.db.sqla.constants import RequestType
from rucio.transfertool.fts3 import FTS3Transfertool

if TYPE_CHECKING:
    from types import FrameType
    from typing import Optional

METRICS = MetricManager(module=__name__)
graceful_stop = threading.Event()


def stager(once=False, rses=None, bulk=100, group_bulk=1, group_policy='rule',
           source_strategy=None, activities=None, sleep_time=600):

    submitter(
        once=once,
        rses=rses,
        partition_wait_time=0,
        bulk=bulk,
        group_bulk=group_bulk,
        group_policy=group_policy,
        source_strategy=source_strategy,
        activities=activities,
        sleep_time=sleep_time,
        archive_timeout_override=None,
        filter_transfertool=None,
        transfertools=[FTS3Transfertool.external_name],
        ignore_availability=False,
        executable='conveyor-stager',
        request_type=[RequestType.STAGEIN],
        default_lifetime=-1,
        metrics=METRICS,
    )


def stop(signum: "Optional[int]" = None, frame: "Optional[FrameType]" = None) -> None:
    """
    Graceful exit.
    """

    graceful_stop.set()


def run(once=False, total_threads=1, group_bulk=1, group_policy='rule',
        rses=None, include_rses=None, exclude_rses=None, vos=None, bulk=100, source_strategy=None,
        activities=[], sleep_time=600):
    """
    Starts up the conveyer threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    multi_vo = config_get_bool('common', 'multi_vo', raise_exception=False, default=False)
    working_rses = None
    if rses or include_rses or exclude_rses:
        working_rses = get_conveyor_rses(rses, include_rses, exclude_rses, vos)
        logging.info("RSE selection: RSEs: %s, Include: %s, Exclude: %s" % (rses,
                                                                            include_rses,
                                                                            exclude_rses))
    elif multi_vo:
        working_rses = get_conveyor_rses(rses, include_rses, exclude_rses, vos)
        logging.info("RSE selection: automatic for relevant VOs")
    else:
        logging.info("RSE selection: automatic")

    if once:
        logging.info('executing one stager iteration only')
        stager(once,
               rses=working_rses,
               bulk=bulk,
               group_bulk=group_bulk,
               group_policy=group_policy,
               source_strategy=source_strategy,
               activities=activities)

    else:
        logging.info('starting stager threads')
        threads = [threading.Thread(target=stager, kwargs={'rses': working_rses,
                                                           'bulk': bulk,
                                                           'group_bulk': group_bulk,
                                                           'group_policy': group_policy,
                                                           'activities': activities,
                                                           'sleep_time': sleep_time,
                                                           'source_strategy': source_strategy}) for _ in range(0, total_threads)]

        [thread.start() for thread in threads]

        logging.info('waiting for interrupts')

        # Interruptible joins require a timeout.
        while threads:
            threads = [thread.join(timeout=3.14) for thread in threads if thread and thread.is_alive()]
