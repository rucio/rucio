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
from typing import TYPE_CHECKING, Any, Optional

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
    from collections.abc import Mapping, Sequence
    from types import FrameType

    from rucio.common.types import RSESettingsDict


METRICS = MetricManager(module=__name__)
GRACEFUL_STOP = threading.Event()
DAEMON_NAME = 'conveyor-stager'


def stager(
        once: bool = False,
        rses: Optional[list["RSESettingsDict"]] = None,
        bulk: int = 100,
        group_bulk: int = 1,
        group_policy: str = 'rule',
        source_strategy: Optional[str] = None,
        activities: Optional[list[str]] = None,
        sleep_time: int = 600,
        total_threads: int = 1
) -> None:

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
        executable=DAEMON_NAME,
        request_type=[RequestType.STAGEIN],
        default_lifetime=-1,
        metrics=METRICS,
        total_threads=total_threads,
    )


def stop(signum: Optional[int] = None, frame: Optional["FrameType"] = None) -> None:
    """
    Graceful exit.
    """

    GRACEFUL_STOP.set()


def run(
    once: bool = False,
    total_threads: int = 1,
    group_bulk: int = 1,
    group_policy: str = 'rule',
    rses: Optional["Sequence[Mapping[str, Any]]"] = None,
    include_rses: Optional[str] = None,
    exclude_rses: Optional[str] = None,
    vos: Optional[list[str]] = None,
    bulk: int = 100,
    source_strategy: Optional[str] = None,
    activities: Optional[list[str]] = None,
    sleep_time: int = 600
) -> None:
    """
    Starts up the conveyor threads.
    """
    activities = activities or []
    setup_logging(process_name=DAEMON_NAME)

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException('Database was not updated, daemon won\'t start')

    multi_vo = config_get_bool('common', 'multi_vo', raise_exception=False, default=False)
    working_rses = None
    if rses or include_rses or exclude_rses:
        working_rses = get_conveyor_rses(rses, include_rses, exclude_rses, vos)
        logging.info("RSE selection: RSEs: %s, Include: %s, Exclude: %s", rses,
                                                                            include_rses,
                                                                            exclude_rses)
    elif multi_vo:
        working_rses = get_conveyor_rses(rses, include_rses, exclude_rses, vos)
        logging.info("RSE selection: automatic for relevant VOs")
    else:
        logging.info("RSE selection: automatic")

    stager(
        once=once,
        rses=working_rses,
        bulk=bulk,
        group_bulk=group_bulk,
        group_policy=group_policy,
        source_strategy=source_strategy,
        activities=activities,
        sleep_time=sleep_time,
        total_threads=total_threads,
    )
