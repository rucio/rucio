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

import logging
import threading
import time
from typing import TYPE_CHECKING

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.logging import setup_logging
from rucio.core.load_injection import (
    add_unique_rse_pair_datasets,
    delete_unique_rse_pair_datasets,
    get_unique_rse_pair_datasets,
    scan_unique_rse_pair_datasets,
)
from rucio.core.rse import list_rses
from rucio.daemons.common import HeartbeatHandler, run_daemon

if TYPE_CHECKING:
    from types import FrameType
    from typing import Optional

graceful_stop = threading.Event()
DAEMON_NAME = "loadinjector-scanner"


def update_unique_rse_pair_datasets(src_rse_id: str, dest_rse_id: str) -> None:
    """
    Update the cached unique datasets for a given RSE pair in unique_dataset table.

    :param src_rse_id: The src RSE id.
    :param des_rse_id: The des RSE id.
    """
    # Query from UniqueRSEPairDatasets table
    unique_datasets_db = get_unique_rse_pair_datasets(src_rse_id, dest_rse_id)
    # Scan from DatasetLock table
    unique_datasets_scanned = scan_unique_rse_pair_datasets(src_rse_id, dest_rse_id)

    # Compare scanned unique datasets with datasets in UniqueRSEPairDatasets table
    datasets_db_set = {tuple(sorted(dataset.items())) for dataset in unique_datasets_db}
    datasets_scanned_set = {
        tuple(sorted(dataset.items())) for dataset in unique_datasets_scanned
    }
    datasets_to_add = [
        dict(dataset) for dataset in datasets_scanned_set - datasets_db_set
    ]
    datasets_to_remove = [
        dict(dataset) for dataset in datasets_db_set - datasets_scanned_set
    ]
    # datasets_to_add = list()
    # datasets_to_remove = list()
    # for dataset in unique_datasets_scanned:
    #     if dataset not in unique_datasets_db:
    #         datasets_to_add.append(dataset)
    # for dataset in unique_datasets_db:
    #     if dataset not in unique_datasets_scanned:
    #         datasets_to_remove.append(dataset)

    # Remove datasets from UniqueRSEPairDatasets table
    if datasets_to_remove:
        delete_unique_rse_pair_datasets(datasets_to_remove)
    if datasets_to_add:
        add_unique_rse_pair_datasets(datasets_to_add)


def update_unique_rse_pair_datasets_bulk() -> None:
    """
    Update the cached unique datasets from all RSEs to all other RSEs in unique_dataset table.
    """
    rse_ids = [rse["id"] for rse in list_rses()]
    for src_rse_id in rse_ids:
        for des_rse_id in rse_ids:
            update_unique_rse_pair_datasets(src_rse_id, des_rse_id)


def loadinjector_scanner(once: bool = False, sleep_time: int = 43200) -> None:
    """
    Main loop for scanning unique datasets.
    """
    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable=DAEMON_NAME,
        partition_wait_time=1,
        sleep_time=sleep_time,
        run_once_fnc=run_once,
    )


def run_once(heartbeat_handler: HeartbeatHandler, **_kwargs) -> None:
    """
    Run loadinjector scanner once.
    """
    worker_number, total_workers, logger = heartbeat_handler.live()

    if graceful_stop.is_set():
        return
    start = time.time()

    update_unique_rse_pair_datasets_bulk()
    logger(
        logging.DEBUG,
        "update unique rse pair datasets for all rses took %f" % (time.time() - start),
    )


def stop(signum: "Optional[int]" = None, frame: "Optional[FrameType]" = None) -> None:
    """
    Graceful exit.
    """
    graceful_stop.set()


def run(once: bool = False, sleep_time: int = 43200) -> None:
    """
    Start up the loadinjector scanner threads.
    """
    setup_logging(process_name=DAEMON_NAME)

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException(
            "Database was not upgraded, daemon won't start."
        )

    if once:
        logging.info("main: executing one iteration only")
        loadinjector_scanner(once)
    else:
        logging.info("main: executing in a loop")
        loadinjector_scanner(once=once, sleep_time=sleep_time)
