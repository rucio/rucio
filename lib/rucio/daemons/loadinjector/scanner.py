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
from rucio.common.exception import DuplicateContent
from rucio.common.logging import setup_logging
from rucio.core.load_injection import (
    add_unique_rse_pair_datasets,
    delete_unique_rse_pair_datasets,
    get_unique_rse_pair_datasets,
    refresh_unique_rse_pair_dataset_metadata,
    scan_unique_rse_pair_datasets,
)
from rucio.core.rse import list_rses
from rucio.daemons.common import HeartbeatHandler, run_daemon

if TYPE_CHECKING:
    from types import FrameType
    from typing import Optional

graceful_stop = threading.Event()
DAEMON_NAME = "loadinjector-scanner"


def _dataset_key(dataset: dict) -> tuple:
    """Extract the natural key (scope, name) from a dataset dict."""
    return (dataset["scope"], dataset["name"])


def update_unique_rse_pair_datasets(src_rse_id: str, dest_rse_id: str) -> None:
    """
    Update the cached unique datasets for a given RSE pair in unique_dataset table.

    :param src_rse_id: The src RSE id.
    :param dest_rse_id: The dest RSE id.
    """
    if src_rse_id == dest_rse_id:
        return  # Skip self-pairs

    unique_datasets_db = get_unique_rse_pair_datasets(src_rse_id, dest_rse_id)
    unique_datasets_scanned = scan_unique_rse_pair_datasets(src_rse_id, dest_rse_id)

    # Build lookup maps keyed by (scope, name).
    db_map = {_dataset_key(ds): ds for ds in unique_datasets_db}
    scanned_map = {_dataset_key(ds): ds for ds in unique_datasets_scanned}

    datasets_to_add = [
        ds for key, ds in scanned_map.items() if key not in db_map
    ]
    datasets_to_remove = [
        ds for key, ds in db_map.items() if key not in scanned_map
    ]

    # Detect metadata changes on datasets that remain unique.
    # The key (scope, name) still matches, but bytes or length may
    # have changed between scanner cycles.  Replace stale rows so
    # the submitter always works from fresh metadata.
    datasets_to_update = []
    for key, db_ds in db_map.items():
        scanned_ds = scanned_map.get(key)
        if scanned_ds is None:
            continue
        if (db_ds["bytes"] != scanned_ds["bytes"]
                or db_ds["length"] != scanned_ds["length"]):
            # Stamp the previously observed values so the core
            # refresh can use a compare-and-swap WHERE clause.
            scanned_ds["old_bytes"] = db_ds["bytes"]
            scanned_ds["old_length"] = db_ds["length"]
            datasets_to_update.append(scanned_ds)

    if datasets_to_remove:
        delete_unique_rse_pair_datasets(datasets_to_remove)
    if datasets_to_update:
        # Atomic UPDATE — a concurrent scanner worker with stale
        # metadata cannot overwrite fresh values because the UPDATE
        # is a single statement, not a delete+add gap.
        refresh_unique_rse_pair_dataset_metadata(datasets_to_update)
    if datasets_to_add:
        try:
            add_unique_rse_pair_datasets(datasets_to_add)
        except DuplicateContent:
            # Another scanner worker already inserted the same dataset.
            # The cache is already correct, so skip without failing.
            pass


def update_unique_rse_pair_datasets_bulk() -> None:
    """
    Update the cached unique datasets for all RSE pairs within the same VO.
    Groups RSEs by VO so intra-VO pairs are scanned while cross-VO pairs
    (which would always yield empty results) are skipped entirely.
    """
    from collections import defaultdict

    rses = list_rses()
    vo_rse_ids: dict[str, list[str]] = defaultdict(list)
    for rse in rses:
        vo_rse_ids[rse.get("vo", "def")].append(rse["id"])

    for vo, rse_ids in vo_rse_ids.items():
        for src_rse_id in rse_ids:
            for dest_rse_id in rse_ids:
                update_unique_rse_pair_datasets(src_rse_id, dest_rse_id)


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
