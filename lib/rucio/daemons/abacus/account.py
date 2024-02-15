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
Abacus-Account is a daemon to update Account counters.
"""

import logging
import time
from typing import Any

from rucio.core.account_counter import get_updated_account_counters, update_account_counter
from rucio.daemons.common import HeartbeatHandler
from rucio.daemons.abacus.common import AbacusDaemon


class AbacusAccount(AbacusDaemon):
    def __init__(self, **_kwargs) -> None:
        super().__init__(daemon_name="abacus-account", **_kwargs)

    def _run_once(self, heartbeat_handler: "HeartbeatHandler", **_kwargs) -> tuple[bool, Any]:
        worker_number, total_workers, logger = heartbeat_handler.live()
        must_sleep = False

        start = time.time()  # NOQA
        account_rse_ids = get_updated_account_counters(total_workers=total_workers,
                                                       worker_number=worker_number)
        logger(logging.DEBUG, 'Index query time %f size=%d' % (time.time() - start, len(account_rse_ids)))

        # If the list is empty, sent the worker to sleep
        if not account_rse_ids:
            logger(logging.INFO, 'did not get any work')
            return must_sleep, None

        for account_rse_id in account_rse_ids:
            worker_number, total_workers, logger = heartbeat_handler.live()
            if self.graceful_stop.is_set():
                break
            start_time = time.time()
            update_account_counter(account=account_rse_id[0], rse_id=account_rse_id[1])
            logger(logging.DEBUG, 'update of account-rse counter "%s-%s" took %f' % (account_rse_id[0], account_rse_id[1], time.time() - start_time))
        return must_sleep, None
