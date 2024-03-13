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
from rucio.daemons.common import Daemon, HeartbeatHandler
from rucio.common.utils import get_thread_with_periodic_running_function
from rucio.core.account_counter import fill_account_counter_history_table
import logging
import threading
from typing import Any
from abc import abstractmethod

ABACUS_HISTORY_TABLE_INTERVAL = 3600


class AbacusDaemon(Daemon):
    """
    Common daemon logic for multiple Abacus daemons.
    """
    def __init__(self, fill_history_table: bool = False, **_kwargs) -> None:
        f"""
        :param fill_history_table: Set to True to record account usage into history table every {ABACUS_HISTORY_TABLE_INTERVAL} seconds.
        """
        super().__init__(**_kwargs)
        self.fill_history_table = fill_history_table
        self.paused_dids = {}

    @abstractmethod
    def _run_once(
        self, heartbeat_handler: "HeartbeatHandler", **_kwargs
    ) -> tuple[bool, Any]:
        pass

    def run(self) -> None:
        self._pre_run_checks()

        if self.once:
            logging.info("%s: executing one iteration only", self.daemon_name)
            self._call_daemon()
        else:
            logging.info("%s: starting threads", self.daemon_name)
            thread_list = [threading.Thread(target=self._call_daemon) for _ in
                           range(0, self.total_workers)]
            if self.fill_history_table:
                thread_list.append(get_thread_with_periodic_running_function(ABACUS_HISTORY_TABLE_INTERVAL, fill_account_counter_history_table, self.graceful_stop))
            [t.start() for t in thread_list]
            logging.info("%s: waiting for interrupts", self.daemon_name)
            # Interruptible joins require a timeout.
            while thread_list:
                thread_list = [
                    thread.join(timeout=3.14)
                    for thread in thread_list
                    if thread and thread.is_alive()
                ]
