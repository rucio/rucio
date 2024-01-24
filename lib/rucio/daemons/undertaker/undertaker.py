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

'''
Undertaker is a daemon to manage expired did.
'''

from collections.abc import Callable
import logging
import threading
import traceback
from copy import deepcopy
from datetime import datetime, timedelta
from random import randint
from re import match
from typing import TYPE_CHECKING, Any, Optional, Union
from dataclasses import dataclass

from sqlalchemy.exc import DatabaseError
from rucio.db.sqla.constants import MYSQL_LOCK_NOWAIT_REGEX, ORACLE_RESOURCE_BUSY_REGEX, PSQL_LOCK_NOT_AVAILABLE_REGEX

from rucio.common.exception import DatabaseException, UnsupportedOperation, RuleNotFound
from rucio.common.types import InternalAccount
from rucio.common.utils import chunks
from rucio.core.did import list_expired_dids, delete_dids
from rucio.core.monitor import MetricManager
from rucio.daemons.common import Daemon, HeartbeatHandler, DaemonExecutionParameters

if TYPE_CHECKING:
    from types import FrameType
    from typing import Optional

logging.getLogger("requests").setLevel(logging.CRITICAL)

METRICS = MetricManager(module=__name__)
graceful_stop = threading.Event()
DAEMON_NAME = 'undertaker'

@dataclass
class UndertakerExecutionParameters(DaemonExecutionParameters):
    chunk_size: int = 10

class Undertaker(Daemon):
    def __init__(self, execution_params: UndertakerExecutionParameters) -> None:
        super().__init__(execution_params, daemon_name="undertaker")
        self.paused_dids = {}

    def _run_once(self, heartbeat_handler: HeartbeatHandler, **_kwargs) -> None:
        worker_number, total_workers, logger = heartbeat_handler.live()

        try:
            # Refresh paused dids
            iter_paused_dids = deepcopy(self.paused_dids)
            for key in iter_paused_dids:
                if datetime.utcnow() > self.paused_dids[key]:
                    del self.paused_dids[key]

            dids = list_expired_dids(worker_number=worker_number, total_workers=total_workers, limit=10000)

            dids = [did for did in dids if (did['scope'], did['name']) not in self.paused_dids]

            if not dids:
                logger(logging.INFO, 'did not get any work')
                return

            for chunk in chunks(dids, self.execution_params.chunk_size):
                _, _, logger = heartbeat_handler.live()
                try:
                    logger(logging.INFO, 'Receive %s dids to delete', len(chunk))
                    delete_dids(dids=chunk, account=InternalAccount('root', vo='def'), expire_rules=True)
                    logger(logging.INFO, 'Delete %s dids', len(chunk))
                    METRICS.counter(name='undertaker.delete_dids').inc(len(chunk))
                except RuleNotFound as error:
                    logger(logging.ERROR, error)
                except (DatabaseException, DatabaseError, UnsupportedOperation) as e:
                    if match(ORACLE_RESOURCE_BUSY_REGEX, str(e.args[0])) or match(PSQL_LOCK_NOT_AVAILABLE_REGEX, str(e.args[0])) or match(MYSQL_LOCK_NOWAIT_REGEX, str(e.args[0])):
                        for did in chunk:
                            self.paused_dids[(did['scope'], did['name'])] = datetime.utcnow() + timedelta(seconds=randint(600, 2400))
                        METRICS.counter('delete_dids.exceptions.{exception}').labels(exception='LocksDetected').inc()
                        logger(logging.WARNING, 'Locks detected for chunk')
                    else:
                        logger(logging.ERROR, 'Got database error %s.', str(e))
        except:
            logging.critical(traceback.format_exc())