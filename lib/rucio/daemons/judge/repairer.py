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
Judge-Repairer is a daemon to repair stuck replication rules.
"""
import logging
import time
import traceback
from copy import deepcopy
from datetime import datetime, timedelta
from random import randint
from re import match
from typing import Any
from rucio.db.sqla.constants import ORACLE_CONNECTION_LOST_CONTACT_REGEX, ORACLE_RESOURCE_BUSY_REGEX

from sqlalchemy.exc import DatabaseError

from rucio.common.exception import DatabaseException
from rucio.core.monitor import MetricManager
from rucio.core.rule import repair_rule, get_stuck_rules
from rucio.daemons.common import Daemon, HeartbeatHandler

METRICS = MetricManager(module=__name__)


class JudgeRepairer(Daemon):
    def __init__(self, **_kwargs) -> None:
        super().__init__(daemon_name="judge-repairer", **_kwargs)
        self.delta = -1 if self.once else 1800
        self.paused_rules = {}  # {rule_id: datetime}

    def _run_once(self, heartbeat_handler: "HeartbeatHandler", **_kwargs) -> tuple[bool, Any]:
        worker_number, total_workers, logger = heartbeat_handler.live()
        must_sleep = False

        start = time.time()

        # Refresh paused rules
        iter_paused_rules = deepcopy(self.paused_rules)
        for key in iter_paused_rules:
            if datetime.utcnow() > self.paused_rules[key]:
                del self.paused_rules[key]

        # Select a bunch of rules for this worker to repair
        rules = get_stuck_rules(total_workers=total_workers,
                                worker_number=worker_number,
                                delta=self.delta,
                                limit=100,
                                blocked_rules=[key for key in self.paused_rules])

        logger(logging.DEBUG, 'index query time %f fetch size is %d' % (time.time() - start, len(rules)))

        if not rules:
            logger(logging.DEBUG, 'did not get any work (paused_rules=%s)' % (str(len(self.paused_rules))))
            return must_sleep, None

        for rule_id in rules:
            _, _, logger = heartbeat_handler.live()
            rule_id = rule_id[0]
            logger(logging.INFO, 'Repairing rule %s' % (rule_id))
            if self.graceful_stop.is_set():
                break
            try:
                start = time.time()
                repair_rule(rule_id=rule_id)
                logger(logging.DEBUG, 'repairing of %s took %f' % (rule_id, time.time() - start))
            except (DatabaseException, DatabaseError) as e:
                if match(ORACLE_RESOURCE_BUSY_REGEX, str(e.args[0])):
                    self.paused_rules[rule_id] = datetime.utcnow() + timedelta(seconds=randint(600, 2400))
                    logger(logging.WARNING, 'Locks detected for %s' % (rule_id))
                    METRICS.counter('exceptions.{exception}').labels(exception='LocksDetected').inc()
                elif match('.*QueuePool.*', str(e.args[0])):
                    logger(logging.WARNING, traceback.format_exc())
                    METRICS.counter('exceptions.{exception}').labels(exception=e.__class__.__name__).inc()
                elif match(ORACLE_CONNECTION_LOST_CONTACT_REGEX, str(e.args[0])):
                    logger(logging.WARNING, traceback.format_exc())
                    METRICS.counter('exceptions.{exception}').labels(exception=e.__class__.__name__).inc()
                else:
                    logger(logging.ERROR, traceback.format_exc())
                    METRICS.counter('exceptions.{exception}').labels(exception=e.__class__.__name__).inc()
        return must_sleep, None
