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

from datetime import datetime, timedelta

import pytest

from rucio.core.rule import _stuck_rule_suspend_reason, reset_stuck_state
from rucio.db.sqla import models


def _rule(stuck_days_ago=None, stuck_cnt=0):
    rule = models.ReplicationRule()
    rule.stuck_at = None if stuck_days_ago is None else datetime.utcnow() - timedelta(days=stuck_days_ago)
    rule.stuck_cnt = stuck_cnt
    return rule


class TestStuckRuleSuspension:
    """
    The STUCK -> SUSPENDED decision, rucio#8743
    """

    def test_two_week_timer_still_suspends(self, db_session):
        """ REPLICATION RULE (CORE): A rule STUCK for more than two weeks is suspended """
        assert _stuck_rule_suspend_reason(_rule(stuck_days_ago=1), session=db_session) is None
        assert _stuck_rule_suspend_reason(_rule(stuck_days_ago=15), session=db_session) is not None

    def test_attempt_counter_is_off_by_default(self, db_session):
        """ REPLICATION RULE (CORE): The attempt based policy does nothing unless it is configured """
        assert _stuck_rule_suspend_reason(_rule(stuck_days_ago=1, stuck_cnt=99), session=db_session) is None

    @pytest.mark.parametrize("core_config_mock", [{"table_content": [
        ('rules', 'stuck_cnt_to_suspend', 3),
    ]}], indirect=True)
    @pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
        'rucio.core.config.REGION',
    ]}], indirect=True)
    def test_attempt_counter_suspends_when_configured(self, db_session, core_config_mock, caches_mock):
        """ REPLICATION RULE (CORE): A rule that stays STUCK for too many repair attempts is suspended """
        assert _stuck_rule_suspend_reason(_rule(stuck_days_ago=1, stuck_cnt=2), session=db_session) is None
        assert _stuck_rule_suspend_reason(_rule(stuck_days_ago=1, stuck_cnt=3), session=db_session) is not None
        assert _stuck_rule_suspend_reason(_rule(stuck_days_ago=1, stuck_cnt=5), session=db_session) is not None

    def test_reset_forgets_the_stuck_history(self, db_session):
        """ REPLICATION RULE (CORE): Reaching OK clears both the timer and the attempt counter """
        rule = _rule(stuck_days_ago=15, stuck_cnt=7)
        reset_stuck_state(rule)
        assert rule.stuck_at is None
        assert rule.stuck_cnt == 0
        assert _stuck_rule_suspend_reason(rule, session=db_session) is None
