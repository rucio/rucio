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
import random
from time import sleep

import pytest

from rucio.core import account_counter, rse_counter
from rucio.core.account import get_usage
from rucio.daemons.abacus.account import account_update
from rucio.daemons.abacus.rse import rse_update
from rucio.db.sqla import models


@pytest.mark.noparallel(reason='runs abacus daemons')
class TestCoreRSECounter:

    def test_inc_dec_get_counter(self, rse_factory):
        """ RSE COUNTER (CORE): Increase, decrease and get counter """
        _, rse_id = rse_factory.make_mock_rse()
        rse_update(once=True)
        rse_counter.del_counter(rse_id=rse_id)
        rse_counter.add_counter(rse_id=rse_id)
        cnt = rse_counter.get_counter(rse_id=rse_id)
        del cnt['updated_at']
        assert cnt == {'files': 0, 'bytes': 0}

        count, sum_ = 0, 0
        for i in range(10):
            rse_counter.increase(rse_id=rse_id, files=1, bytes_=2.147e+9)
            rse_update(once=True)
            count += 1
            sum_ += 2.147e+9
            cnt = rse_counter.get_counter(rse_id=rse_id)
            del cnt['updated_at']
            assert cnt == {'files': count, 'bytes': sum_}

        for i in range(4):
            rse_counter.decrease(rse_id=rse_id, files=1, bytes_=2.147e+9)
            rse_update(once=True)
            count -= 1
            sum_ -= 2.147e+9
            cnt = rse_counter.get_counter(rse_id=rse_id)
            del cnt['updated_at']
            assert cnt == {'files': count, 'bytes': sum_}

        for i in range(5):
            rse_counter.increase(rse_id=rse_id, files=1, bytes_=2.147e+9)
            rse_update(once=True)
            count += 1
            sum_ += 2.147e+9
            cnt = rse_counter.get_counter(rse_id=rse_id)
            del cnt['updated_at']
            assert cnt == {'files': count, 'bytes': sum_}

        for i in range(8):
            rse_counter.decrease(rse_id=rse_id, files=1, bytes_=2.147e+9)
            rse_update(once=True)
            count -= 1
            sum_ -= 2.147e+9
            cnt = rse_counter.get_counter(rse_id=rse_id)
            del cnt['updated_at']
            assert cnt == {'files': count, 'bytes': sum_}

    def test_fill_counter_history(self, db_session):
        """RSE COUNTER (CORE): Fill the usage history with the current value."""
        db_session.query(models.RSEUsageHistory).delete()
        db_session.commit()
        rse_counter.fill_rse_counter_history_table()
        history_usage = [(usage['rse_id'], usage['files'], usage['source'], usage['used']) for usage in db_session.query(models.RSEUsageHistory)]
        current_usage = [(usage['rse_id'], usage['files'], usage['source'], usage['used']) for usage in db_session.query(models.RSEUsage)]
        for usage in history_usage:
            assert usage in current_usage


@pytest.mark.noparallel(reason='runs abacus daemons; deletes all account_usage_history rows')
class TestCoreAccountCounter:

    def test_inc_dec_get_counter(self, jdoe_account, rse_factory, db_session):
        """ACCOUNT COUNTER (CORE): Increase, decrease and get counter """
        db_session.commit()
        account_update(once=True)
        _, rse_id = rse_factory.make_mock_rse(session=db_session)
        db_session.commit()
        account = jdoe_account
        account_counter.del_counter(rse_id=rse_id, account=account)
        account_counter.add_counter(rse_id=rse_id, account=account)
        cnt = get_usage(rse_id=rse_id, account=account)
        del cnt['updated_at']
        assert cnt == {'files': 0, 'bytes': 0}

        count, sum_ = 0, 0
        for i in range(10):
            account_counter.increase(rse_id=rse_id, account=account, files=1, bytes_=2.147e+9)
            account_update(once=True)
            count += 1
            sum_ += 2.147e+9
            cnt = get_usage(rse_id=rse_id, account=account)
            del cnt['updated_at']
            assert cnt == {'files': count, 'bytes': sum_}

        for i in range(4):
            account_counter.decrease(rse_id=rse_id, account=account, files=1, bytes_=2.147e+9)
            account_update(once=True)
            count -= 1
            sum_ -= 2.147e+9
            cnt = get_usage(rse_id=rse_id, account=account)
            del cnt['updated_at']
            assert cnt == {'files': count, 'bytes': sum_}

        for i in range(5):
            account_counter.increase(rse_id=rse_id, account=account, files=1, bytes_=2.147e+9)
            account_update(once=True)
            count += 1
            sum_ += 2.147e+9
            cnt = get_usage(rse_id=rse_id, account=account)
            del cnt['updated_at']
            assert cnt == {'files': count, 'bytes': sum_}

        for i in range(8):
            account_counter.decrease(rse_id=rse_id, account=account, files=1, bytes_=2.147e+9)
            account_update(once=True)
            count -= 1
            sum_ -= 2.147e+9
            cnt = get_usage(rse_id=rse_id, account=account)
            del cnt['updated_at']
            assert cnt == {'files': count, 'bytes': sum_}

        # check that the counters are correctly copied into the history table
        db_session.query(models.AccountUsageHistory).delete()
        db_session.commit()
        account_counter.fill_account_counter_history_table()
        history_usage = {(usage['rse_id'], usage['files'], usage['account'], usage['bytes']) for usage in db_session.query(models.AccountUsageHistory)}
        current_usage = {(usage['rse_id'], usage['files'], usage['account'], usage['bytes']) for usage in db_session.query(models.AccountUsage)}
        assert history_usage
        assert history_usage == current_usage

        # The granularity of our updated_at field in the database is 1 second, so we may get a duplicate key error if we don't wait
        sleep(1)
        new_count = random.randint(count + 1, count * 1000)
        db_session.query(models.AccountUsage).filter_by(rse_id=rse_id, account=account).update({'files': new_count})
        db_session.commit()
        account_counter.fill_account_counter_history_table()
        history_usage = {(usage['rse_id'], usage['files'], usage['account'], usage['bytes']) for usage in db_session.query(models.AccountUsageHistory)}
        assert (rse_id, count, account, sum_) in history_usage
        assert (rse_id, new_count, account, sum_) in history_usage
