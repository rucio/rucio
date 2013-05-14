# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

from nose.tools import assert_equal

from rucio.core.counter import increase, decrease, add_counter, get_counter, del_counter
from rucio.core.rse import get_rse


class TestCoreCounter():

    def test_inc_dec_get_counter(self):
        """ COUNTER (CORE): Increase, decrease and get counter """
        rse_id = get_rse('MOCK').id
        del_counter(rse_id=rse_id)
        add_counter(rse_id=rse_id)
        cnt = get_counter(rse_id=rse_id)
        del cnt['updated_at']
        assert_equal(cnt, {'total': 0, 'bytes': 0})

        count, sum = 0, 0
        for i in xrange(10):
            increase(rse_id=rse_id, delta=1, bytes=2.147e+9)
            count += 1
            sum += 2.147e+9

        for i in xrange(4):
            decrease(rse_id=rse_id, delta=1, bytes=2.147e+9)
            count -= 1
            sum -= 2.147e+9

        cnt = get_counter(rse_id=rse_id)
        del cnt['updated_at']
        assert_equal(cnt, {'total': count, 'bytes': sum})
