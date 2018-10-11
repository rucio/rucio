# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018

import datetime

from nose.tools import assert_equal

from rucio.core import account_counter, rse_counter
from rucio.core.rse import get_rse
from rucio.daemons.abacus.rse import rse_update
from rucio.daemons.abacus.account import account_update
from rucio.db.sqla import models, constants, session


class TestCoreRSECounter():

    def test_inc_dec_get_counter(self):
        """ RSE COUNTER (CORE): Increase, decrease and get counter """
        rse_id = get_rse('MOCK').id
        rse_update(once=True)
        rse_counter.del_counter(rse_id=rse_id)
        rse_counter.add_counter(rse_id=rse_id)
        cnt = rse_counter.get_counter(rse_id=rse_id)
        del cnt['updated_at']
        assert_equal(cnt, {'files': 0, 'bytes': 0})

        count, sum = 0, 0
        for i in range(10):
            rse_counter.increase(rse_id=rse_id, files=1, bytes=2.147e+9)
            rse_update(once=True)
            count += 1
            sum += 2.147e+9
            cnt = rse_counter.get_counter(rse_id=rse_id)
            del cnt['updated_at']
            assert_equal(cnt, {'files': count, 'bytes': sum})

        for i in range(4):
            rse_counter.decrease(rse_id=rse_id, files=1, bytes=2.147e+9)
            rse_update(once=True)
            count -= 1
            sum -= 2.147e+9
            cnt = rse_counter.get_counter(rse_id=rse_id)
            del cnt['updated_at']
            assert_equal(cnt, {'files': count, 'bytes': sum})

        for i in range(5):
            rse_counter.increase(rse_id=rse_id, files=1, bytes=2.147e+9)
            rse_update(once=True)
            count += 1
            sum += 2.147e+9
            cnt = rse_counter.get_counter(rse_id=rse_id)
            del cnt['updated_at']
            assert_equal(cnt, {'files': count, 'bytes': sum})

        for i in range(8):
            rse_counter.decrease(rse_id=rse_id, files=1, bytes=2.147e+9)
            rse_update(once=True)
            count -= 1
            sum -= 2.147e+9
            cnt = rse_counter.get_counter(rse_id=rse_id)
            del cnt['updated_at']
            assert_equal(cnt, {'files': count, 'bytes': sum})

    def test_get_rse_usage_from_unavailable_replicas(self):
        """ RSE COUNTER (CORE): Get rse usage from unavailable replicas """
        rse_id = get_rse('MOCK').id
        scope = 'mock'
        account = 'root'
        db_session = session.get_session()
        db_session.query(models.RSEFileAssociation).delete()

        models.DataIdentifier(name='file_1', scope=scope, account=account, did_type=constants.DIDType.FILE).save(session=db_session)
        models.RSEFileAssociation(name='file_1', rse_id=rse_id, bytes=2, state=constants.ReplicaState.COPYING, scope=scope).save(session=db_session)
        unavailable_replicas = rse_counter.get_rse_usage_from_unavailable_replicas(0, 0, session=db_session)
        assert_equal(unavailable_replicas, [{'rse_id': rse_id, 'bytes': 2, 'files': 1}])

        models.DataIdentifier(name='file_2', scope=scope, account=account, did_type=constants.DIDType.FILE).save(session=db_session)
        models.RSEFileAssociation(name='file_2', rse_id=rse_id, bytes=2, tombstone=datetime.datetime.utcnow(), state=constants.ReplicaState.COPYING, scope=scope).save(session=db_session)
        unavailable_replicas = rse_counter.get_rse_usage_from_unavailable_replicas(0, 0, session=db_session)
        assert_equal(unavailable_replicas, [{'rse_id': rse_id, 'bytes': 2, 'files': 1}])

        models.DataIdentifier(name='file_3', scope=scope, account=account, did_type=constants.DIDType.FILE).save(session=db_session)
        models.RSEFileAssociation(name='file_3', rse_id=rse_id, bytes=2, state=constants.ReplicaState.UNAVAILABLE, scope=scope).save(session=db_session)
        unavailable_replicas = rse_counter.get_rse_usage_from_unavailable_replicas(0, 0, session=db_session)
        assert_equal(unavailable_replicas, [{'rse_id': rse_id, 'bytes': 4, 'files': 2}])

        models.DataIdentifier(name='file_4', scope=scope, account=account, did_type=constants.DIDType.FILE).save(session=db_session)
        models.RSEFileAssociation(name='file_4', rse_id=rse_id, bytes=2, state=constants.ReplicaState.AVAILABLE, scope=scope).save(session=db_session)
        unavailable_replicas = rse_counter.get_rse_usage_from_unavailable_replicas(0, 0, session=db_session)
        assert_equal(unavailable_replicas, [{'rse_id': rse_id, 'bytes': 4, 'files': 2}])

        db_session.commit()

    def test_update_unavailable_rse_usage(self):
        """ RSE COUNTER (CORE): Update rse usage from unavailable replicas """
        rse_id = get_rse('MOCK').id
        db_session = session.get_session()
        db_session.query(models.RSEUsage).delete()
        rse_counter.update_rse_usage_from_unavailable_replicas({'rse_id': rse_id, 'bytes': 2, 'files': 2}, session=db_session)
        usage = db_session.query(models.RSEUsage).filter_by(rse_id=rse_id, source='unavailable').one()
        assert_equal(usage['used'], 2)
        assert_equal(usage['files'], 2)

        db_session.commit()


class TestCoreAccountCounter():

    def test_inc_dec_get_counter(self):
        """ACCOUNT COUNTER (CORE): Increase, decrease and get counter """
        account_update(once=True)
        rse_id = get_rse('MOCK').id
        account = 'jdoe'
        account_counter.del_counter(rse_id=rse_id, account=account)
        account_counter.add_counter(rse_id=rse_id, account=account)
        cnt = account_counter.get_counter(rse_id=rse_id, account=account)
        del cnt['updated_at']
        assert_equal(cnt, {'files': 0, 'bytes': 0})

        count, sum = 0, 0
        for i in range(10):
            account_counter.increase(rse_id=rse_id, account=account, files=1, bytes=2.147e+9)
            account_update(once=True)
            count += 1
            sum += 2.147e+9
            cnt = account_counter.get_counter(rse_id=rse_id, account=account)
            del cnt['updated_at']
            assert_equal(cnt, {'files': count, 'bytes': sum})

        for i in range(4):
            account_counter.decrease(rse_id=rse_id, account=account, files=1, bytes=2.147e+9)
            account_update(once=True)
            count -= 1
            sum -= 2.147e+9
            cnt = account_counter.get_counter(rse_id=rse_id, account=account)
            del cnt['updated_at']
            assert_equal(cnt, {'files': count, 'bytes': sum})

        for i in range(5):
            account_counter.increase(rse_id=rse_id, account=account, files=1, bytes=2.147e+9)
            account_update(once=True)
            count += 1
            sum += 2.147e+9
            cnt = account_counter.get_counter(rse_id=rse_id, account=account)
            del cnt['updated_at']
            assert_equal(cnt, {'files': count, 'bytes': sum})

        for i in range(8):
            account_counter.decrease(rse_id=rse_id, account=account, files=1, bytes=2.147e+9)
            account_update(once=True)
            count -= 1
            sum -= 2.147e+9
            cnt = account_counter.get_counter(rse_id=rse_id, account=account)
            del cnt['updated_at']
            assert_equal(cnt, {'files': count, 'bytes': sum})
