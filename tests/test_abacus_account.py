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


import pytest

from rucio.common.schema import get_schema_value
from rucio.core.account import get_usage_history
from rucio.core.account_counter import update_account_counter_history
from rucio.core.account_limit import get_local_account_usage, set_local_account_limit
from rucio.daemons.abacus.account import account_update
from rucio.daemons.judge import cleaner
from rucio.daemons.reaper import reaper
from rucio.db.sqla import models
from rucio.db.sqla.session import get_session


@pytest.mark.noparallel(reason='uses daemon, failing in parallel to other tests, updates account')
class TestAbacusAccount2():

    def test_abacus_account(self, vo, root_account, mock_scope, rse_factory, did_factory, rucio_client):
        """ ABACUS (ACCOUNT): Test update of account usage """
        session = get_session()
        session.query(models.UpdatedAccountCounter).delete()  # pylint: disable=no-member
        session.query(models.AccountUsage).delete()  # pylint: disable=no-member
        session.commit()  # pylint: disable=no-member

        # Upload files -> account usage should increase
        file_sizes = 2
        nfiles = 2
        rse, rse_id = rse_factory.make_posix_rse()
        dids = did_factory.upload_test_dataset(rse_name=rse, scope=mock_scope.external, size=file_sizes, nb_files=nfiles)
        dataset = dids[0]['dataset_name']
        activity = get_schema_value('ACTIVITY')['enum'][0]
        rucio_client.add_replication_rule([{'scope': mock_scope.external, 'name': dataset}], 1, rse, lifetime=-1, activity=activity)
        account_update(once=True)
        account_usage = get_local_account_usage(account=root_account, rse_id=rse_id)[0]
        assert account_usage['bytes'] == nfiles * file_sizes
        assert account_usage['files'] == nfiles

        # Update and check the account history with the core method
        update_account_counter_history(account=root_account, rse_id=rse_id)
        usage_history = get_usage_history(rse_id=rse_id, account=root_account)
        assert usage_history[-1]['bytes'] == nfiles * file_sizes
        assert usage_history[-1]['files'] == nfiles

        # Check the account history with the client
        usage_history = rucio_client.get_account_usage_history(rse=rse, account=root_account.external)
        assert usage_history[-1]['bytes'] == nfiles * file_sizes
        assert usage_history[-1]['files'] == nfiles

        # Delete rules -> account usage should decrease
        cleaner.run(once=True)
        account_update(once=True)
        # set account limit because return value of get_local_account_usage differs if a limit is set or not
        set_local_account_limit(account=root_account, rse_id=rse_id, bytes_=10)
        account_usages = get_local_account_usage(account=root_account, rse_id=rse_id)[0]
        assert account_usages['bytes'] == 0
        assert account_usages['files'] == 0

        if vo:
            reaper.run(once=True, include_rses='vo=%s&(%s)' % (str(vo), rse), greedy=True)
        else:
            reaper.run(once=True, include_rses=rse, greedy=True)
