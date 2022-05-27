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
from rucio.core.rse import get_rse_usage
from rucio.daemons.abacus.rse import rse_update
from rucio.daemons.judge import cleaner
from rucio.daemons.reaper import reaper
from rucio.db.sqla import models
from rucio.db.sqla.session import get_session


@pytest.mark.noparallel(reason='uses daemon, failing in parallel to other tests')
class TestAbacusRSE():

    def test_abacus_rse(self, vo, mock_scope, rse_factory, did_factory, rucio_client):
        """ ABACUS (RSE): Test update of RSE usage. """
        # Get RSE usage of all sources
        session = get_session()
        session.query(models.UpdatedRSECounter).delete()  # pylint: disable=no-member
        session.query(models.RSEUsage).delete()  # pylint: disable=no-member
        session.commit()  # pylint: disable=no-member

        # Upload files -> RSE usage should increase
        file_sizes = 2
        nfiles = 2
        rse, rse_id = rse_factory.make_posix_rse()
        dids = did_factory.upload_test_dataset(rse_name=rse, scope=mock_scope.external, size=file_sizes, nb_files=nfiles)
        files = [{'scope': did['did_scope'], 'name': did['did_name']} for did in dids]
        dataset = dids[0]['dataset_name']
        rse_update(once=True)
        rse_usage = get_rse_usage(rse_id=rse_id)[0]
        assert rse_usage['used'] == len(files) * file_sizes
        rse_usage_from_rucio = get_rse_usage(rse_id=rse_id, source='rucio')[0]
        assert rse_usage_from_rucio['used'] == len(files) * file_sizes
        rse_usage_from_unavailable = get_rse_usage(rse_id=rse_id, source='unavailable')
        assert len(rse_usage_from_unavailable) == 0

        # Delete files -> rse usage should decrease
        from rucio.daemons.reaper.reaper import REGION
        REGION.invalidate()
        activity = get_schema_value('ACTIVITY')['enum'][0]
        rucio_client.add_replication_rule([{'scope': mock_scope.external, 'name': dataset}], 1, rse, lifetime=-1, activity=activity)
        cleaner.run(once=True)
        if vo:
            reaper.run(once=True, include_rses='vo=%s&(%s)' % (str(vo), rse), greedy=True)
        else:
            reaper.run(once=True, include_rses=rse, greedy=True)
        rse_update(once=True)
        rse_usage = get_rse_usage(rse_id=rse_id)[0]
        assert rse_usage['used'] == 0
        rse_usage_from_rucio = get_rse_usage(rse_id=rse_id, source='rucio')[0]
        assert rse_usage_from_rucio['used'] == 0
        rse_usage_from_unavailable = get_rse_usage(rse_id=rse_id, source='unavailable')
        assert len(rse_usage_from_unavailable) == 0
