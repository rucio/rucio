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
from sqlalchemy import delete

from rucio.core.replica import add_replica, get_replica, set_tombstone
from rucio.core.rse import get_rse_usage
from rucio.daemons.abacus.rse_obsolete import run
from rucio.db.sqla import models
from rucio.db.sqla.constants import OBSOLETE
from rucio.db.sqla.session import get_session
from rucio.tests.common import did_name_generator


@pytest.mark.noparallel(reason='uses daemon, failing in parallel to other tests')
class TestAbacusRSEObsolete:

    def test_abacus_rse_obsolete(self, mock_scope, rse_factory, root_account):
        """ ABACUS (RSE): Test update of RSE usage for obsolete replicas. """
        # Get RSE usage of all sources
        session = get_session()
        for model in [models.UpdatedRSECounter, models.RSEUsage]:
            stmt = delete(model)
            session.execute(stmt)
        session.commit()

        # create an RSE and some replicas with a tombstone:
        _, rse_id = rse_factory.make_mock_rse()
        nbfiles = 3
        for _ in range(nbfiles):
            name = did_name_generator('file')
            add_replica(rse_id, mock_scope, name, 4, root_account)
            assert get_replica(rse_id, mock_scope, name)['tombstone'] is None
            set_tombstone(rse_id, mock_scope, name)
            assert get_replica(rse_id, mock_scope, name)['tombstone'] == OBSOLETE

        # now one more replica, on a different RSE, but not obsolete:
        _, rse_id2 = rse_factory.make_mock_rse()
        name2 = did_name_generator('file')
        add_replica(rse_id2, mock_scope, name2, 4, root_account)
        assert get_replica(rse_id2, mock_scope, name2)['tombstone'] is None

        run(once=True)
        res = get_rse_usage(rse_id, 'obsolete')[0]  # 3 files, 12 bytes
        assert res['used'] == 12
        assert res['files'] == 3
        res = get_rse_usage(rse_id2, 'obsolete')[0]  # 0 files, 0 bytes
        assert res['used'] == 0
        assert res['files'] == 0
