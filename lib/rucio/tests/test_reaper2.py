# Copyright 2020 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Thomas Beermann <thomas.beermann@cern.ch>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Mario Lassnig <mario.lassnig@cern.ch>, 2020

from datetime import datetime, timedelta
from nose.tools import assert_equal

from rucio.client.rseclient import RSEClient
from rucio.common.config import config_get, config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core import replica as replica_core
from rucio.core import rse as rse_core
from rucio.daemons.reaper.reaper2 import reaper
from rucio.tests.common import rse_name_generator


def test_reaper():
    """ REAPER2 (DAEMON): Test the reaper2 daemon."""
    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
    else:
        vo = {}

    rse_name = rse_name_generator()
    rse_id = rse_core.add_rse(rse_name, **vo)

    mock_protocol = {'scheme': 'MOCK',
                     'hostname': 'localhost',
                     'port': 123,
                     'prefix': '/test/reaper',
                     'impl': 'rucio.rse.protocols.mock.Default',
                     'domains': {
                         'lan': {'read': 1,
                                 'write': 1,
                                 'delete': 1},
                         'wan': {'read': 1,
                                 'write': 1,
                                 'delete': 1}}}
    rse_core.add_protocol(rse_id=rse_id, parameter=mock_protocol)

    nb_files = 30
    file_size = 2147483648  # 2G

    file_names = []
    for i in range(nb_files):
        file_name = 'lfn' + generate_uuid()
        file_names.append(file_name)
        replica_core.add_replica(rse_id=rse_id, scope=InternalScope('data13_hip', **vo),
                                 name=file_name, bytes=file_size,
                                 tombstone=datetime.utcnow() - timedelta(days=1),
                                 account=InternalAccount('root', **vo), adler32=None, md5=None)

    rse_core.set_rse_usage(rse_id=rse_id, source='storage', used=nb_files * file_size, free=800)
    rse_core.set_rse_limits(rse_id=rse_id, name='MinFreeSpace', value=10737418240)
    rse_core.set_rse_limits(rse_id=rse_id, name='MaxBeingDeletedFiles', value=10)

    if vo:
        reaper(once=True, rses=[], include_rses='vo=%s&(%s)' % (vo['vo'], rse_name), exclude_rses=[])
        reaper(once=True, rses=[], include_rses='vo=%s&(%s)' % (vo['vo'], rse_name), exclude_rses=[])
    else:
        reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=[])
        reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=[])

    assert_equal(len(list(replica_core.list_replicas(dids=[{'scope': InternalScope('data13_hip', **vo), 'name': n} for n in file_names], rse_expression=rse_name))), nb_files - 5)
