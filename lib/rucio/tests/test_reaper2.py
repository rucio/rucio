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
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Mario Lassnig <mario.lassnig@cern.ch>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from datetime import datetime, timedelta

from rucio.common.config import config_get, config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core import replica as replica_core
from rucio.core import rse as rse_core
from rucio.core import scope as scope_core
from rucio.core import vo as vo_core
from rucio.daemons.reaper.reaper2 import reaper
from rucio.tests.common import rse_name_generator


def test_reaper():
    """ REAPER2 (DAEMON): Test the reaper2 daemon."""
    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        vo = {'vo': config_get('client', 'vo', raise_exception=False, default='tst')}
        new_vo = {'vo': 'new'}
        if not vo_core.vo_exists(**new_vo):
            vo_core.add_vo(description='Test', email='rucio@email.com', **new_vo)
        if not scope_core.check_scope(InternalScope('data13_hip', **new_vo)):
            scope_core.add_scope(InternalScope('data13_hip', **new_vo), InternalAccount('root', **new_vo))
        nb_rses = 2
    else:
        vo = {}
        new_vo = {}
        nb_rses = 1

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

    nb_files = 30
    file_size = 2147483648  # 2G

    rse_names = []
    all_file_names = []
    for j in range(nb_rses):
        rse_name = rse_name_generator()
        rse_names.append(rse_name)
        rse_id = rse_core.add_rse(rse_name, **vo)
        rse_core.add_protocol(rse_id=rse_id, parameter=mock_protocol)
        if new_vo:
            rse_id_new = rse_core.add_rse(rse_name, **new_vo)
            rse_core.add_protocol(rse_id=rse_id_new, parameter=mock_protocol)

        file_names = []
        for i in range(nb_files):
            file_name = 'lfn' + generate_uuid()
            file_names.append(file_name)
            replica_core.add_replica(rse_id=rse_id, scope=InternalScope('data13_hip', **vo),
                                     name=file_name, bytes=file_size,
                                     tombstone=datetime.utcnow() - timedelta(days=1),
                                     account=InternalAccount('root', **vo), adler32=None, md5=None)
            if new_vo:
                replica_core.add_replica(rse_id=rse_id_new, scope=InternalScope('data13_hip', **new_vo),
                                         name=file_name, bytes=file_size,
                                         tombstone=datetime.utcnow() - timedelta(days=1),
                                         account=InternalAccount('root', **new_vo), adler32=None, md5=None)

        all_file_names.append(file_names)
        rse_core.set_rse_usage(rse_id=rse_id, source='storage', used=nb_files * file_size, free=800)
        rse_core.set_rse_limits(rse_id=rse_id, name='MinFreeSpace', value=10737418240)
        rse_core.set_rse_limits(rse_id=rse_id, name='MaxBeingDeletedFiles', value=10)
        if new_vo:
            rse_core.set_rse_usage(rse_id=rse_id_new, source='storage', used=nb_files * file_size, free=800)
            rse_core.set_rse_limits(rse_id=rse_id_new, name='MinFreeSpace', value=10737418240)
            rse_core.set_rse_limits(rse_id=rse_id_new, name='MaxBeingDeletedFiles', value=10)

    if not vo:
        reaper(once=True, rses=[], include_rses=rse_names[0], exclude_rses=[])
        reaper(once=True, rses=[], include_rses=rse_names[0], exclude_rses=[])
        assert len(list(replica_core.list_replicas(dids=[{'scope': InternalScope('data13_hip', **vo), 'name': n} for n in all_file_names[0]],
                                                   rse_expression=rse_name))) == nb_files - 5
    else:
        # Check we reap all VOs by default
        reaper(once=True, rses=[], include_rses=rse_names[0], exclude_rses=[])
        reaper(once=True, rses=[], include_rses=rse_names[0], exclude_rses=[])
        assert len(list(replica_core.list_replicas(dids=[{'scope': InternalScope('data13_hip', **vo), 'name': n} for n in all_file_names[0]],
                                                   rse_expression=rse_names[0]))) == nb_files - 5
        assert len(list(replica_core.list_replicas(dids=[{'scope': InternalScope('data13_hip', **new_vo), 'name': n} for n in all_file_names[0]],
                                                   rse_expression=rse_names[0]))) == nb_files - 5
        # Check we don't affect a second VO that isn't specified
        reaper(once=True, rses=[], include_rses=rse_names[1], exclude_rses=[], vos=['new'])
        reaper(once=True, rses=[], include_rses=rse_names[1], exclude_rses=[], vos=['new'])
        assert len(list(replica_core.list_replicas(dids=[{'scope': InternalScope('data13_hip', **vo), 'name': n} for n in all_file_names[1]],
                                                   rse_expression=rse_names[1]))), nb_files
        assert len(list(replica_core.list_replicas(dids=[{'scope': InternalScope('data13_hip', **new_vo), 'name': n} for n in all_file_names[1]],
                                                   rse_expression=rse_names[1]))), nb_files - 5
