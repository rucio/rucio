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
# - Radu Carpa <radu.carpa@cern.ch>, 2021

from datetime import datetime, timedelta

import pytest

from rucio.common.config import config_get_bool
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.api import rse as rse_api
from rucio.api import replica as replica_api
from rucio.core import replica as replica_core
from rucio.core import rse as rse_core
from rucio.core import scope as scope_core
from rucio.core import vo as vo_core
from rucio.daemons.reaper.reaper2 import reaper, REGION, run as run_reaper
from rucio.tests.common import rse_name_generator

__mock_protocol = {'scheme': 'MOCK',
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


def __add_test_rse_and_replicas(vo, scope, nb_files, file_size):
    rse_name = rse_name_generator()
    rse_id = rse_core.add_rse(rse_name, vo=vo)

    rse_core.add_protocol(rse_id=rse_id, parameter=__mock_protocol)

    dids = []
    for i in range(nb_files):
        file_name = 'lfn' + generate_uuid()
        dids.append({'scope': scope, 'name': file_name})
        replica_core.add_replica(rse_id=rse_id, scope=scope,
                                 name=file_name, bytes=file_size,
                                 tombstone=datetime.utcnow() - timedelta(days=1),
                                 account=InternalAccount('root', vo=vo), adler32=None, md5=None)
    return rse_name, rse_id, dids


def __setup_new_vo():
    multi_vo = config_get_bool('common', 'multi_vo', raise_exception=False, default=False)
    if not multi_vo:
        pytest.skip('multi_vo mode is not enabled. Running multi_vo tests in single_vo mode would result in failures.')

    new_vo = 'new'
    if not vo_core.vo_exists(vo=new_vo):
        vo_core.add_vo(vo=new_vo, description='Test', email='rucio@email.com')
    return new_vo


@pytest.mark.noparallel(reason='fails when run in parallel. It resets some memcached values.')
def test_reaper(vo):
    """ REAPER2 (DAEMON): Test the reaper2 daemon."""
    scope = InternalScope('data13_hip', vo=vo)

    nb_files = 250
    file_size = 200  # 2G
    rse_name, rse_id, dids = __add_test_rse_and_replicas(vo=vo, scope=scope, nb_files=nb_files, file_size=file_size)

    rse_core.set_rse_limits(rse_id=rse_id, name='MinFreeSpace', value=50 * file_size)
    assert len(list(replica_core.list_replicas(dids=dids, rse_expression=rse_name))) == nb_files

    # Check first if the reaper does not delete anything if no space is needed
    REGION.invalidate()
    rse_core.set_rse_usage(rse_id=rse_id, source='storage', used=nb_files * file_size, free=323000000000)
    reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=None)
    assert len(list(replica_core.list_replicas(dids=dids, rse_expression=rse_name))) == nb_files

    # Now put it over threshold and delete
    REGION.invalidate()
    rse_core.set_rse_usage(rse_id=rse_id, source='storage', used=nb_files * file_size, free=1)
    reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=None)
    reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=None)
    assert len(list(replica_core.list_replicas(dids, rse_expression=rse_name))) == 200


@pytest.mark.noparallel(reason='fails when run in parallel. It resets some memcached values.')
def test_reaper_multi_vo_via_run(vo):
    """ MULTI VO (DAEMON): Test that reaper runs on the specified VO(s) """
    new_vo = __setup_new_vo()
    rse_name = rse_name_generator()
    rse_id_tst = rse_core.add_rse(rse_name, 'root', vo=vo)
    rse_id_new = rse_core.add_rse(rse_name, 'root', vo=new_vo)

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
    rse_core.add_protocol(rse=rse_name, data=mock_protocol, issuer='root', vo=vo)
    rse_core.add_protocol(rse=rse_name, data=mock_protocol, issuer='root', vo=new_vo)

    scope_uuid = str(generate_uuid()).lower()[:16]
    scope_name = 'shr_%s' % scope_uuid
    scope_tst = InternalScope(scope_name, vo=vo)
    scope_new = InternalScope(scope_name, vo=new_vo)
    scope_core.add_scope(scope_name, 'root', 'root', vo=vo)
    scope_core.add_scope(scope_name, 'root', 'root', vo=new_vo)

    nb_files = 30
    file_size = 200  # 2G

    names = []
    for i in range(nb_files):
        name = 'lfn%s' % generate_uuid()
        names.append(name)
        replica_core.add_replica(rse_id=rse_id_tst, scope=scope_tst, name=name, bytes=file_size, account=InternalAccount('root', vo=vo),
                                 adler32=None, md5=None, tombstone=datetime.utcnow() - timedelta(days=1))
        replica_core.add_replica(rse_id=rse_id_new, scope=scope_new, name=name, bytes=file_size, account=InternalAccount('root', vo=new_vo),
                                 adler32=None, md5=None, tombstone=datetime.utcnow() - timedelta(days=1))

    rse_api.set_rse_usage(rse=rse_name, source='storage', used=nb_files * file_size, free=1, issuer='root', vo=vo)
    rse_api.set_rse_limits(rse=rse_name, name='MinFreeSpace', value=5 * 200, issuer='root', vo=vo)
    rse_api.set_rse_limits(rse=rse_name, name='MaxBeingDeletedFiles', value=10, issuer='root', vo=vo)

    rse_api.set_rse_usage(rse=rse_name, source='storage', used=nb_files * file_size, free=1, issuer='root', vo=new_vo)
    rse_api.set_rse_limits(rse=rse_name, name='MinFreeSpace', value=5 * 200, issuer='root', vo=new_vo)
    rse_api.set_rse_limits(rse=rse_name, name='MaxBeingDeletedFiles', value=10, issuer='root', vo=new_vo)

    # Check we start of with the expected number of replicas
    assert len(list(replica_api.list_replicas([{'scope': scope_name, 'name': n} for n in names], rse_expression=rse_name, vo=vo))) == nb_files
    assert len(list(replica_api.list_replicas([{'scope': scope_name, 'name': n} for n in names], rse_expression=rse_name, vo=new_vo))) == nb_files

    # Check we reap all VOs by default
    from rucio.daemons.reaper.reaper2 import REGION
    REGION.invalidate()
    run_reaper(once=True, rses=[rse_name])
    assert len(list(replica_api.list_replicas([{'scope': scope_name, 'name': n} for n in names], rse_expression=rse_name, vo=vo))) == 25
    assert len(list(replica_api.list_replicas([{'scope': scope_name, 'name': n} for n in names], rse_expression=rse_name, vo=new_vo))) == 25


@pytest.mark.noparallel(reason='fails when run in parallel. It resets some memcached values.')
def test_reaper_affect_other_vo_via_run(vo):
    """ MULTI VO (DAEMON): Test that reaper runs on the specified VO(s) and does not reap others"""
    new_vo = __setup_new_vo()
    rse_name = rse_name_generator()
    rse_id_tst = rse_core.add_rse(rse_name, 'root', vo=vo)
    rse_id_new = rse_core.add_rse(rse_name, 'root', vo=new_vo)

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
    rse_core.add_protocol(rse=rse_name, data=mock_protocol, issuer='root', vo=vo)
    rse_core.add_protocol(rse=rse_name, data=mock_protocol, issuer='root', vo=new_vo)

    scope_uuid = str(generate_uuid()).lower()[:16]
    scope_name = 'shr_%s' % scope_uuid
    scope_tst = InternalScope(scope_name, vo=vo)
    scope_new = InternalScope(scope_name, vo=new_vo)
    scope_core.add_scope(scope_name, 'root', 'root', vo=vo)
    scope_core.add_scope(scope_name, 'root', 'root', vo=new_vo)

    nb_files = 30
    file_size = 200  # 2G

    names = []
    for i in range(nb_files):
        name = 'lfn%s' % generate_uuid()
        names.append(name)
        replica_core.add_replica(rse_id=rse_id_tst, scope=scope_tst, name=name, bytes=file_size, account=InternalAccount('root', vo=vo),
                                 adler32=None, md5=None, tombstone=datetime.utcnow() - timedelta(days=1))
        replica_core.add_replica(rse_id=rse_id_new, scope=scope_new, name=name, bytes=file_size, account=InternalAccount('root', vo=new_vo),
                                 adler32=None, md5=None, tombstone=datetime.utcnow() - timedelta(days=1))

    rse_api.set_rse_usage(rse=rse_name, source='storage', used=nb_files * file_size, free=1, issuer='root', vo=vo)
    rse_api.set_rse_limits(rse=rse_name, name='MinFreeSpace', value=5 * 200, issuer='root', vo=vo)
    rse_api.set_rse_limits(rse=rse_name, name='MaxBeingDeletedFiles', value=10, issuer='root', vo=vo)

    rse_api.set_rse_usage(rse=rse_name, source='storage', used=nb_files * file_size, free=1, issuer='root', vo=new_vo)
    rse_api.set_rse_limits(rse=rse_name, name='MinFreeSpace', value=5 * 200, issuer='root', vo=new_vo)
    rse_api.set_rse_limits(rse=rse_name, name='MaxBeingDeletedFiles', value=10, issuer='root', vo=new_vo)

    # Check we start of with the expected number of replicas
    assert len(list(replica_api.list_replicas([{'scope': scope_name, 'name': n} for n in names], rse_expression=rse_name, vo=vo))) == nb_files
    assert len(list(replica_api.list_replicas([{'scope': scope_name, 'name': n} for n in names], rse_expression=rse_name, vo=new_vo))) == nb_files

    # Check we don't affect a second VO that isn't specified
    from rucio.daemons.reaper.reaper2 import REGION
    REGION.invalidate()
    run_reaper(once=True, rses=[rse_name], vos=['new'])
    assert len(list(replica_api.list_replicas([{'scope': scope_name, 'name': n} for n in names], rse_expression=rse_name, vo=vo))) == nb_files
    assert len(list(replica_api.list_replicas([{'scope': scope_name, 'name': n} for n in names], rse_expression=rse_name, vo=new_vo))) == 25


@pytest.mark.noparallel(reason='fails when run in parallel. It resets some memcached values.')
def test_reaper_multi_vo(vo):
    """ REAPER2 (DAEMON): Test the reaper2 daemon with multiple vo."""
    vo1 = vo
    vo2 = __setup_new_vo()
    if not vo_core.vo_exists(vo=vo2):
        vo_core.add_vo(vo=vo2, description='Test', email='rucio@email.com')
    scope1 = InternalScope('data13_hip', vo=vo1)
    scope2 = InternalScope('data13_hip', vo=vo2)
    if not scope_core.check_scope(scope2):
        scope_core.add_scope(scope2, InternalAccount('root', vo=vo2))

    nb_files = 250
    file_size = 200  # 2G
    rse1_name, rse1_id, dids1 = __add_test_rse_and_replicas(vo=vo1, scope=scope1, nb_files=nb_files, file_size=file_size)
    rse2_name, rse2_id, dids2 = __add_test_rse_and_replicas(vo=vo2, scope=scope2, nb_files=nb_files, file_size=file_size)

    rse_core.set_rse_limits(rse_id=rse1_id, name='MinFreeSpace', value=50 * file_size)
    rse_core.set_rse_limits(rse_id=rse2_id, name='MinFreeSpace', value=50 * file_size)

    # Check we reap all VOs by default
    REGION.invalidate()
    rse_core.set_rse_usage(rse_id=rse1_id, source='storage', used=nb_files * file_size, free=1)
    rse_core.set_rse_usage(rse_id=rse2_id, source='storage', used=nb_files * file_size, free=1)
    both_rses = '%s|%s' % (rse1_name, rse2_name)
    reaper(once=True, rses=[], include_rses=both_rses, exclude_rses=None)
    reaper(once=True, rses=[], include_rses=both_rses, exclude_rses=None)
    assert len(list(replica_core.list_replicas(dids=dids1, rse_expression=both_rses))) == 200
    assert len(list(replica_core.list_replicas(dids=dids2, rse_expression=both_rses))) == 200
