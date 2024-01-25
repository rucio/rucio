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

from datetime import datetime, timedelta

import pytest
from sqlalchemy import and_, or_

from rucio.api import replica as replica_api
from rucio.api import rse as rse_api
from rucio.db.sqla import models
from rucio.db.sqla.constants import OBSOLETE
from rucio.db.sqla.session import get_session
from rucio.common.exception import ReplicaNotFound, DataIdentifierNotFound
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import generate_uuid
from rucio.core import did as did_core
from rucio.core import message as message_core
from rucio.core import replica as replica_core
from rucio.core import rse as rse_core
from rucio.core import rule as rule_core
from rucio.daemons.reaper.reaper import reaper
from rucio.daemons.reaper.dark_reaper import reaper as dark_reaper
from rucio.daemons.reaper.reaper import run as run_reaper
from rucio.db.sqla.models import ConstituentAssociationHistory
from rucio.db.sqla.session import read_session
from rucio.tests.common import rse_name_generator, skip_rse_tests_with_accounts
from tests.ruciopytest import NoParallelGroups

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


def __add_test_rse_and_replicas(vo, scope, rse_name, names, file_size, epoch_tombstone=False):
    rse_id = rse_core.add_rse(rse_name, vo=vo)

    rse_core.add_protocol(rse_id=rse_id, parameter=__mock_protocol)
    tombstone = datetime.utcnow() - timedelta(days=1)
    if epoch_tombstone:
        tombstone = datetime(year=1970, month=1, day=1)

    dids = []
    for file_name in names:
        dids.append({'scope': scope, 'name': file_name})
        replica_core.add_replica(rse_id=rse_id, scope=scope,
                                 name=file_name, bytes_=file_size,
                                 tombstone=tombstone, meta={'datatype': 'SOME_DATATYPE'},
                                 account=InternalAccount('root', vo=vo), adler32=None, md5=None)
    return rse_name, rse_id, dids


@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.daemons.reaper.reaper.REGION'
]}], indirect=True)
def test_reaper(vo, caches_mock, message_mock):
    """ REAPER (DAEMON): Test the reaper daemon."""
    [cache_region] = caches_mock
    scope = InternalScope('data13_hip', vo=vo)

    nb_files = 250
    file_size = 200  # 2G
    rse_name, rse_id, dids = __add_test_rse_and_replicas(vo=vo, scope=scope, rse_name=rse_name_generator(),
                                                         names=['lfn' + generate_uuid() for _ in range(nb_files)], file_size=file_size)

    rse_core.set_rse_limits(rse_id=rse_id, name='MinFreeSpace', value=50 * file_size)
    assert len(list(replica_core.list_replicas(dids=dids, rse_expression=rse_name))) == nb_files

    # Check first if the reaper does not delete anything if no space is needed
    cache_region.invalidate()
    rse_core.set_rse_usage(rse_id=rse_id, source='storage', used=nb_files * file_size, free=323000000000)
    reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=None)
    assert len(list(replica_core.list_replicas(dids=dids, rse_expression=rse_name))) == nb_files

    # Now put it over threshold and delete
    cache_region.invalidate()
    rse_core.set_rse_usage(rse_id=rse_id, source='storage', used=nb_files * file_size, free=1)
    reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=None)
    reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=None)
    assert len(list(replica_core.list_replicas(dids, rse_expression=rse_name))) == 200

    msgs = message_core.retrieve_messages()
    assert len(msgs) == 50  # one for each deleted file
    assert all(msg['payload']['datatype'] == 'SOME_DATATYPE' for msg in msgs)

    # run dark reaper just to catch the simplest possible errors in this daemon.
    # TODO: remove this when/if we implement good testing for dark reaper
    dark_reaper(once=True, rses=[rse_id])


@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.daemons.reaper.reaper.REGION'
]}], indirect=True)
def test_reaper_bulk_delete(vo, caches_mock):
    """ REAPER (DAEMON): Mock test the reaper daemon on async bulk delete request."""
    [cache_region] = caches_mock
    scope = InternalScope('data13_hip', vo=vo)

    nb_files = 250
    file_size = 200  # 2G
    rse_name, rse_id, dids = __add_test_rse_and_replicas(vo=vo, scope=scope, rse_name=rse_name_generator(),
                                                         names=['lfn' + generate_uuid() for _ in range(nb_files)], file_size=file_size)

    rse_core.set_rse_limits(rse_id=rse_id, name='MinFreeSpace', value=50 * file_size)
    assert len(list(replica_core.list_replicas(dids=dids, rse_expression=rse_name))) == nb_files

    # Check first if the reaper does not delete anything if no space is needed
    cache_region.invalidate()
    rse_core.set_rse_usage(rse_id=rse_id, source='storage', used=nb_files * file_size, free=323000000000)
    reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=None, chunk_size=1000, scheme='MOCK')
    assert len(list(replica_core.list_replicas(dids=dids, rse_expression=rse_name))) == nb_files

    # Now put it over threshold and delete
    cache_region.invalidate()
    rse_core.set_rse_usage(rse_id=rse_id, source='storage', used=nb_files * file_size, free=1)
    reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=None, chunk_size=1000, scheme='MOCK')
    reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=None, chunk_size=1000, scheme='MOCK')
    assert len(list(replica_core.list_replicas(dids, rse_expression=rse_name))) == 200


@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.daemons.reaper.reaper.REGION'
]}], indirect=True)
def test_reaper_multi_vo_via_run(vo, second_vo, scope_factory, caches_mock):
    """ MULTI VO (DAEMON): Test that reaper runs on the specified VO(s) """
    [cache_region] = caches_mock
    new_vo = second_vo
    scope_name, [scope_tst, scope_new] = scope_factory(vos=[vo, new_vo])
    rse_name = rse_name_generator()

    nb_files = 30
    file_size = 200  # 2G
    names = ['lfn' + generate_uuid() for _ in range(nb_files)]
    _, rse_id_tst, _ = __add_test_rse_and_replicas(vo=vo, scope=scope_tst, rse_name=rse_name, names=names, file_size=file_size)
    _, rse_id_new, _ = __add_test_rse_and_replicas(vo=new_vo, scope=scope_new, rse_name=rse_name, names=names, file_size=file_size)

    rse_api.set_rse_usage(rse=rse_name, source='storage', used=nb_files * file_size, free=1, issuer='root', vo=vo)
    rse_api.set_rse_limits(rse=rse_name, name='MinFreeSpace', value=5 * 200, issuer='root', vo=vo)

    rse_api.set_rse_usage(rse=rse_name, source='storage', used=nb_files * file_size, free=1, issuer='root', vo=new_vo)
    rse_api.set_rse_limits(rse=rse_name, name='MinFreeSpace', value=5 * 200, issuer='root', vo=new_vo)

    # Check we start of with the expected number of replicas
    assert len(list(replica_api.list_replicas([{'scope': scope_name, 'name': n} for n in names], rse_expression=rse_name, vo=vo))) == nb_files
    assert len(list(replica_api.list_replicas([{'scope': scope_name, 'name': n} for n in names], rse_expression=rse_name, vo=new_vo))) == nb_files

    # Check we reap all VOs by default
    cache_region.invalidate()
    run_reaper(once=True, rses=[rse_name])
    assert len(list(replica_api.list_replicas([{'scope': scope_name, 'name': n} for n in names], rse_expression=rse_name, vo=vo))) == 25
    assert len(list(replica_api.list_replicas([{'scope': scope_name, 'name': n} for n in names], rse_expression=rse_name, vo=new_vo))) == 25


@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.daemons.reaper.reaper.REGION'
]}], indirect=True)
def test_reaper_affect_other_vo_via_run(vo, second_vo, scope_factory, caches_mock):
    """ MULTI VO (DAEMON): Test that reaper runs on the specified VO(s) and does not reap others"""
    [cache_region] = caches_mock
    new_vo = second_vo
    scope_name, [scope_tst, scope_new] = scope_factory(vos=[vo, new_vo])
    rse_name = rse_name_generator()

    nb_files = 30
    file_size = 200  # 2G
    names = ['lfn' + generate_uuid() for _ in range(nb_files)]
    _, rse_id_tst, _ = __add_test_rse_and_replicas(vo=vo, scope=scope_tst, rse_name=rse_name, names=names, file_size=file_size)
    _, rse_id_new, _ = __add_test_rse_and_replicas(vo=new_vo, scope=scope_new, rse_name=rse_name, names=names, file_size=file_size)

    rse_api.set_rse_usage(rse=rse_name, source='storage', used=nb_files * file_size, free=1, issuer='root', vo=vo)
    rse_api.set_rse_limits(rse=rse_name, name='MinFreeSpace', value=5 * 200, issuer='root', vo=vo)

    rse_api.set_rse_usage(rse=rse_name, source='storage', used=nb_files * file_size, free=1, issuer='root', vo=new_vo)
    rse_api.set_rse_limits(rse=rse_name, name='MinFreeSpace', value=5 * 200, issuer='root', vo=new_vo)

    # Check we start of with the expected number of replicas
    assert len(list(replica_api.list_replicas([{'scope': scope_name, 'name': n} for n in names], rse_expression=rse_name, vo=vo))) == nb_files
    assert len(list(replica_api.list_replicas([{'scope': scope_name, 'name': n} for n in names], rse_expression=rse_name, vo=new_vo))) == nb_files

    # Check we don't affect a second VO that isn't specified
    cache_region.invalidate()
    run_reaper(once=True, rses=[rse_name], vos=['new'])
    assert len(list(replica_api.list_replicas([{'scope': scope_name, 'name': n} for n in names], rse_expression=rse_name, vo=vo))) == nb_files
    assert len(list(replica_api.list_replicas([{'scope': scope_name, 'name': n} for n in names], rse_expression=rse_name, vo=new_vo))) == 25


@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.daemons.reaper.reaper.REGION'
]}], indirect=True)
def test_reaper_multi_vo(vo, second_vo, scope_factory, caches_mock):
    """ REAPER (DAEMON): Test the reaper daemon with multiple vo."""
    [cache_region] = caches_mock
    new_vo = second_vo
    _, [scope_tst, scope_new] = scope_factory(vos=[vo, new_vo])

    nb_files = 250
    file_size = 200  # 2G
    rse1_name, rse1_id, dids1 = __add_test_rse_and_replicas(vo=vo, scope=scope_tst, rse_name=rse_name_generator(),
                                                            names=['lfn' + generate_uuid() for _ in range(nb_files)], file_size=file_size)
    rse2_name, rse2_id, dids2 = __add_test_rse_and_replicas(vo=new_vo, scope=scope_new, rse_name=rse_name_generator(),
                                                            names=['lfn' + generate_uuid() for _ in range(nb_files)], file_size=file_size)

    rse_core.set_rse_limits(rse_id=rse1_id, name='MinFreeSpace', value=50 * file_size)
    rse_core.set_rse_limits(rse_id=rse2_id, name='MinFreeSpace', value=50 * file_size)

    # Check we reap all VOs by default
    cache_region.invalidate()
    rse_core.set_rse_usage(rse_id=rse1_id, source='storage', used=nb_files * file_size, free=1)
    rse_core.set_rse_usage(rse_id=rse2_id, source='storage', used=nb_files * file_size, free=1)
    both_rses = '%s|%s' % (rse1_name, rse2_name)
    reaper(once=True, rses=[], include_rses=both_rses, exclude_rses=None)
    reaper(once=True, rses=[], include_rses=both_rses, exclude_rses=None)
    assert len(list(replica_core.list_replicas(dids=dids1, rse_expression=both_rses))) == 200
    assert len(list(replica_core.list_replicas(dids=dids2, rse_expression=both_rses))) == 200


@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.daemons.reaper.reaper.REGION'
]}], indirect=True)
def test_archive_removal_impact_on_constituents(rse_factory, did_factory, mock_scope, root_account, caches_mock):
    [cache_region] = caches_mock
    rse_name, rse_id = rse_factory.make_mock_rse()
    scope = mock_scope
    account = root_account

    # Create 2 archives and 4 files:
    # - One only exists in the first archive
    # - One in both, plus another replica, which is not in an archive
    # - One in both, plus another replica, which is not in an archive; and this replica has expired
    # - One in both, plus another replica, which is not in an archive; and this replica has expired; but a replication rule exists on this second replica
    # Also add these files to datasets, one of which will be removed at the end
    nb_constituents = 4
    nb_c_outside_archive = nb_constituents - 1
    constituent_size = 2000
    archive_size = 1000
    uuid = str(generate_uuid())
    constituents = [{'scope': scope, 'name': 'lfn.%s.%d' % (uuid, i)} for i in range(nb_constituents)]
    did_factory.register_dids(constituents)
    c_first_archive_only, c_with_replica, c_with_expired_replica, c_with_replica_and_rule = constituents

    replica_core.add_replica(rse_id=rse_id, account=account, bytes_=constituent_size, **c_with_replica)

    replica_core.add_replica(rse_id=rse_id, account=account, bytes_=constituent_size,
                             tombstone=datetime.utcnow() - timedelta(days=1), **c_with_expired_replica)

    replica_core.add_replica(rse_id=rse_id, account=account, bytes_=constituent_size,
                             tombstone=datetime.utcnow() - timedelta(days=1), **c_with_replica_and_rule)
    rule_core.add_rule(dids=[c_with_replica_and_rule], account=account, copies=1, rse_expression=rse_name, grouping='NONE',
                       weight=None, lifetime=None, locked=False, subscription_id=None)

    archive1, archive2 = [{'scope': scope, 'name': 'archive_%s.%d.zip' % (uuid, i)} for i in range(2)]
    replica_core.add_replica(rse_id=rse_id, bytes_=archive_size, account=account, **archive1)
    replica_core.add_replica(rse_id=rse_id, bytes_=archive_size, account=account, **archive2)
    did_core.attach_dids(dids=[{'scope': c['scope'], 'name': c['name'], 'bytes': constituent_size} for c in constituents],
                         account=account, **archive1)
    did_core.attach_dids(dids=[{'scope': c['scope'], 'name': c['name'], 'bytes': constituent_size} for c in [c_with_replica, c_with_expired_replica, c_with_replica_and_rule]],
                         account=account, **archive2)

    dataset1, dataset2 = [{'scope': scope, 'name': 'dataset_%s.%i' % (uuid, i)} for i in range(2)]
    did_core.add_did(did_type='DATASET', account=account, **dataset1)
    did_core.attach_dids(dids=constituents, account=account, **dataset1)
    did_core.add_did(did_type='DATASET', account=account, **dataset2)
    did_core.attach_dids(dids=[c_first_archive_only, c_with_expired_replica], account=account, **dataset2)

    @read_session
    def __get_archive_contents_history_count(archive, *, session=None):
        return session.query(ConstituentAssociationHistory).filter_by(**archive).count()

    # Run reaper the first time.
    # the expired non-archive replica of c_with_expired_replica must be removed,
    # but the did must not be removed, and it must still remain in the dataset because
    # it still has the replica from inside the archive
    assert replica_core.get_replica(rse_id=rse_id, **c_with_expired_replica)
    cache_region.invalidate()
    rse_core.set_rse_limits(rse_id=rse_id, name='MinFreeSpace', value=2 * archive_size + nb_c_outside_archive * constituent_size)
    rse_core.set_rse_usage(rse_id=rse_id, source='storage', used=2 * archive_size + nb_c_outside_archive * constituent_size, free=1)
    reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=None)
    for did in constituents + [archive1, archive2]:
        assert did_core.get_did(**did)
    for did in [archive1, archive2, c_with_replica, c_with_replica_and_rule]:
        assert replica_core.get_replica(rse_id=rse_id, **did)
    with pytest.raises(ReplicaNotFound):
        # The replica is only on the archive, not on the constituent
        replica_core.get_replica(rse_id=rse_id, **c_first_archive_only)
    with pytest.raises(ReplicaNotFound):
        # The replica outside the archive was removed by reaper
        nb_c_outside_archive -= 1
        replica_core.get_replica(rse_id=rse_id, **c_with_expired_replica)
    # Compared to get_replica, list_replicas resolves archives, must return replicas for all files
    assert len(list(replica_core.list_replicas(dids=constituents))) == 4
    assert len(list(did_core.list_content(**dataset1))) == 4
    assert len(list(did_core.list_archive_content(**archive1))) == 4
    assert len(list(did_core.list_archive_content(**archive2))) == 3
    assert __get_archive_contents_history_count(archive1) == 0
    assert __get_archive_contents_history_count(archive2) == 0

    # Expire the first archive and run reaper again
    # the archive will be removed; and c_first_archive_only must be removed from datasets
    # and from the did table.
    replica_core.set_tombstone(rse_id=rse_id, tombstone=datetime.utcnow() - timedelta(days=1), **archive1)
    cache_region.invalidate()
    rse_core.set_rse_limits(rse_id=rse_id, name='MinFreeSpace', value=2 * archive_size + nb_c_outside_archive * constituent_size)
    rse_core.set_rse_usage(rse_id=rse_id, source='storage', used=2 * archive_size + nb_c_outside_archive * constituent_size, free=1)
    reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=None)
    with pytest.raises(DataIdentifierNotFound):
        assert did_core.get_did(**archive1)
    with pytest.raises(DataIdentifierNotFound):
        assert did_core.get_did(**c_first_archive_only)
    assert len(list(replica_core.list_replicas(dids=constituents))) == 3
    assert len(list(did_core.list_content(**dataset1))) == 3
    assert len(list(did_core.list_archive_content(**archive1))) == 0
    assert len(list(did_core.list_archive_content(**archive2))) == 3
    assert __get_archive_contents_history_count(archive1) == 4
    assert __get_archive_contents_history_count(archive2) == 0

    # Expire the second archive replica and run reaper another time
    # c_with_expired_replica is removed because its external replica got removed at previous step
    # and it exists only inside the archive now.
    # If not open, Dataset2 will be removed because it will be empty.
    did_core.set_status(open=False, **dataset2)
    replica_core.set_tombstone(rse_id=rse_id, tombstone=datetime.utcnow() - timedelta(days=1), **archive2)
    cache_region.invalidate()
    rse_core.set_rse_limits(rse_id=rse_id, name='MinFreeSpace', value=archive_size + nb_c_outside_archive * constituent_size)
    rse_core.set_rse_usage(rse_id=rse_id, source='storage', used=archive_size + nb_c_outside_archive * constituent_size, free=1)
    reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=None)
    # The archive must be removed
    with pytest.raises(DataIdentifierNotFound):
        assert did_core.get_did(**archive2)
    # The DIDs which only existed in the archive are also removed
    with pytest.raises(DataIdentifierNotFound):
        assert did_core.get_did(**c_first_archive_only)
    with pytest.raises(DataIdentifierNotFound):
        assert did_core.get_did(**c_with_expired_replica)
    # If the DID has a non-expired replica outside the archive without rules on it, the DID is not removed
    assert did_core.get_did(**c_with_replica)
    # If the DID has an expired replica outside the archive, but has rules on that replica, the DID is not removed
    assert did_core.get_did(**c_with_replica_and_rule)
    assert len(list(replica_core.list_replicas(dids=constituents))) == 2
    assert len(list(did_core.list_content(**dataset1))) == 2
    with pytest.raises(DataIdentifierNotFound):
        did_core.get_did(**dataset2)
    with pytest.raises(DataIdentifierNotFound):
        list(did_core.list_content(**dataset2))
    assert len(list(did_core.list_archive_content(**archive2))) == 0
    assert __get_archive_contents_history_count(archive1) == 4
    assert __get_archive_contents_history_count(archive2) == 3


@pytest.mark.parametrize("core_config_mock", [{"table_content": [
    ('deletion', 'archive_dids', True), ('deletion', 'archive_content', True)
]}], indirect=True)
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.daemons.reaper.reaper.REGION',
    'rucio.core.config.REGION',
    'rucio.core.replica.REGION',
]}], indirect=True)
def test_archive_of_deleted_dids(vo, did_factory, root_account, core_config_mock, caches_mock):
    """ REAPER (DAEMON): Test that the options to keep the did and content history work."""
    [reaper_cache_region, _config_cache_region, _replica_cache_region] = caches_mock
    scope = InternalScope('data13_hip', vo=vo)
    account = root_account

    nb_files = 10
    file_size = 200  # 2G
    rse_name, rse_id, dids = __add_test_rse_and_replicas(vo=vo, scope=scope, rse_name=rse_name_generator(),
                                                         names=['lfn' + generate_uuid() for _ in range(nb_files)], file_size=file_size, epoch_tombstone=True)
    dataset = did_factory.make_dataset()
    print(dataset)
    did_core.attach_dids(dids=dids, account=account, **dataset)

    rse_core.set_rse_limits(rse_id=rse_id, name='MinFreeSpace', value=50 * file_size)
    assert len(list(replica_core.list_replicas(dids=dids, rse_expression=rse_name))) == nb_files

    reaper_cache_region.invalidate()
    rse_core.set_rse_usage(rse_id=rse_id, source='storage', used=nb_files * file_size, free=323000000000)
    reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=None, greedy=True)
    assert len(list(replica_core.list_replicas(dids=dids, rse_expression=rse_name))) == 0

    file_clause = []
    for did in dids:
        file_clause.append(and_(models.DeletedDataIdentifier.scope == did['scope'], models.DeletedDataIdentifier.name == did['name']))

    session = get_session()
    query = session.query(models.DeletedDataIdentifier.scope,
                          models.DeletedDataIdentifier.name,
                          models.DeletedDataIdentifier.did_type).\
        filter(or_(*file_clause))

    deleted_dids = list()
    for did in query.all():
        print(did)
        deleted_dids.append(did)
    assert len(deleted_dids) == len(dids)

    query = session.query(models.DataIdentifierAssociationHistory.child_scope,
                          models.DataIdentifierAssociationHistory.child_name,
                          models.DataIdentifierAssociationHistory.child_type).\
        filter(and_(models.DataIdentifierAssociationHistory.scope == dataset['scope'], models.DataIdentifierAssociationHistory.name == dataset['name']))

    deleted_dids = list()
    for did in query.all():
        print(did)
        deleted_dids.append(did)
    assert len(deleted_dids) == len(dids)


@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.daemons.reaper.reaper.REGION'
]}], indirect=True)
def test_run_on_non_existing_scheme(vo, caches_mock):
    """ REAPER (DAEMON): Mock test the reaper daemon with a speficied scheme."""
    [cache_region] = caches_mock
    scope = InternalScope('data13_hip', vo=vo)

    nb_files = 250
    file_size = 200  # 2G
    rse_name, rse_id, dids = __add_test_rse_and_replicas(vo=vo, scope=scope, rse_name=rse_name_generator(),
                                                         names=['lfn' + generate_uuid() for _ in range(nb_files)], file_size=file_size)

    rse_core.set_rse_limits(rse_id=rse_id, name='MinFreeSpace', value=50 * file_size)
    assert len(list(replica_core.list_replicas(dids=dids, rse_expression=rse_name))) == nb_files

    # Now put it over threshold and delete
    # Nothing should be deleted since the protocol doesn't exists for this RSE
    # The reaper will set a flag pause_deletion_<rse_id>
    cache_region.invalidate()
    rse_core.set_rse_usage(rse_id=rse_id, source='storage', used=nb_files * file_size, free=1)
    reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=None, chunk_size=1000, scheme='https')
    assert len(list(replica_core.list_replicas(dids, rse_expression=rse_name))) == 250
    assert cache_region.get('pause_deletion_%s' % rse_id)


@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.daemons.reaper.reaper.REGION'
]}], indirect=True)
def test_reaper_without_rse_usage(vo, caches_mock):
    """ REAPER (DAEMON): Mock test the reaper daemon and check it deletes obsolete replicas even if no rse_usage is set."""
    [cache_region] = caches_mock
    scope = InternalScope('data13_hip', vo=vo)

    nb_files = 250
    nb_epoch_tombstone = 10
    file_size = 200  # 2G
    rse_name, rse_id, dids = __add_test_rse_and_replicas(vo=vo, scope=scope, rse_name=rse_name_generator(),
                                                         names=['lfn' + generate_uuid() for _ in range(nb_files)], file_size=file_size)

    rse_core.set_rse_limits(rse_id=rse_id, name='MinFreeSpace', value=50 * file_size)
    assert len(list(replica_core.list_replicas(dids=dids, rse_expression=rse_name))) == nb_files

    # Check first if the reaper does not delete anything if there's nothing obsolete
    cache_region.invalidate()
    reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=None, chunk_size=1000, scheme='MOCK')
    assert len(list(replica_core.list_replicas(dids=dids, rse_expression=rse_name))) == nb_files

    # Now set Epoch tombstone for a few replicas
    for did in dids[:nb_epoch_tombstone]:
        print(did)
        replica_core.set_tombstone(rse_id, did['scope'], did['name'], tombstone=OBSOLETE)

    # The reaper should delete the replica with Epoch tombstone even if the rse_usage is not set
    cache_region.invalidate()
    reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=None, chunk_size=1000, scheme='MOCK')
    assert len(list(replica_core.list_replicas(dids, rse_expression=rse_name))) == nb_files - nb_epoch_tombstone


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason="leaves files in XRD containers")
@pytest.mark.noparallel(groups=[NoParallelGroups.WEB])
@pytest.mark.parametrize("caches_mock", [{"caches_to_mock": [
    'rucio.daemons.reaper.reaper.REGION'
]}], indirect=True)
@pytest.mark.parametrize("file_config_mock", [
    {"overrides": [('oidc', 'admin_issuer', 'indigoiam')]},
], indirect=True)
def test_deletion_with_tokens(vo, did_factory, root_account, caches_mock, file_config_mock):
    rse_name = 'WEB1'
    did = did_factory.upload_test_file(rse_name)
    for rule in list(rule_core.list_associated_rules_for_file(**did)):
        rule_core.delete_rule(rule['id'])

    reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=None, chunk_size=1000, greedy=True, scheme='davs')
