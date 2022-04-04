# -*- coding: utf-8 -*-
# Copyright 2021-2022 CERN
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
# - Cedric Serfon <cedric.serfon@cern.ch>, 2021-2022

from __future__ import print_function

from datetime import datetime, timedelta
from json import dumps, loads

import pytest

from rucio.common.exception import RucioException, UnsupportedOperation, InvalidType
from rucio.common.utils import generate_uuid, clean_surls
from rucio.core.did import delete_dids
from rucio.core.replica import (add_replicas, get_replicas_state, list_replicas,
                                declare_bad_file_replicas, list_bad_replicas, get_bad_pfns,
                                get_bad_replicas_backlog, list_bad_replicas_status)
from rucio.daemons.badreplicas.minos import run as minos_run
from rucio.daemons.badreplicas.minos_temporary_expiration import run as minos_temp_run
from rucio.daemons.badreplicas.necromancer import run as necromancer_run
from rucio.daemons.badreplicas.necromancer import REGION
from rucio.db.sqla.constants import DIDType, ReplicaState, BadPFNStatus, BadFilesStatus
from rucio.tests.common import headers, auth


@pytest.mark.noparallel(reason='calls list_bad_replicas() which acts on all bad replicas without any filtering')
def test_add_list_bad_replicas(rse_factory, mock_scope, root_account):
    """ REPLICA (CORE): Add bad replicas and list them"""

    nbfiles = 5
    # Adding replicas to deterministic RSE
    _, rse1_id = rse_factory.make_srm_rse(deterministic=True)
    files = [{'scope': mock_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
    add_replicas(rse_id=rse1_id, files=files, account=root_account, ignore_availability=True)

    # Listing replicas on deterministic RSE
    replicas = []
    list_rep = []
    for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm']):
        replicas.extend(replica['rses'][rse1_id])
        list_rep.append(replica)
    r = declare_bad_file_replicas(replicas, 'This is a good reason', root_account)
    assert r == {}
    bad_replicas = list_bad_replicas()
    nbbadrep = 0
    for rep in list_rep:
        for badrep in bad_replicas:
            if badrep['rse_id'] == rse1_id:
                if badrep['scope'] == rep['scope'] and badrep['name'] == rep['name']:
                    nbbadrep += 1
    assert len(replicas) == nbbadrep

    # Adding replicas to non-deterministic RSE
    _, rse2_id = rse_factory.make_srm_rse(deterministic=False)
    files = [{'scope': mock_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb',
              'pfn': 'srm://%s.cern.ch/srm/managerv2?SFN=/test/%s/%s' % (rse2_id, mock_scope, generate_uuid()), 'meta': {'events': 10}} for _ in range(nbfiles)]
    add_replicas(rse_id=rse2_id, files=files, account=root_account, ignore_availability=True)

    # Listing replicas on non-deterministic RSE
    replicas = []
    list_rep = []
    for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm']):
        replicas.extend(replica['rses'][rse2_id])
        list_rep.append(replica)
    r = declare_bad_file_replicas(replicas, 'This is a good reason', root_account)
    assert r == {}
    bad_replicas = list_bad_replicas()
    nbbadrep = 0
    for rep in list_rep:
        for badrep in bad_replicas:
            if badrep['rse_id'] == rse2_id:
                if badrep['scope'] == rep['scope'] and badrep['name'] == rep['name']:
                    nbbadrep += 1
    assert len(replicas) == nbbadrep

    # Try adding replicas already declared bad
    r = declare_bad_file_replicas(replicas, 'This is a good reason', root_account)
    output = ['%s Unknown replica' % rep for rep in replicas]
    assert list(r.keys()) == [rse2_id]
    list1 = r[rse2_id]
    list1.sort()
    list2 = ['%s Already declared' % clean_surls([rep])[0] for rep in replicas]
    list2.sort()
    assert list1 == list2

    # Now adding non-existing bad replicas
    files = ['srm://%s.cern.ch/test/%s/%s' % (rse2_id, mock_scope, generate_uuid()), ]
    r = declare_bad_file_replicas(files, 'This is a good reason', root_account)
    output = ['%s Unknown replica' % rep for rep in files]
    assert r == {rse2_id: output}


@pytest.mark.noparallel(reason='runs necromancer which acts on all bad replicas without any filtering')
@pytest.mark.parametrize("file_config_mock", [{
    "overrides": [('necromancer', 'max_bad_replicas_backlog_count', '20')]
}], indirect=True)
def test_get_bad_replicas_backlog(rse_factory, mock_scope, root_account, file_config_mock):
    """ REPLICA (CORE): Check the behaviour of the necromancer in case of backlog on an RSE"""

    # Run necromancer once
    necromancer_run(threads=1, bulk=10000, once=True)

    nbfiles1 = 100
    nbfiles2 = 20
    # Adding replicas to deterministic RSE
    rse1, rse1_id = rse_factory.make_srm_rse(deterministic=True)
    _, rse2_id = rse_factory.make_srm_rse(deterministic=True)

    # Create bad replicas on rse1
    files = [{'scope': mock_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles1)]
    add_replicas(rse_id=rse1_id, files=files, account=root_account, ignore_availability=True)

    replicas = []
    list_rep = []
    for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm']):
        replicas.extend(replica['rses'][rse1_id])
        list_rep.append({'scope': replica['scope'], 'name': replica['name'], 'rse': rse1, 'rse_id': rse1_id})
    res = declare_bad_file_replicas(replicas, 'This is a good reason', root_account)
    assert res == {}

    result = get_bad_replicas_backlog()
    assert rse1_id in result
    assert result[rse1_id] == nbfiles1

    # Create more bad replicas on rse2
    files = [{'scope': mock_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles2)]
    add_replicas(rse_id=rse2_id, files=files, account=root_account, ignore_availability=True)

    repl = []
    for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm']):
        repl.extend(replica['rses'][rse2_id])
    res = declare_bad_file_replicas(repl, 'This is a good reason', root_account)
    assert res == {}

    # List bad replicas on rse1
    bad_replicas = list_bad_replicas(rses=[{'id': rse1_id}])
    assert len(bad_replicas) == nbfiles1
    for rep in bad_replicas:
        assert rep in list_rep

    # Run necromancer once, all the files on RSE2 should be gone, 80 files should stay on RSE1
    REGION.invalidate()
    get_bad_replicas_backlog()
    necromancer_run(threads=1, bulk=20, once=True)

    bad_replicas = list_bad_replicas(rses=[{'id': rse1_id}, {'id': rse2_id}])
    assert len(bad_replicas) == 80
    for rep in bad_replicas:
        assert rep['rse_id'] == rse1_id


@pytest.mark.noparallel(reason='calls list_bad_replicas() and runs necromancer. Both act on all bad replicas without any filtering')
def test_client_add_list_bad_replicas(rse_factory, replica_client, did_client):
    """ REPLICA (CLIENT): Add bad replicas"""
    tmp_scope = 'mock'
    nbfiles = 5
    # Adding replicas to deterministic RSE
    files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
    rse1, rse1_id = rse_factory.make_srm_rse(deterministic=True)
    replica_client.add_replicas(rse=rse1, files=files)

    # Listing replicas on deterministic RSE
    replicas, list_rep = [], []
    for replica in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], all_states=True):
        replicas.extend(replica['rses'][rse1])
        list_rep.append(replica)
    r = replica_client.declare_bad_file_replicas(replicas, 'This is a good reason')
    assert r == {}
    bad_replicas = list_bad_replicas()
    nbbadrep = 0
    for rep in list_rep:
        for badrep in bad_replicas:
            if badrep['rse_id'] == rse1_id:
                if badrep['scope'].external == rep['scope'] and badrep['name'] == rep['name']:
                    nbbadrep += 1
    assert len(replicas) == nbbadrep

    # Run necromancer once
    necromancer_run(threads=1, bulk=10000, once=True)

    # Try to attach a lost file
    tmp_dsn = 'dataset_%s' % generate_uuid()
    did_client.add_dataset(scope=tmp_scope, name=tmp_dsn)
    with pytest.raises(UnsupportedOperation):
        did_client.add_files_to_dataset(tmp_scope, name=tmp_dsn, files=files, rse=rse1)

    # Adding replicas to non-deterministic RSE
    rse2, rse2_id = rse_factory.make_srm_rse(deterministic=False)
    files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb',
              'pfn': 'srm://%s.cern.ch/srm/managerv2?SFN=/test/%s/%s' % (rse2_id, tmp_scope, generate_uuid()), 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse=rse2, files=files)

    # Listing replicas on non-deterministic RSE
    replicas, list_rep = [], []
    for replica in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], all_states=True):
        replicas.extend(replica['rses'][rse2])
        list_rep.append(replica)
    r = replica_client.declare_bad_file_replicas(replicas, 'This is a good reason')
    assert r == {}
    bad_replicas = list_bad_replicas()
    nbbadrep = 0
    for rep in list_rep:
        for badrep in bad_replicas:
            if badrep['rse_id'] == rse2_id:
                if badrep['scope'].external == rep['scope'] and badrep['name'] == rep['name']:
                    nbbadrep += 1
    assert len(replicas) == nbbadrep

    # Now adding non-existing bad replicas
    files = ['srm://%s.cern.ch/test/%s/%s' % (rse2_id, tmp_scope, generate_uuid()), ]
    r = replica_client.declare_bad_file_replicas(files, 'This is a good reason')
    output = ['%s Unknown replica' % rep for rep in files]
    assert r == {rse2: output}

    # Now test adding bad_replicas with a list of replicas instead of PFNs
    # Adding replicas to deterministic RSE
    rse3, rse3_id = rse_factory.make_srm_rse(deterministic=True)
    files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse=rse3, files=files)
    list_rep = [{'scope': file_['scope'], 'name': file_['name'], 'rse': rse3} for file_ in files]

    # Listing replicas on deterministic RSE
    replicas = []
    for replica in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], all_states=True):
        replicas.extend(replica['rses'][rse3])
    r = replica_client.declare_bad_file_replicas(list_rep, 'This is a good reason')
    assert r == {}
    bad_replicas = list_bad_replicas()
    nbbadrep = 0
    for rep in list_rep:
        for badrep in bad_replicas:
            if badrep['rse_id'] == rse3_id:
                if badrep['scope'].external == rep['scope'] and badrep['name'] == rep['name']:
                    nbbadrep += 1
    assert len(replicas) == nbbadrep

    # InvalidType is raised if list_rep contains a mixture of replicas and PFNs
    list_rep.extend(['srm://%s.cern.ch/test/%s/%s' % (rse2_id, tmp_scope, generate_uuid()), ])
    with pytest.raises(InvalidType):
        r = replica_client.declare_bad_file_replicas(list_rep, 'This is a good reason')


def test_client_add_suspicious_replicas(rse_factory, replica_client):
    """ REPLICA (CLIENT): Add suspicious replicas"""
    tmp_scope = 'mock'
    nbfiles = 5
    # Adding replicas to deterministic RSE
    rse1, _ = rse_factory.make_srm_rse(deterministic=True)
    files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse=rse1, files=files)

    # Listing replicas on deterministic RSE
    replicas = []
    list_rep = []
    for replica in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], all_states=True):
        replicas.extend(replica['rses'][rse1])
        list_rep.append(replica)
    r = replica_client.declare_suspicious_file_replicas(replicas, 'This is a good reason')
    assert r == {}

    # Adding replicas to non-deterministic RSE
    rse2, rse2_id = rse_factory.make_srm_rse(deterministic=False)
    files = [{'scope': tmp_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb',
              'pfn': 'srm://%s.cern.ch/srm/managerv2?SFN=/test/%s/%s' % (rse2_id, tmp_scope, generate_uuid()), 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse=rse2, files=files)

    # Listing replicas on non-deterministic RSE
    replicas = []
    list_rep = []
    for replica in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['srm'], all_states=True):
        replicas.extend(replica['rses'][rse2])
        list_rep.append(replica)
    r = replica_client.declare_suspicious_file_replicas(replicas, 'This is a good reason')
    assert r == {}
    # Now adding non-existing bad replicas
    files = ['srm://%s.cern.ch/test/%s/%s' % (rse2_id, tmp_scope, generate_uuid()), ]
    r = replica_client.declare_suspicious_file_replicas(files, 'This is a good reason')
    output = ['%s Unknown replica' % rep for rep in files]
    assert r == {rse2: output}


@pytest.mark.noparallel(reason='Lists bad replicas multiple times. If the list changes between calls, test fails.')
def test_rest_bad_replica_methods_for_ui(rest_client, auth_token):
    __test_rest_bad_replica_methods_for_ui(rest_client, auth_token, list_pfns=False)
    __test_rest_bad_replica_methods_for_ui(rest_client, auth_token, list_pfns=True)


def __test_rest_bad_replica_methods_for_ui(rest_client, auth_token, list_pfns):
    """ REPLICA (REST): Test the listing of bad and suspicious replicas """
    if list_pfns:
        common_data = {'list_pfns': 'True'}
    else:
        common_data = {}

    data = {**common_data}
    response = rest_client.get('/replicas/bad/states', headers=headers(auth(auth_token)), query_string=data)
    assert response.status_code == 200
    tot_files = []
    for line in response.get_data(as_text=True).split('\n'):
        if line != '':
            tot_files.append(dumps(line))
    nb_tot_files = len(tot_files)

    data = {'state': 'B', **common_data}
    response = rest_client.get('/replicas/bad/states', headers=headers(auth(auth_token)), query_string=data)
    assert response.status_code == 200
    tot_bad_files = []
    for line in response.get_data(as_text=True).split('\n'):
        if line != '':
            tot_bad_files.append(dumps(line))
    nb_tot_bad_files1 = len(tot_bad_files)

    data = {'state': 'S', **common_data}
    response = rest_client.get('/replicas/bad/states', headers=headers(auth(auth_token)), query_string=data)
    assert response.status_code == 200
    tot_suspicious_files = []
    for line in response.get_data(as_text=True).split('\n'):
        if line != '':
            tot_suspicious_files.append(dumps(line))
    nb_tot_suspicious_files = len(tot_suspicious_files)

    data = {'state': 'T', **common_data}
    response = rest_client.get('/replicas/bad/states', headers=headers(auth(auth_token)), query_string=data)
    assert response.status_code == 200
    tot_temporary_unavailable_files = []
    for line in response.get_data(as_text=True).split('\n'):
        if line != '':
            tot_temporary_unavailable_files.append(dumps(line))
    nb_tot_temporary_unavailable_files = len(tot_temporary_unavailable_files)

    assert nb_tot_files == nb_tot_bad_files1 + nb_tot_suspicious_files + nb_tot_temporary_unavailable_files

    tomorrow = datetime.utcnow() + timedelta(days=1)
    data = {'state': 'B', 'younger_than': tomorrow.isoformat(), **common_data}
    response = rest_client.get('/replicas/bad/states', headers=headers(auth(auth_token)), query_string=data)
    assert response.status_code == 200
    tot_bad_files = []
    for line in response.get_data(as_text=True).split('\n'):
        if line != '':
            tot_bad_files.append(dumps(line))
    nb_tot_bad_files = len(tot_bad_files)
    assert nb_tot_bad_files == 0

    if not list_pfns:
        response = rest_client.get('/replicas/bad/summary', headers=headers(auth(auth_token)))
        assert response.status_code == 200
        nb_tot_bad_files2 = 0
        for line in response.get_data(as_text=True).split('\n'):
            if line != '':
                line = loads(line)
                nb_tot_bad_files2 += int(line.get('BAD', 0))
        assert nb_tot_bad_files1 == nb_tot_bad_files2


@pytest.mark.dirty
@pytest.mark.noparallel(reason='runs minos, which acts on all bad pfns')
def test_client_add_temporary_unavailable_pfns(rse_factory, mock_scope, replica_client):
    """ REPLICA (CLIENT): Add temporary unavailable PFNs"""
    rse, rse_id = rse_factory.make_posix_rse()
    nbfiles = 5
    # Adding replicas to deterministic RSE
    files = [{'scope': mock_scope.external, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
    replica_client.add_replicas(rse=rse, files=files)

    # Listing replicas on deterministic RSE
    list_rep = []
    for replica in replica_client.list_replicas(dids=[{'scope': f['scope'], 'name': f['name']} for f in files], schemes=['file'], all_states=True):
        pfn = list(replica['pfns'].keys())[0]
        list_rep.append(pfn)

    # Submit bad PFNs
    now = datetime.utcnow()
    reason_str = generate_uuid()
    replica_client.add_bad_pfns(pfns=list_rep, reason=str(reason_str), state='TEMPORARY_UNAVAILABLE', expires_at=now.isoformat())
    result = get_bad_pfns(limit=10000, thread=None, total_threads=None, session=None)
    bad_pfns = {}
    for res in result:
        bad_pfns[res['pfn']] = (res['state'], res['reason'], res['expires_at'])

    for pfn in list_rep:
        pfn = str(clean_surls([pfn])[0])
        assert pfn in bad_pfns
        assert bad_pfns[pfn][0] == BadPFNStatus.TEMPORARY_UNAVAILABLE
        assert bad_pfns[pfn][1] == reason_str

    # Submit with wrong state
    with pytest.raises(RucioException):
        replica_client.add_bad_pfns(pfns=list_rep, reason=str(reason_str), state='BADSTATE', expires_at=now.isoformat())

    # Run minos once
    minos_run(threads=1, bulk=10000, once=True)
    result = get_bad_pfns(limit=10000, thread=None, total_threads=None, session=None)
    pfns = [res['pfn'] for res in result if res['pfn'] in bad_pfns]
    res_pfns = []
    for replica in list_rep:
        if replica in pfns:
            res_pfns.append(replica)
    assert res_pfns == []

    # Check the state in the replica table
    for did in files:
        rep = get_replicas_state(scope=mock_scope, name=did['name'])
        assert list(rep.keys())[0] == ReplicaState.TEMPORARY_UNAVAILABLE

    rep = []
    for did in files:
        did['state'] = ReplicaState.TEMPORARY_UNAVAILABLE
        rep.append(did)

    # Run the minos expiration
    minos_temp_run(threads=1, once=True)
    # Check the state in the replica table
    for did in files:
        rep = get_replicas_state(scope=mock_scope, name=did['name'])
        assert list(rep.keys())[0] == ReplicaState.AVAILABLE


def test_add_and_delete_bad_replicas(rse_factory, mock_scope, root_account, did_client, vo):
    """ REPLICA (CORE): Add bad replicas and delete them"""
    # Adding replicas to deterministic RSE
    nbfiles = 5
    rse1, rse1_id = rse_factory.make_srm_rse(deterministic=True, vo=vo)
    files = [{'scope': mock_scope, 'name': 'file_%s' % generate_uuid(), 'bytes': 1, 'adler32': '0cc737eb', 'meta': {'events': 10}} for _ in range(nbfiles)]
    client_files = [{'scope': file_['scope'].external, 'name': file_['name']} for file_ in files]
    add_replicas(rse_id=rse1_id, files=files, account=root_account, ignore_availability=True)
    tmp_dsn = 'dataset_%s' % generate_uuid()
    did_client.add_dataset(scope=mock_scope.external, name=tmp_dsn)
    did_client.add_files_to_dataset(mock_scope.external, name=tmp_dsn, files=client_files, rse=rse1)

    # Declare replica bad
    replicas = []
    for replica in list_replicas(dids=[{'scope': f['scope'], 'name': f['name'], 'type': DIDType.FILE} for f in files], schemes=['srm']):
        replicas.extend(replica['rses'][rse1_id])
    r = declare_bad_file_replicas(replicas, 'This is a good reason', root_account)
    assert r == {}

    # Check state of bad replicas
    list_bad_rep = [{'scope': rep['scope'].external, 'name': rep['name']} for rep in list_bad_replicas_status(state=BadFilesStatus.BAD, rse_id=rse1_id, vo=vo)]
    for rep in client_files:
        assert rep in list_bad_rep
    assert [rep for rep in list_bad_replicas_status(state=BadFilesStatus.DELETED, rse_id=rse1_id, vo=vo)] == []

    # Now delete the dataset
    delete_dids([{'scope': mock_scope, 'name': tmp_dsn, 'did_type': DIDType.DATASET, 'purge_replicas': True}], account=root_account)
    assert [rep for rep in list_bad_replicas_status(state=BadFilesStatus.BAD, rse_id=rse1_id, vo=vo)] == []
    list_deleted_rep = [{'scope': rep['scope'].external, 'name': rep['name']} for rep in list_bad_replicas_status(state=BadFilesStatus.DELETED, rse_id=rse1_id, vo=vo)]
    for rep in client_files:
        assert rep in list_deleted_rep
