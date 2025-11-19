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

from datetime import datetime
from pathlib import Path

import pytest
from belleii_rucio_policy_package.schema import validate_schema

from rucio.common.exception import InvalidObject
from rucio.common.utils import extract_scope, generate_uuid
from rucio.core.config import remove_option
from rucio.core.config import set as config_set
from rucio.tests.common import did_name_generator, skip_non_belleii


@skip_non_belleii
@pytest.mark.parametrize("file_lifetime", [86400.0, None])
def test_dirac_addfile(rse_factory, did_factory, root_account, did_client, dirac_client, rse_client, replica_client, file_lifetime):
    """ DIRAC (CLIENT): Test the functionality of the addfile method """
    nbfiles = 5
    rse1, rse1_id = rse_factory.make_srm_rse(deterministic=True)
    rse_client.add_rse_attribute(rse=rse1, key='ANY', value='True')
    config_set('dirac', 'lifetime', '{"user.*": 2592400}')

    if file_lifetime is not None:
        config_set('dirac', 'file_lifetime', file_lifetime)
    else:
        remove_option('dirac', 'file_lifetime')

    # Create replicas on rse1 using addfile in mock scope (not lifetime)
    lfns = [{'lfn': did_name_generator('file'), 'rse': rse1, 'bytes': 1, 'adler32': '0cc737eb', 'guid': generate_uuid()} for _ in range(nbfiles)]
    files = [{'scope': extract_scope(lfn['lfn'], [])[0], 'name': lfn['lfn']} for lfn in lfns]
    reps = [{'scope': extract_scope(lfn['lfn'], [])[0], 'name': lfn['lfn'], 'rse': rse1} for lfn in lfns]
    dirac_client.add_files(lfns=lfns, ignore_availability=False)
    replicas = [rep for rep in replica_client.list_replicas(dids=files)]
    for replica in replicas:
        assert {'scope': replica['scope'], 'name': replica['name'], 'rse': list(replica['rses'].keys())[0]} in reps

    # Check the existence of all parents from the files
    for lfn in lfns:
        directories = lfn['lfn'].split('/')
        for cnt, directory in enumerate(directories):
            parent = "/".join(directories[0:cnt])
            child = "/".join(directories[0:cnt + 1])
            if parent != '':
                parent_scope, parent_name = extract_scope(parent, [])
                children = [did['name'] for did in did_client.list_content(parent_scope, parent_name)]
                assert child in children

    # Check that the default rules are created
    for lfn in lfns:
        # Check dataset rule
        directory = "/".join(lfn['lfn'].split('/')[:-1])
        scope, name = extract_scope(directory, [])
        rules = [rule for rule in did_client.list_did_rules(scope, name)]
        assert len(rules) == 1
        assert rules[0]['rse_expression'] == 'ANY=true'
        assert rules[0]['expires_at'] is None

        # Check file rule
        scope, name = extract_scope(lfn['lfn'], [])
        rules = [rule for rule in did_client.list_did_rules(scope, name)]
        assert len(rules) == 1
        assert rules[0]['rse_expression'] == rse1

        if file_lifetime is not None:
            assert (rules[0]['expires_at'] - datetime.utcnow()).seconds < file_lifetime
        else:
            assert rules[0]['expires_at'] is None

    # Create replicas on rse1 using addfile in user scope (30 days lifetime)
    lfns = [{'lfn': did_name_generator('file', name_prefix='user'), 'rse': rse1, 'bytes': 1, 'adler32': '0cc737eb', 'guid': generate_uuid()} for _ in range(nbfiles)]
    files = [{'scope': extract_scope(lfn['lfn'], [])[0], 'name': lfn['lfn']} for lfn in lfns]
    reps = [{'scope': extract_scope(lfn['lfn'], [])[0], 'name': lfn['lfn'], 'rse': rse1} for lfn in lfns]
    dirac_client.add_files(lfns=lfns, ignore_availability=False)

    # Check that the default rules are created
    for lfn in lfns:
        # Check dataset rule
        directory = "/".join(lfn['lfn'].split('/')[:-1])
        scope, name = extract_scope(directory, [])
        rules = [rule for rule in did_client.list_did_rules(scope, name)]
        assert len(rules) == 1
        assert rules[0]['rse_expression'] == 'ANY=true'
        assert (rules[0]['expires_at'] - datetime.utcnow()).days == 30


@skip_non_belleii
def test_dirac_addfile_with_parents_meta(rse_factory, did_factory, root_account, did_client, dirac_client, rse_client, replica_client):
    """ DIRAC (CLIENT): Test the functionality of the addfile method """
    rse1, rse1_id = rse_factory.make_srm_rse(deterministic=True)
    rse_client.add_rse_attribute(rse=rse1, key='ANY', value='True')
    config_set('dirac', 'lifetime', '{"user.*": 2592400}')
    lfn_name = did_name_generator('file')
    lfn_meta = {'events': 10, 'key1': 'value1'}
    # Create replicas on rse1 using addfile in mock scope (not lifetime)
    lfns = [{'lfn': lfn_name, 'rse': rse1, 'bytes': 1, 'adler32': '0cc737eb', 'guid': generate_uuid(), 'meta': lfn_meta}]
    files = [{'scope': extract_scope(lfn['lfn'], [])[0], 'name': lfn['lfn']} for lfn in lfns]
    reps = [{'scope': extract_scope(lfn['lfn'], [])[0], 'name': lfn['lfn'], 'rse': rse1} for lfn in lfns]
    dataset = "/".join(lfns[0]['lfn'].split('/')[:-1])
    container = "/".join(lfns[0]['lfn'].split('/')[:-2])
    dataset_meta = {'project': 'data13_hip', 'run_number': 300000, 'mykey': 'myvalue'}
    container_meta = {'containerkey': 'containervalue'}
    parents_metadata = {dataset: dataset_meta, container: container_meta}
    dirac_client.add_files(lfns=lfns, ignore_availability=False, parents_metadata=parents_metadata)
    replicas = [rep for rep in replica_client.list_replicas(dids=files)]
    for replica in replicas:
        assert {'scope': replica['scope'], 'name': replica['name'], 'rse': list(replica['rses'].keys())[0]} in reps

    # check if metadata if properly created for file and parents
    for lfn in lfns:
        scope, name = extract_scope(lfn['lfn'], [])
        metadata = did_client.get_metadata(scope, name, plugin='ALL')
        assert all(item in metadata.items() for item in lfn_meta.items())
        dsn_scope, dsn_name = extract_scope(dataset, [])
        metadata = did_client.get_metadata(dsn_scope, dsn_name, plugin='ALL')
        assert all(item in metadata.items() for item in dataset_meta.items())
        con_scope, con_name = extract_scope(container, [])
        metadata = did_client.get_metadata(con_scope, con_name, plugin='ALL')
        assert all(item in metadata.items() for item in container_meta.items())


@skip_non_belleii
def test_belle2_schema(rse_factory, did_factory, root_account, did_client):
    """ BELLE2 SCHEMA (COMMON): Basic tests on Belle II schema """
    bad_paths = ['invalid_name', '/belle/invalid@/did']
    for path in bad_paths:
        scope, name = extract_scope(path, [])
        with pytest.raises(InvalidObject):
            validate_schema('did', {'name': name, 'scope': scope, 'type': 'CONTAINER'})


@skip_non_belleii
def test_download_datasets(download_client, rse_factory, did_factory, tmp_path, monkeypatch):
    """CLIENT(USER): Rucio download datasets"""
    rse, _ = rse_factory.make_posix_rse()

    # dummy fix to make dids come out correctly
    monkeypatch.setattr(did_factory, "name_prefix", "mock")

    datasets = [
        did_factory.upload_test_dataset(rse, nb_files=2),
        did_factory.upload_test_dataset(rse, nb_files=2),
    ]
    dids = []
    for dataset in datasets:
        name = dataset[0]["dataset_name"]
        dids.append({"did": name, "base_dir": tmp_path})

    download_client.download_dids(dids)

    for dataset in datasets:
        for f in dataset:
            file_name = Path(f["did_name"]).name
            # remove leading / to make joining work
            subdir = f['dataset_name'][1:]
            assert (tmp_path / subdir / file_name).is_file()
