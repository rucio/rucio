# -*- coding: utf-8 -*-
# Copyright CERN since 2021
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


from rucio.common.utils import generate_uuid, extract_scope
from rucio.core import distance as distance_core
from rucio.core import rse as rse_core


def test_dirac_addfile(rse_factory, did_factory, root_account, did_client, dirac_client, rse_client, replica_client, vo):

    src_rses = [rse_factory.make_posix_rse() for _ in range(2)]
    dst_rses = [rse_factory.make_posix_rse() for _ in range(3)]
    for _, src_rse_id in src_rses:
        for _, dst_rse_id in dst_rses:
            distance_core.add_distance(src_rse_id=src_rse_id, dest_rse_id=dst_rse_id, ranking=10)
            distance_core.add_distance(src_rse_id=dst_rse_id, dest_rse_id=src_rse_id, ranking=10)
    print([rse for rse in rse_core.list_rses()])
    print([did for did in did_client.list_content('other', '/belle')])
    nbfiles = 5
    # Adding replicas to deterministic RSE
    rse1, rse1_id = rse_factory.make_srm_rse(deterministic=True)
    rse_client.add_rse_attribute(rse=rse1, key='ANY', value='True')

    # Create replicas on rse1
    lfns = [{'lfn': '/belle/MC/test_dir/file_%s' % generate_uuid(), 'rse': rse1, 'bytes': 1, 'adler32': '0cc737eb', 'guid': generate_uuid()} for _ in range(nbfiles)]
    files = [{'scope': extract_scope(lfn['lfn'], [])[0], 'name': lfn['lfn']} for lfn in lfns]
    reps = [{'scope': extract_scope(lfn['lfn'], [])[0], 'name': lfn['lfn'], 'rse': rse1} for lfn in lfns]
    dirac_client.add_files(lfns=lfns, ignore_availability=False)
    replicas = [rep for rep in replica_client.list_replicas(dids=files)]
    for replica in replicas:
        assert {'scope': replica['scope'], 'name': replica['name'], 'rse': list(replica['rses'].keys())[0]} in reps
