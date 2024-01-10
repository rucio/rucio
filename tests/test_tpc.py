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

import time
import datetime
import pytest
import hashlib
import re

from rucio.core.request import get_request_by_did, list_and_mark_transfer_requests_and_source_replicas
from rucio.core.topology import Topology
from rucio.core.transfer import ProtocolFactory
from rucio.core.rule import add_rule
from rucio.common.utils import generate_uuid
from rucio.daemons.judge.evaluator import re_evaluator
from rucio.daemons.conveyor import submitter, poller, finisher
from rucio.daemons.conveyor.common import build_transfer_paths
from rucio.client.rseclient import RSEClient
from rucio.client.ruleclient import RuleClient
from rucio.common.utils import run_cmd_process

MAX_POLL_WAIT_SECONDS = 60


@pytest.fixture
def rse_client():
    return RSEClient()


@pytest.fixture
def rule_client():
    return RuleClient()


def check_url(pfn, hostname, path):
    assert hostname in pfn
    assert path in pfn


def poll_fts_transfer_status(request_id, timeout=30):
    rcode, out = run_cmd_process(f"fts-rest-transfer-status -v -s https://fts:8446 {request_id}", timeout=timeout)
    transfer_status = None
    if rcode == 0:
        transfer_status = re.search("Status: (.*)", out).group(1)
    return transfer_status


@pytest.mark.noparallel(reason="multiple submitters cannot be run in parallel due to partial job assignment by hash")
@pytest.mark.dirty(reason="Creates artifact /tmp/test_tpc.artifact in dev_rucio_1 container")
def test_tpc(containerized_rses, root_account, test_scope, did_factory, rse_client, rule_client, artifact):
    if len(containerized_rses) < 2:
        pytest.skip("TPC tests need at least 2 containerized rse's for execution}")
    rse1_name, rse1_id = containerized_rses[0]
    rse2_name, rse2_id = containerized_rses[1]

    base_file_name = generate_uuid()
    test_file = did_factory.upload_test_file(rse1_name, scope=test_scope, name=base_file_name + '.000')
    test_file_did_str = '%s:%s' % (test_file['scope'], test_file['name'])
    test_file_name_hash = hashlib.md5(test_file_did_str.encode('utf-8')).hexdigest()
    test_file_expected_pfn = '%s/%s/%s/%s' % (test_file['scope'], test_file_name_hash[0:2], test_file_name_hash[2:4], test_file['name'])

    rse1_hostname = rse_client.get_protocols(rse1_name)[0]['hostname']
    rse2_hostname = rse_client.get_protocols(rse2_name)[0]['hostname']

    rule_id = add_rule(dids=[test_file], account=root_account, copies=1, rse_expression=rse2_name,
                       grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)
    rule = rule_client.get_replication_rule(rule_id[0])

    re_evaluator(once=True, did_limit=None)

    assert rule['locks_ok_cnt'] == 0
    assert rule['locks_replicating_cnt'] == 1

    topology = Topology()
    requests = list_and_mark_transfer_requests_and_source_replicas(rse_collection=topology, rses=[rse1_id, rse2_id]).values()
    paths, *_ = build_transfer_paths(topology=topology, protocol_factory=ProtocolFactory(), requests_with_sources=requests)
    [[_, [transfer_path]]] = paths.items()
    assert transfer_path[0].rws.rule_id == rule_id[0]
    src_url = transfer_path[0].source_url(transfer_path[0].sources[0])
    dest_url = transfer_path[0].dest_url
    check_url(src_url, rse1_hostname, test_file_expected_pfn)
    check_url(dest_url, rse2_hostname, test_file_expected_pfn)

    # Run Submitter
    submitter.submitter(once=True)

    # Get FTS transfer job id
    request = get_request_by_did(rse_id=rse2_id, **test_file)
    fts_transfer_id = request['external_id']

    # Check FTS transfer job
    assert fts_transfer_id is not None

    # Wait for the FTS transfer to finish
    fts_transfer_status = None
    for _ in range(MAX_POLL_WAIT_SECONDS):
        fts_transfer_status = poll_fts_transfer_status(fts_transfer_id)
        if fts_transfer_status not in ['SUBMITTED', 'ACTIVE']:
            break
        time.sleep(1)
    assert fts_transfer_status == 'FINISHED'

    poller.run(once=True, older_than=0)
    finisher.run(once=True)
    rule = rule_client.get_replication_rule(rule_id[0])
    assert rule['locks_ok_cnt'] == 1
    assert rule['locks_replicating_cnt'] == 0

    if artifact is not None:
        date = datetime.date.today().strftime("%Y-%m-%d")
        with open(artifact, 'w') as artifact_file:
            artifact_file.write(
                f"/var/log/fts3/{date}/{rse1_name.lower()}__{rse2_name.lower()}/*__{fts_transfer_id}"
            )
