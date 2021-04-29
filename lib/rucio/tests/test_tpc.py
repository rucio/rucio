import datetime
import pytest
import hashlib
import re

from rucio.core.rule import add_rule
from rucio.core.transfer import get_transfer_requests_and_source_replicas
from rucio.common.utils import generate_uuid
from rucio.daemons.judge.evaluator import re_evaluator
from rucio.daemons.conveyor import submitter, poller, finisher
from rucio.client.rseclient import RSEClient
from rucio.client.ruleclient import RuleClient
from rucio.common.utils import run_cmd_process


@pytest.fixture
def file_factory(vo, test_scope):
    from rucio.tests.temp_factories import TemporaryFileFactory

    with TemporaryFileFactory(vo=vo, default_scope=test_scope) as factory:
        yield factory


@pytest.fixture
def rse_client():
    return RSEClient()


@pytest.fixture
def rule_client():
    return RuleClient()


@pytest.fixture
def rse1(rse_factory):
    xrd1, xrd1_id = rse_factory.fetch_containerized_rse('XRD1')
    if xrd1 is not None:
        return {
            'rse_name': xrd1,
            'rse_id': xrd1_id,
        }
    rse, _ = rse_factory.make_posix_rse()
    return rse


@pytest.fixture
def rse2(rse_factory):
    xrd2, xrd2_id = rse_factory.fetch_containerized_rse('XRD2')
    if xrd2 is not None:
        return {
            'rse_name': xrd2,
            'rse_id': xrd2_id
        }
    rse, _ = rse_factory.make_posix_rse()
    return rse


def check_url(pfn, hostname, path):
    assert hostname in pfn
    assert path in pfn


def list_fts_transfer(timeout=30):
    time_start = datetime.datetime.now().second
    running_time = 0
    request_id = None
    request_status = None
    while running_time < timeout:
        rcode, out = run_cmd_process("/usr/bin/python2 /usr/bin/fts-rest-transfer-list -v -s https://fts:8446", timeout=10)
        if "Request ID" in out:
            request_id = re.search("Request ID: (.*)", out).group(1)
            request_status = re.search("Status: (.*)", out).group(1)
            break
        time_now = datetime.datetime.now().second
        running_time = int(time_now - time_start)
    return request_id, request_status


def poll_fts_transfer_status(request_id, timeout=30):
    rcode, out = run_cmd_process(f"/usr/bin/python2 /usr/bin/fts-rest-transfer-status -v -s https://fts:8446 {request_id}", timeout=timeout)
    transfer_status = None
    if rcode == 0:
        transfer_status = re.search("Status: (.*)", out).group(1)
    return transfer_status


def test_tpc(rse1, rse2, root_account, test_scope, file_factory, rse_client, rule_client, artifact):
    base_file_name = generate_uuid()
    test_file = file_factory.upload_test_file(rse1['rse_name'], name=base_file_name + '.000', return_full_item=True)
    test_file_did_str = '%s:%s' % (test_file['did_scope'], test_file['did_name'])
    test_file_did = {
        'scope': test_scope,
        'name': test_file['did_name']
    }
    test_file_name_hash = hashlib.md5(test_file_did_str.encode('utf-8')).hexdigest()
    test_file_expected_pfn = '%s/%s/%s/%s' % (test_file_did['scope'], test_file_name_hash[0:2], test_file_name_hash[2:4], test_file_did['name'])

    rse1_hostname = rse_client.get_protocols(rse1['rse_name'])[0]['hostname']
    rse2_hostname = rse_client.get_protocols(rse2['rse_name'])[0]['hostname']

    rule_id = add_rule(dids=[test_file_did], account=root_account, copies=1, rse_expression=rse2['rse_name'],
                       grouping='NONE', weight=None, lifetime=None, locked=False, subscription_id=None)
    rule = rule_client.get_replication_rule(rule_id[0])

    re_evaluator(once=True)

    assert rule['locks_ok_cnt'] == 0
    assert rule['locks_replicating_cnt'] == 1

    transfer_requestss = get_transfer_requests_and_source_replicas(rses=[rse1['rse_id'], rse2['rse_id']])
    for transfer_requests in transfer_requestss:
        for transfer_request in transfer_requests:
            if transfer_requests[transfer_request]['rule_id'] == rule_id[0]:
                src_url = transfer_requests[transfer_request]['sources'][0][1]
                dest_url = transfer_requests[transfer_request]['dest_urls'][0]
                check_url(src_url, rse1_hostname, test_file_expected_pfn)
                check_url(dest_url, rse2_hostname, test_file_expected_pfn)

    # Run Submitter
    submitter.run(once=True)

    # Get FTS transfer job info
    fts_transfer_id, fts_transfer_status = list_fts_transfer(timeout=30)

    # Check FTS transfer job
    assert fts_transfer_id is not None and fts_transfer_status is not None
    assert fts_transfer_status in ['SUBMITTED', 'ACTIVE']

    fts_transfer_status = poll_fts_transfer_status(fts_transfer_id)
    assert fts_transfer_status == 'FINISHED'

    poller.run(once=True, older_than=0)
    finisher.run(once=True)
    rule = rule_client.get_replication_rule(rule_id[0])
    assert rule['locks_ok_cnt'] == 1
    assert rule['locks_replicating_cnt'] == 0

    if artifact is not None:
        with open(artifact, 'w') as artifact_file:
            artifact_file.write(fts_transfer_id)
