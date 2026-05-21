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

import json
from argparse import Namespace
from types import SimpleNamespace
from unittest.mock import patch

from click.testing import CliRunner

from rucio.cli.bin_legacy.rucio import add_rule, get_parser
from rucio.cli.rule import rule
from rucio.client.ruleclient import RuleClient
from rucio.common.constants import HTTPMethod


class _CreatedResponse:
    status_code = 201
    text = '["rule-id"]'
    headers = {}
    content = b''


class _RecordingRuleClient:
    account = 'root'

    def __init__(self):
        self.calls = []

    def add_replication_rule(self, **kwargs):
        self.calls.append(kwargs)
        return ['rule-id']


def test_rule_client_add_replication_rule_sends_split_container():
    captured = {}
    client = RuleClient.__new__(RuleClient)
    client.list_hosts = ['http://rucio.example']

    def send_request(url, method, data):
        captured['url'] = url
        captured['method'] = method
        captured['data'] = data
        return _CreatedResponse()

    client._send_request = send_request

    result = client.add_replication_rule(
        dids=[{'scope': 'mock', 'name': 'dataset'}],
        copies=1,
        rse_expression='MOCK',
        split_container=True,
    )

    assert result == ['rule-id']
    assert captured['method'] == HTTPMethod.POST
    assert json.loads(captured['data'])['split_container'] is True


def test_rule_add_cli_passes_split_container_to_client():
    client = _RecordingRuleClient()
    with patch('rucio.cli.rule.get_scope', return_value=('mock', 'dataset')):
        result = CliRunner().invoke(
            rule,
            ['add', 'mock:dataset', '--copies', '1', '--rses', 'MOCK', '--split-container'],
            obj=SimpleNamespace(client=client),
        )

    assert result.exit_code == 0, result.output
    assert client.calls[0]['split_container'] is True


def test_legacy_add_rule_parser_accepts_split_container():
    args = get_parser().parse_args(['add-rule', 'mock:dataset', '1', 'MOCK', '--split-container'])

    assert args.split_container is True


def test_legacy_add_rule_passes_split_container_to_client():
    client = _RecordingRuleClient()
    args = Namespace(
        dids=['mock:dataset'],
        copies=1,
        rse_expression='MOCK',
        weight=None,
        lifetime=None,
        grouping=None,
        rule_account=None,
        locked=False,
        source_replica_expression=None,
        notify=None,
        activity=None,
        comment=None,
        ask_approval=False,
        asynchronous=False,
        delay_injection=None,
        split_container=True,
        ignore_duplicate=False,
    )

    with patch('rucio.cli.bin_legacy.rucio.get_scope', return_value=('mock', 'dataset')):
        assert add_rule(args, client, None, None, None) == 0
    assert client.calls[0]['split_container'] is True
