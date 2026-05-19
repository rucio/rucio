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

from json import loads
from types import SimpleNamespace

from click.testing import CliRunner

from rucio.cli import rule as rule_cli
from rucio.cli.bin_legacy import rucio as legacy_rucio
from rucio.client.ruleclient import RuleClient
from rucio.common.constants import HTTPMethod


class _CreatedResponse:
    status_code = 201
    text = '["rule-id"]'


class _RecordingRuleClient:
    def __init__(self):
        self.calls = []

    def add_replication_rule(self, **kwargs):
        self.calls.append(kwargs)
        return ["rule-id"]


def test_add_replication_rule_serializes_split_container():
    captured = {}
    client = RuleClient.__new__(RuleClient)
    client.list_hosts = ["https://rucio.example"]

    def _send_request(url, method, data):
        captured["url"] = url
        captured["method"] = method
        captured["data"] = loads(data)
        return _CreatedResponse()

    client._send_request = _send_request

    assert client.add_replication_rule(
        dids=[{"scope": "mock", "name": "container"}],
        copies=1,
        rse_expression="MOCK",
        split_container=True,
    ) == ["rule-id"]
    assert captured["url"] == "https://rucio.example/rules/"
    assert captured["method"] == HTTPMethod.POST
    assert captured["data"]["split_container"] is True


def test_rule_click_add_forwards_split_container(monkeypatch):
    client = _RecordingRuleClient()
    monkeypatch.setattr(rule_cli, "get_scope", lambda did, _client: tuple(did.split(":", 1)))

    result = CliRunner().invoke(
        rule_cli.rule,
        ["add", "mock:container", "--copies", "1", "--rses", "MOCK", "--split-container"],
        obj=SimpleNamespace(client=client),
    )

    assert result.exit_code == 0, result.output
    assert client.calls[0]["split_container"] is True


def test_legacy_add_rule_forwards_split_container(monkeypatch):
    client = _RecordingRuleClient()
    monkeypatch.setattr(legacy_rucio, "get_scope", lambda did, _client: tuple(did.split(":", 1)))
    args = SimpleNamespace(
        dids=["mock:container"],
        copies=1,
        rse_expression="MOCK",
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

    assert legacy_rucio.add_rule(args, client, None, None, None) == legacy_rucio.SUCCESS
    assert client.calls[0]["split_container"] is True
