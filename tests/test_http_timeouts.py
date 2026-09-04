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
import math
from unittest.mock import Mock, patch

import pytest
import requests

from rucio.common.utils import send_trace
from rucio.core import oidc
from rucio.transfertool.fts3 import FTS3Transfertool


@pytest.fixture
def fts(file_config_mock):
    for section in ('conveyor', 'transfers', 'packet-marking'):
        if not file_config_mock.has_section(section):
            file_config_mock.add_section(section)
    file_config_mock.set('conveyor', 'use_deterministic_id', 'false')
    file_config_mock.set('transfers', 'fts3tape_metadata_plugins', '')
    file_config_mock.set('packet-marking', 'enabled', 'false')
    return FTS3Transfertool(external_host='http://fts.example')


@pytest.mark.parametrize('method, args', [
    ('submit', ([], {})),
    ('cancel', (['job-id'],)),
    ('update_priority', ('job-id', 3)),
    ('query', (['job-id'],)),
    ('bulk_query', ({'job-id': {}},)),
])
@pytest.mark.parametrize('timeout_kwargs', [{}, {'timeout': None}, {'timeout': 12.5}])
def test_fts_timeout_defaults_and_overrides(fts, method, args, timeout_kwargs):
    """Conveyor's explicit None must not disable the HTTP timeout."""
    response = Mock(status_code=200)
    response.json.return_value = [] if method == 'bulk_query' else {'job_id': 'job-id'}
    with patch('requests.sessions.Session.request', return_value=response) as request:
        getattr(fts, method)(*args, **timeout_kwargs)

    request.assert_called_once()
    sent_timeout = request.call_args.kwargs['timeout']
    if timeout_kwargs.get('timeout') is None:
        connect_timeout, read_timeout = sent_timeout
        assert math.isfinite(connect_timeout) and connect_timeout > 0
        assert math.isfinite(read_timeout) and read_timeout > 0
    else:
        assert sent_timeout == timeout_kwargs['timeout']


@pytest.mark.parametrize('method', ['get_se_config', 'set_se_config'])
@pytest.mark.parametrize('error', [requests.ConnectTimeout, requests.ReadTimeout])
def test_fts_configuration_timeout_reports_failure(fts, method, error):
    """A timed-out request must not mask the failure with UnboundLocalError."""
    with patch('requests.sessions.Session.request', side_effect=error):
        with pytest.raises(Exception, match='Could not .* the configuration'):
            getattr(fts, method)('storage.example')


@pytest.mark.parametrize('ban', [True, False])
@pytest.mark.parametrize('job_timeout', [None, 3600])
def test_fts_ban_job_timeout_is_separate_from_http_timeout(fts, ban, job_timeout):
    response = Mock(status_code=200 if ban else 204)
    with patch('requests.sessions.Session.request', return_value=response) as request:
        assert fts.set_se_status('storage.example', 'maintenance', ban=ban, timeout=job_timeout) == 0

    request.assert_called_once()
    assert request.call_args.kwargs['timeout'] == (5, 30)
    payload = json.loads(request.call_args.kwargs['data'])
    if job_timeout is None:
        assert payload['status'] == 'CANCEL'
        assert 'timeout' not in payload
    else:
        assert payload['status'] == 'WAIT'
        assert payload['timeout'] == job_timeout


@pytest.fixture
def oidc_provider(monkeypatch, tmp_path):
    secrets = tmp_path / 'idpsecrets.json'
    secrets.write_text(json.dumps({'test': {
        'client_id': 'client-id',
        'client_secret': 'client-secret',
        'issuer': 'https://issuer.example/',
    }}))
    monkeypatch.setattr(oidc, 'IDPSECRETS', str(secrets))
    monkeypatch.setattr(oidc, 'ADMIN_ISSUER_ID', 'test')
    monkeypatch.setattr(oidc, 'OIDC_CONFIGURATION_RUN', False)
    monkeypatch.setattr(oidc, 'OIDC_CLIENT_ID', None)
    monkeypatch.setattr(oidc, 'OIDC_CLIENT_SECRET', None)
    monkeypatch.setattr(oidc, 'OIDC_PROVIDER_ENDPOINT', None)


@pytest.mark.parametrize('error', [requests.ConnectTimeout, requests.ReadTimeout, requests.ConnectionError])
def test_oidc_discovery_failure_returns_no_token(oidc_provider, error):
    with patch('rucio.core.oidc.requests.get', side_effect=error) as discovery:
        with patch('rucio.core.oidc.requests.post') as token_request:
            assert oidc.request_token('fts.example', 'fts', use_cache=False) is None

    discovery.assert_called_once()
    assert discovery.call_args.kwargs['timeout'] == (5, 10)
    token_request.assert_not_called()


@pytest.mark.parametrize('error', [requests.ConnectTimeout, requests.ReadTimeout])
def test_oidc_token_timeout_returns_no_token(oidc_provider, error):
    discovery = Mock()
    discovery.json.return_value = {'token_endpoint': 'https://issuer.example/token'}
    with patch('rucio.core.oidc.requests.get', return_value=discovery):
        with patch('rucio.core.oidc.requests.post', side_effect=error) as token_request:
            assert oidc.request_token('fts.example', 'fts', use_cache=False) is None

    token_request.assert_called_once()
    assert token_request.call_args.kwargs['timeout'] == (5, 10)


@pytest.mark.parametrize('recover', [False, True])
def test_trace_timeout_preserves_best_effort_retries(recover):
    side_effect = [requests.ReadTimeout(), Mock()] if recover else requests.ReadTimeout
    with patch('rucio.common.utils.requests.post', side_effect=side_effect) as post:
        assert send_trace({}, 'https://trace.example', 'rucio') == (0 if recover else 1)

    assert post.call_count == (2 if recover else 5)
    assert all(call.kwargs['timeout'] == (5, 5) for call in post.call_args_list)
