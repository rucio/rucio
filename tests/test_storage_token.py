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

import base64
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from dogpile.cache.api import NoValue
from jwkest.jwt import JWT

from rucio.common.exception import InvalidRequest
from rucio.core.token import (
    StorageTokenContext,
    StorageTokenOperation,
    TokenAudience,
    TokenCache,
    TokenManaged,
    TokenRequest,
    TokenScope,
    get_token_for_operation,
    token_is_managed,
)
from rucio.core.token.request import _token_cache_get, _token_cache_set
from rucio.transfertool.fts3 import _unmanaged_tokens_param


def _unsigned_jwt(audience: str, scope: str) -> str:
    header = base64.urlsafe_b64encode(json.dumps({'alg': 'none'}).encode()).rstrip(b'=')
    payload = base64.urlsafe_b64encode(json.dumps({'aud': audience, 'scope': scope}).encode()).rstrip(b'=')
    return f'{header.decode()}.{payload.decode()}.'


def _decode_unsigned_jwt(token: str) -> dict:
    payload = token.split('.')[1]
    padding = '=' * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload + padding))


def _jwt_with_claims(**claims) -> str:
    return JWT().pack([claims])


def _future_exp(hours: int = 1) -> int:
    return int((datetime.now(tz=timezone.utc) + timedelta(hours=hours)).timestamp())


class TestTokenAudienceDefault:

    def test_fts_auth_uses_hostname_from_extras(self):
        ctx = StorageTokenContext(
            operation=StorageTokenOperation.FTS_AUTH,
            extras={'fts_hostname': 'fts.example.org'},
        )
        assert TokenAudience.default(ctx) == 'fts.example.org'

    def test_fts_auth_requires_hostname(self):
        ctx = StorageTokenContext(operation=StorageTokenOperation.FTS_AUTH)
        with pytest.raises(InvalidRequest):
            TokenAudience.default(ctx)

    @pytest.mark.parametrize('operation', [
        StorageTokenOperation.TPC_SOURCE,
        StorageTokenOperation.TPC_DESTINATION,
        StorageTokenOperation.CENTRAL_DELETE,
    ])
    @patch('rucio.core.token.audience.determine_audience_for_rse', return_value='davs.example.org')
    def test_rse_operations_use_davs_hostnames(self, mock_audience, operation):
        ctx = StorageTokenContext(operation=operation, rse_id='rse-1')
        assert TokenAudience.default(ctx) == 'davs.example.org'
        mock_audience.assert_called_once_with('rse-1')

    def test_rse_operation_requires_rse_id(self):
        ctx = StorageTokenContext(operation=StorageTokenOperation.TPC_SOURCE)
        with pytest.raises(InvalidRequest):
            TokenAudience.default(ctx)

    def test_reserved_client_operation_is_unsupported(self):
        ctx = StorageTokenContext(operation=StorageTokenOperation.CLIENT_DOWNLOAD, rse_id='rse-1')
        with pytest.raises(InvalidRequest):
            TokenAudience.default(ctx)


class TestTokenScopeDefault:

    def test_fts_auth_scope(self):
        ctx = StorageTokenContext(operation=StorageTokenOperation.FTS_AUTH)
        assert TokenScope.default(ctx) == 'fts'

    @patch('rucio.core.token.scope.determine_scope_for_rse')
    def test_tpc_source_adds_offline_access(self, mock_scope):
        mock_scope.return_value = 'offline_access storage.read:/data'
        ctx = StorageTokenContext(operation=StorageTokenOperation.TPC_SOURCE, rse_id='rse-1')
        assert TokenScope.default(ctx) == 'offline_access storage.read:/data'
        mock_scope.assert_called_once_with(
            rse_id='rse-1',
            scopes=['storage.read'],
            oauth_scopes=['offline_access'],
        )

    @patch('rucio.core.token.scope.determine_scope_for_rse')
    def test_tpc_destination_adds_offline_access(self, mock_scope):
        mock_scope.return_value = 'offline_access storage.modify:/data storage.read:/data'
        ctx = StorageTokenContext(operation=StorageTokenOperation.TPC_DESTINATION, rse_id='rse-1')
        TokenScope.default(ctx)
        mock_scope.assert_called_once_with(
            rse_id='rse-1',
            scopes=['storage.modify', 'storage.read'],
            oauth_scopes=['offline_access'],
        )

    @patch('rucio.core.token.scope.determine_scope_for_rse')
    def test_central_delete_has_no_offline_access(self, mock_scope):
        mock_scope.return_value = 'storage.modify:/data storage.read:/data'
        ctx = StorageTokenContext(operation=StorageTokenOperation.CENTRAL_DELETE, rse_id='rse-1')
        TokenScope.default(ctx)
        mock_scope.assert_called_once_with(
            rse_id='rse-1',
            scopes=['storage.modify', 'storage.read'],
            oauth_scopes=[],
        )

    def test_reserved_tape_operation_is_unsupported(self):
        ctx = StorageTokenContext(operation=StorageTokenOperation.TPC_STAGE, rse_id='rse-1')
        with pytest.raises(InvalidRequest):
            TokenScope.default(ctx)


class TestTokenRequestDefault:

    def _oidc_ready(self):
        return patch.multiple(
            'rucio.core.token.request.oidc_core',
            OIDC_CLIENT_ID='client-id',
            OIDC_CLIENT_SECRET='client-secret',
            OIDC_PROVIDER_ENDPOINT='https://iam.example.org/token',
            OIDC_CONFIGURATION_RUN=True,
        )

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_posts_client_credentials_and_returns_access_token(self, mock_post, mock_region):
        mock_region.get.return_value = NoValue()
        mock_post.return_value = MagicMock()
        mock_post.return_value.raise_for_status.return_value = None
        mock_post.return_value.json.return_value = {'access_token': 'tok-1'}
        ctx = StorageTokenContext(operation=StorageTokenOperation.FTS_AUTH)
        with self._oidc_ready():
            token = TokenRequest.default('fts.example.org', 'fts', ctx)
        assert token == 'tok-1'
        _args, kwargs = mock_post.call_args
        assert kwargs['url'] == 'https://iam.example.org/token'
        assert kwargs['auth'] == ('client-id', 'client-secret')
        assert kwargs['data'] == {
            'grant_type': 'client_credentials',
            'audience': 'fts.example.org',
            'scope': 'fts',
        }

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_extras_expiry_time_reaches_form_but_fts_hostname_does_not(self, mock_post, mock_region):
        mock_region.get.return_value = NoValue()
        mock_post.return_value = MagicMock()
        mock_post.return_value.raise_for_status.return_value = None
        mock_post.return_value.json.return_value = {'access_token': 'tok-2'}
        ctx = StorageTokenContext(
            operation=StorageTokenOperation.FTS_AUTH,
            extras={'fts_hostname': 'fts.example.org', 'expiry_time': 3600, 'resource': 'https://se.example.org'},
        )
        with self._oidc_ready():
            TokenRequest.default('fts.example.org', 'fts', ctx)
        form = mock_post.call_args.kwargs['data']
        assert form['expires_in'] == 3600
        assert form['resource'] == 'https://se.example.org'
        assert 'fts_hostname' not in form
        assert 'expiry_time' not in form

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_expiry_time_extra_maps_to_expires_in(self, mock_post, mock_region):
        mock_region.get.return_value = NoValue()
        mock_post.return_value = MagicMock()
        mock_post.return_value.raise_for_status.return_value = None
        mock_post.return_value.json.return_value = {'access_token': 'tok-3'}
        ctx = StorageTokenContext(
            operation=StorageTokenOperation.TPC_SOURCE,
            extras={'expiry_time': 1800},
        )
        with self._oidc_ready():
            TokenRequest.default('davs.example.org', 'storage.read:/data', ctx)
        assert mock_post.call_args.kwargs['data']['expires_in'] == 1800


class TestGetTokenForOperation:

    def test_interface_mints_token_with_requested_claims(self):
        audience = 'davs.example.org'
        scope = 'offline_access storage.read:/prefix'
        minted = _unsigned_jwt(audience, scope)

        def fake_request(got_audience, got_scope, ctx):
            assert got_audience == audience
            assert got_scope == scope
            return minted

        ctx = StorageTokenContext(
            operation=StorageTokenOperation.TPC_SOURCE,
            rse_id='rse-1',
            did=('mock', 'file.root'),
        )
        with patch.object(TokenAudience, 'get_configured_algorithm', return_value=TokenAudience.default), \
                patch.object(TokenScope, 'get_configured_algorithm', return_value=TokenScope.default), \
                patch.object(TokenRequest, 'get_configured_algorithm', return_value=fake_request), \
                patch('rucio.core.token.audience.determine_audience_for_rse', return_value=audience), \
                patch('rucio.core.token.scope.determine_scope_for_rse', return_value=scope):
            token = get_token_for_operation(ctx)

        assert token is not None
        assert token == minted
        claims = _decode_unsigned_jwt(token)
        assert claims['aud'] == audience
        assert claims['scope'] == scope


class TestTokenCacheDefault:

    @pytest.mark.parametrize('operation', [
        StorageTokenOperation.FTS_AUTH,
        StorageTokenOperation.TPC_SOURCE,
        StorageTokenOperation.TPC_DESTINATION,
        StorageTokenOperation.TPC_STAGE,
        StorageTokenOperation.TPC_POLL,
        StorageTokenOperation.CENTRAL_DELETE,
    ])
    def test_central_operations_are_cacheable(self, operation):
        ctx = StorageTokenContext(operation=operation, rse_id='rse-1')
        assert TokenCache.default(ctx) is True

    @pytest.mark.parametrize('operation', [
        StorageTokenOperation.CLIENT_DELETE,
        StorageTokenOperation.CLIENT_DOWNLOAD,
        StorageTokenOperation.CLIENT_UPLOAD,
    ])
    def test_client_operations_are_not_cacheable(self, operation):
        ctx = StorageTokenContext(operation=operation, rse_id='rse-1')
        assert TokenCache.default(ctx) is False


class TestTokenRequestCache:

    def _oidc_ready(self):
        return patch.multiple(
            'rucio.core.token.request.oidc_core',
            OIDC_CLIENT_ID='client-id',
            OIDC_CLIENT_SECRET='client-secret',
            OIDC_PROVIDER_ENDPOINT='https://iam.example.org/token',
            OIDC_CONFIGURATION_RUN=True,
        )

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_cache_hit_skips_idp(self, mock_post, mock_region):
        cached = _jwt_with_claims(exp=_future_exp())
        mock_region.get.return_value = cached
        ctx = StorageTokenContext(operation=StorageTokenOperation.FTS_AUTH)
        with self._oidc_ready():
            token = TokenRequest.default('fts.example.org', 'fts', ctx)
        assert token == cached
        mock_post.assert_not_called()

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_cache_miss_stores_token(self, mock_post, mock_region):
        mock_region.get.return_value = NoValue()
        mock_post.return_value = MagicMock()
        mock_post.return_value.raise_for_status.return_value = None
        mock_post.return_value.json.return_value = {'access_token': 'tok-fresh'}
        ctx = StorageTokenContext(operation=StorageTokenOperation.FTS_AUTH)
        with self._oidc_ready():
            assert TokenRequest.default('fts.example.org', 'fts', ctx) == 'tok-fresh'
        key = hashlib.md5(b'audience=fts.example.org;scope=fts').hexdigest()
        mock_region.set.assert_called_once_with(key, 'tok-fresh')

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_token_cache_false_skips_get_and_set(self, mock_post, mock_region):
        mock_post.return_value = MagicMock()
        mock_post.return_value.raise_for_status.return_value = None
        mock_post.return_value.json.return_value = {'access_token': 'tok-file'}
        ctx = StorageTokenContext(operation=StorageTokenOperation.CLIENT_DOWNLOAD, rse_id='rse-1')
        with self._oidc_ready():
            TokenRequest.default('davs.example.org', 'storage.read:/file', ctx)
            TokenRequest.default('davs.example.org', 'storage.read:/file', ctx)
        assert mock_post.call_count == 2
        mock_region.get.assert_not_called()
        mock_region.set.assert_not_called()

    @patch.object(TokenCache, 'get_configured_algorithm', return_value=lambda ctx: False)
    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_policy_can_disable_cache_for_cacheable_operation(self, mock_post, mock_region, _mock_cache):
        mock_post.return_value = MagicMock()
        mock_post.return_value.raise_for_status.return_value = None
        mock_post.return_value.json.return_value = {'access_token': 'tok-policy'}
        ctx = StorageTokenContext(operation=StorageTokenOperation.FTS_AUTH)
        with self._oidc_ready():
            TokenRequest.default('fts.example.org', 'fts', ctx)
        mock_region.get.assert_not_called()
        mock_region.set.assert_not_called()

    @patch('rucio.core.token.request.REGION')
    def test_cache_get_rejects_expired_and_invalid(self, mock_region):
        mock_region.get.return_value = NoValue()
        assert _token_cache_get('k') is None

        valid = _jwt_with_claims(exp=_future_exp())
        mock_region.get.return_value = valid
        assert _token_cache_get('k') == valid

        mock_region.get.return_value = 'not-a-jwt'
        assert _token_cache_get('k') is None

        nearly_expired = _jwt_with_claims(exp=int((datetime.now(tz=timezone.utc) + timedelta(minutes=1)).timestamp()))
        mock_region.get.return_value = nearly_expired
        assert _token_cache_get('k') is None

        expired = _jwt_with_claims(exp=int((datetime.now(tz=timezone.utc) - timedelta(minutes=1)).timestamp()))
        mock_region.get.return_value = expired
        assert _token_cache_get('k') is None

    @patch('rucio.core.token.request.REGION')
    def test_cache_set_writes_region(self, mock_region):
        _token_cache_set('k', 'tok')
        mock_region.set.assert_called_once_with('k', 'tok')


class TestTokenManagedDefault:

    def test_offline_access_in_scope_string_is_managed(self):
        ctx = StorageTokenContext(operation=StorageTokenOperation.TPC_SOURCE)
        token = _unsigned_jwt('davs.example.org', 'offline_access storage.read:/data')
        assert TokenManaged.default(ctx, token) is True
        assert token_is_managed(ctx, token) is True

    def test_scope_without_offline_access_is_unmanaged(self):
        ctx = StorageTokenContext(operation=StorageTokenOperation.TPC_SOURCE)
        token = _unsigned_jwt('davs.example.org', 'storage.modify:/data storage.read:/data')
        assert TokenManaged.default(ctx, token) is False

    def test_scope_list_claim(self):
        ctx = StorageTokenContext(operation=StorageTokenOperation.TPC_SOURCE)
        token = _jwt_with_claims(scope=['offline_access', 'storage.read:/data'])
        assert TokenManaged.default(ctx, token) is True

    def test_invalid_token_is_unmanaged(self):
        ctx = StorageTokenContext(operation=StorageTokenOperation.TPC_SOURCE)
        assert TokenManaged.default(ctx, 'not-a-jwt') is False


class TestUnmanagedTokensParam:

    def test_all_managed(self):
        tokens = [
            _unsigned_jwt('src.example.org', 'offline_access storage.read:/data'),
            _unsigned_jwt('dst.example.org', 'offline_access storage.modify:/data'),
        ]
        assert _unmanaged_tokens_param(tokens, vo=None) is False

    def test_all_unmanaged(self):
        tokens = [
            _unsigned_jwt('src.example.org', 'storage.read:/data'),
            _unsigned_jwt('dst.example.org', 'storage.modify:/data'),
        ]
        assert _unmanaged_tokens_param(tokens, vo=None) is True

    def test_mixed_prefers_managed(self):
        tokens = [
            _unsigned_jwt('src.example.org', 'offline_access storage.read:/data'),
            _unsigned_jwt('dst.example.org', 'storage.modify:/data'),
        ]
        logged = []

        def logger(level, msg, *args):
            logged.append((level, msg % args if args else msg))

        assert _unmanaged_tokens_param(tokens, vo=None, logger=logger) is False
        assert logged == [(logging.WARNING, 'Mixed managed and unmanaged storage tokens in one FTS job; submitting as managed')]

    def test_empty_is_managed(self):
        assert _unmanaged_tokens_param([], vo=None) is False
