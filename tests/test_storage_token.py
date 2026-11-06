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
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from unittest.mock import MagicMock, call, patch
from urllib.parse import urlparse

import pytest
import requests
from dogpile.cache.api import NoValue
from jwkest.jwt import JWT

from rucio.common.plugins import PolicyPackageAlgorithms
from rucio.core import oidc as oidc_core
from rucio.core import replica as replica_core
from rucio.core import rule as rule_core
from rucio.core.rse import determine_audience_for_rse, determine_scope_for_rse, get_rse_id, get_rse_info
from rucio.core.token import (
    JobTransferToken,
    StorageTokenContext,
    StorageTokenOperation,
    TokenAudience,
    TokenManaged,
    TokenRequest,
    TokenScope,
    get_token_for_operation,
    token_is_managed,
    unmanaged_tokens_for_job,
)
from rucio.core.token.cache import token_cache_key
from rucio.core.token.request import _TOKEN_EXCHANGE_GRANT, _token_cache_get
from rucio.core.token.scope import normalize_scope_path
from rucio.daemons.reaper.reaper import _central_delete_token, delete_from_storage, reaper
from rucio.rse import rsemanager as rsemgr
from rucio.rse.protocols.webdav import Default as WebDAV
from rucio.tests.common import skip_rse_tests_with_accounts
from tests.ruciopytest import NoParallelGroups

TOKEN_ENDPOINT = 'https://iam.example.org/token'
RSE_NAME = 'WEB1'
PATH_SCOPES = ('storage.read:', 'storage.modify:')
RSE_WIDE_SCOPE = {'storage.modify:/rucio', 'storage.read:/rucio'}


def unsigned_jwt(audience: str, scope: str) -> str:
    header = base64.urlsafe_b64encode(json.dumps({'alg': 'none'}).encode()).rstrip(b'=')
    payload = base64.urlsafe_b64encode(json.dumps({'aud': audience, 'scope': scope}).encode()).rstrip(b'=')
    return f'{header.decode()}.{payload.decode()}.'


def jwt_with_claims(**claims) -> str:
    return JWT().pack([claims])


def future_exp(hours: int = 1) -> int:
    return int((datetime.now(tz=timezone.utc) + timedelta(hours=hours)).timestamp())


def token_response(token: str) -> MagicMock:
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {'access_token': token}
    return response


@contextmanager
def oidc_ready(idp: str = 'iam'):
    """Provide storage-token client credentials and select ``[oidc] idp``."""
    with patch.multiple(
        'rucio.core.token.request.oidc_core',
        OIDC_CLIENT_ID='client-id',
        OIDC_CLIENT_SECRET='client-secret',
        OIDC_PROVIDER_ENDPOINT=TOKEN_ENDPOINT,
        OIDC_CONFIGURATION_RUN=True,
    ), patch('rucio.core.token.request.config_get', return_value=idp):
        yield


class TestTokenAudienceDefault:

    def test_fts_auth_uses_hostname_from_extras(self):
        """ STORAGE TOKEN (CORE): FTS audience is the FTS hostname from the context extras """
        ctx = StorageTokenContext(
            operation=StorageTokenOperation.FTS_AUTH,
            extras={'fts_hostname': 'fts.example.org'},
        )
        assert TokenAudience.default(ctx) == 'fts.example.org'

    @patch('rucio.core.token.audience.determine_audience_for_rse', return_value='davs.example.org')
    def test_tpc_uses_davs_hostnames(self, mock_audience):
        """ STORAGE TOKEN (CORE): Third-party-copy audience is the RSE's davs hostnames """
        ctx = StorageTokenContext(operation=StorageTokenOperation.TPC_SOURCE, rse_id='rse-1')
        assert TokenAudience.default(ctx) == 'davs.example.org'
        mock_audience.assert_called_once_with('rse-1')


class TestTokenScopeDefault:

    def test_fts_auth_scope(self):
        """ STORAGE TOKEN (CORE): FTS scope is fts """
        ctx = StorageTokenContext(operation=StorageTokenOperation.FTS_AUTH)
        assert TokenScope.default(ctx) == 'fts'

    @patch('rucio.core.token.scope.determine_scope_for_rse')
    def test_tpc_source_adds_offline_access(self, mock_scope):
        """ STORAGE TOKEN (CORE): Copy source asks for storage.read and offline_access """
        mock_scope.return_value = 'offline_access storage.read:/data'
        ctx = StorageTokenContext(operation=StorageTokenOperation.TPC_SOURCE, rse_id='rse-1')
        assert TokenScope.default(ctx) == 'offline_access storage.read:/data'
        mock_scope.assert_called_once_with(
            rse_id='rse-1',
            parameterized_scopes=['storage.read'],
            verbatim_scopes=['offline_access'],
        )

    @patch('rucio.core.token.scope.determine_scope_for_rse')
    def test_tpc_destination_adds_offline_access(self, mock_scope):
        """ STORAGE TOKEN (CORE): Copy destination asks for storage.modify, storage.read and offline_access """
        mock_scope.return_value = 'offline_access storage.modify:/data storage.read:/data'
        ctx = StorageTokenContext(operation=StorageTokenOperation.TPC_DESTINATION, rse_id='rse-1')
        TokenScope.default(ctx)
        mock_scope.assert_called_once_with(
            rse_id='rse-1',
            parameterized_scopes=['storage.modify', 'storage.read'],
            verbatim_scopes=['offline_access'],
        )


class TestNormalizeScopePath:

    @pytest.mark.parametrize('prefix,expected', [
        # xrootd spells /rucio as root://host//rucio, so prefixes carry the extra slash.
        ('//rucio', '/rucio'),
        # Stripping a base path with a trailing slash leaves a relative path.
        ('rucio', '/rucio'),
        ('/webdav//atlas///rucio/', '/webdav/atlas/rucio/'),
        ('', '/'),
    ])
    def test_normalization(self, prefix, expected):
        """ STORAGE TOKEN (CORE): Scope paths have one leading slash and no repeated slashes """
        assert normalize_scope_path(prefix) == expected


class TestDetermineScopeForRse:

    @staticmethod
    def davs(prefix: str, extended_attributes: Optional[dict] = None) -> dict:
        return {'scheme': 'davs', 'prefix': prefix, 'extended_attributes': extended_attributes}

    @patch('rucio.core.rse.get_rse_attribute', return_value='/webdav/atlas/')
    @patch('rucio.core.rse.get_rse_info')
    def test_rse_attribute_base_path_keeps_an_absolute_path(self, mock_protocols, mock_attribute):
        """ RSE (CORE): Stripping the RSE oidc_base_path leaves an absolute scope path """
        mock_protocols.return_value = {'protocols': [self.davs('/webdav/atlas/atlasdatadisk/rucio/')]}
        assert determine_scope_for_rse('rse-1', ['storage.read']) == 'storage.read:/atlasdatadisk/rucio/'

    @patch('rucio.core.rse.get_rse_attribute', return_value='/not-used')
    @patch('rucio.core.rse.get_rse_info')
    def test_protocol_extended_attribute_wins_over_rse_attribute(self, mock_protocols, mock_attribute):
        """ RSE (CORE): A protocol oidc_base_path takes precedence over the RSE attribute """
        mock_protocols.return_value = {'protocols': [
            self.davs('/webdav/atlas/atlasdatadisk/', extended_attributes={'oidc_base_path': '/webdav/atlas'}),
        ]}
        assert determine_scope_for_rse('rse-1', ['storage.read']) == 'storage.read:/atlasdatadisk/'
        mock_attribute.assert_not_called()


class TestTokenRequestDefault:

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_posts_client_credentials_and_returns_access_token(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): IAM grant is one client-credentials POST without context extras """
        mock_region.get.return_value = NoValue()
        mock_post.return_value = token_response('tok-1')
        ctx = StorageTokenContext(
            operation=StorageTokenOperation.FTS_AUTH,
            extras={'expiry_time': 3600, 'resource': 'https://se.example.org'},
        )
        with oidc_ready():
            assert TokenRequest.default('fts.example.org', 'fts', ctx) == 'tok-1'
        assert mock_post.call_args.kwargs['url'] == TOKEN_ENDPOINT
        assert mock_post.call_args.kwargs['auth'] == ('client-id', 'client-secret')
        assert mock_post.call_args.kwargs['data'] == {
            'grant_type': 'client_credentials',
            'audience': 'fts.example.org',
            'scope': 'fts',
        }

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_idp_failure_returns_none(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): An IdP error returns no token """
        mock_region.get.return_value = NoValue()
        mock_post.side_effect = requests.ConnectionError('no route to IdP')
        ctx = StorageTokenContext(operation=StorageTokenOperation.FTS_AUTH)
        with oidc_ready():
            assert TokenRequest.default('fts.example.org', 'fts', ctx) is None
        mock_post.assert_called_once()


class TestRfcIdentityProvider:

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_exchanges_a_client_credentials_token_for_each_audience(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): Keycloak grant is client-credentials, then one exchange with an audience per hostname """
        mock_region.get.return_value = NoValue()
        mock_post.side_effect = [token_response('subject-tok'), token_response('exchanged-tok')]
        ctx = StorageTokenContext(operation=StorageTokenOperation.CENTRAL_DELETE, rse_id='rse-1')
        scope = 'storage.modify:/rucio storage.read:/rucio'
        with oidc_ready(' RFC '):
            assert TokenRequest.default('web1 xrd4', scope, ctx) == 'exchanged-tok'

        credentials, exchange = mock_post.call_args_list
        assert credentials.kwargs['data'] == {
            'grant_type': 'client_credentials',
            'scope': scope,
        }
        assert exchange.kwargs['url'] == TOKEN_ENDPOINT
        assert exchange.kwargs['auth'] == ('client-id', 'client-secret')
        assert exchange.kwargs['data'] == [
            ('grant_type', _TOKEN_EXCHANGE_GRANT),
            ('subject_token', 'subject-tok'),
            ('subject_token_type', 'urn:ietf:params:oauth:token-type:access_token'),
            ('requested_token_type', 'urn:ietf:params:oauth:token-type:access_token'),
            ('scope', scope),
            ('audience', 'web1'),
            ('audience', 'xrd4'),
        ]

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_empty_audience_skips_exchange(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): Keycloak grant without hostnames returns the client-credentials token """
        mock_region.get.return_value = NoValue()
        mock_post.return_value = token_response('subject-tok')
        ctx = StorageTokenContext(operation=StorageTokenOperation.CENTRAL_DELETE, rse_id='rse-1')
        with oidc_ready('rfc'):
            assert TokenRequest.default('', 'storage.read:/rucio', ctx) == 'subject-tok'
        mock_post.assert_called_once()

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_credentials_failure_does_not_exchange(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): Keycloak grant sends no exchange when client-credentials fails """
        mock_region.get.return_value = NoValue()
        mock_post.side_effect = requests.ConnectionError('no route')
        ctx = StorageTokenContext(operation=StorageTokenOperation.CENTRAL_DELETE, rse_id='rse-1')
        with oidc_ready('rfc'):
            assert TokenRequest.default('web1', 'storage.read:/rucio', ctx) is None
        mock_post.assert_called_once()


class TestIdentityProviderSelection:

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_cilogon_uses_the_iam_grant(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): idp = cilogon sends the IAM request """
        mock_region.get.return_value = NoValue()
        mock_post.return_value = token_response('tok')
        ctx = StorageTokenContext(operation=StorageTokenOperation.FTS_AUTH)
        with oidc_ready('cilogon'):
            assert TokenRequest.default('fts.example.org', 'fts', ctx) == 'tok'
        assert mock_post.call_args.kwargs['data'] == {
            'grant_type': 'client_credentials',
            'audience': 'fts.example.org',
            'scope': 'fts',
        }

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_missing_option_defaults_to_iam(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): An unreadable idp option falls back to the IAM request """
        mock_region.get.return_value = NoValue()
        mock_post.return_value = token_response('tok')
        ctx = StorageTokenContext(operation=StorageTokenOperation.FTS_AUTH)
        with oidc_ready(), patch('rucio.core.token.request.config_get', side_effect=RuntimeError('no config')):
            assert TokenRequest.default('fts.example.org', 'fts', ctx) == 'tok'
        assert mock_post.call_args.kwargs['data']['audience'] == 'fts.example.org'

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_unknown_idp_returns_none(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): An unknown idp returns no token and contacts no IdP """
        mock_region.get.return_value = NoValue()
        ctx = StorageTokenContext(operation=StorageTokenOperation.FTS_AUTH)
        with oidc_ready('keycloak'):
            assert TokenRequest.default('fts.example.org', 'fts', ctx) is None
        mock_post.assert_not_called()


class TestTokenCacheKey:

    def test_key_is_audience_and_scope(self):
        """ STORAGE TOKEN (CORE): The cache key depends only on audience and scope """
        bare = StorageTokenContext(operation=StorageTokenOperation.TPC_SOURCE, rse_id='rse-1')
        with_facts = StorageTokenContext(
            operation=StorageTokenOperation.TPC_SOURCE,
            rse_id='rse-1',
            did=('mock', 'file.root'),
            account=MagicMock(),
            extras={'fts_hostname': 'fts.example.org'},
        )
        key = token_cache_key('davs.example.org', 'storage.read:/data', bare)
        assert key == hashlib.md5(b'audience=davs.example.org;scope=storage.read:/data').hexdigest()
        assert key == token_cache_key('davs.example.org', 'storage.read:/data', with_facts)
        assert key != token_cache_key('other.example.org', 'storage.read:/data', bare)


class TestTokenRequestCache:

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_cache_hit_skips_idp(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): A valid cached token is returned without contacting the IdP """
        cached = jwt_with_claims(exp=future_exp())
        mock_region.get.return_value = cached
        ctx = StorageTokenContext(operation=StorageTokenOperation.FTS_AUTH)
        with oidc_ready():
            assert TokenRequest.default('fts.example.org', 'fts', ctx) == cached
        mock_post.assert_not_called()

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_cache_miss_stores_token(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): A newly minted token is stored under its cache key """
        mock_region.get.return_value = NoValue()
        mock_post.return_value = token_response('tok-fresh')
        ctx = StorageTokenContext(operation=StorageTokenOperation.FTS_AUTH)
        with oidc_ready():
            assert TokenRequest.default('fts.example.org', 'fts', ctx) == 'tok-fresh'
        mock_region.set.assert_called_once_with(token_cache_key('fts.example.org', 'fts', ctx), 'tok-fresh')

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_client_download_skips_the_cache(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): Client-download tokens are neither read from nor written to the cache """
        mock_post.return_value = token_response('tok-file')
        ctx = StorageTokenContext(operation=StorageTokenOperation.CLIENT_DOWNLOAD, rse_id='rse-1')
        with oidc_ready():
            TokenRequest.default('davs.example.org', 'storage.read:/file', ctx)
        mock_region.get.assert_not_called()
        mock_region.set.assert_not_called()

    @patch('rucio.core.token.request.REGION')
    def test_cache_get_rejects_expired_and_invalid(self, mock_region):
        """ STORAGE TOKEN (CORE): Missing, invalid, expired or nearly expired cached tokens are ignored """
        mock_region.get.return_value = NoValue()
        assert _token_cache_get('k') is None

        valid = jwt_with_claims(exp=future_exp())
        mock_region.get.return_value = valid
        assert _token_cache_get('k') == valid

        mock_region.get.return_value = 'not-a-jwt'
        assert _token_cache_get('k') is None

        nearly_expired = jwt_with_claims(exp=int((datetime.now(tz=timezone.utc) + timedelta(minutes=1)).timestamp()))
        mock_region.get.return_value = nearly_expired
        assert _token_cache_get('k') is None

        expired = jwt_with_claims(exp=int((datetime.now(tz=timezone.utc) - timedelta(minutes=1)).timestamp()))
        mock_region.get.return_value = expired
        assert _token_cache_get('k') is None


class TestTokenManagedDefault:

    def test_offline_access_in_scope_string_is_managed(self):
        """ STORAGE TOKEN (CORE): offline_access in the scope string marks a token as managed """
        ctx = StorageTokenContext(operation=StorageTokenOperation.TPC_SOURCE)
        token = unsigned_jwt('davs.example.org', 'offline_access storage.read:/data')
        assert TokenManaged.default(ctx, token) is True
        assert token_is_managed(ctx, token) is True

    def test_scope_list_claim(self):
        """ STORAGE TOKEN (CORE): offline_access in a scope list marks a token as managed """
        ctx = StorageTokenContext(operation=StorageTokenOperation.TPC_SOURCE)
        token = jwt_with_claims(scope=['offline_access', 'storage.read:/data'])
        assert TokenManaged.default(ctx, token) is True

    def test_invalid_token_is_unmanaged(self):
        """ STORAGE TOKEN (CORE): A token that cannot be parsed is unmanaged """
        ctx = StorageTokenContext(operation=StorageTokenOperation.TPC_SOURCE)
        assert TokenManaged.default(ctx, 'not-a-jwt') is False


class TestUnmanagedTokensForJob:

    @staticmethod
    def items(*jwts: str) -> list[JobTransferToken]:
        return [JobTransferToken(token=token) for token in jwts]

    def test_all_managed(self):
        """ STORAGE TOKEN (CORE): A job with only managed tokens is submitted as managed """
        tokens = self.items(
            unsigned_jwt('src.example.org', 'offline_access storage.read:/data'),
            unsigned_jwt('dst.example.org', 'offline_access storage.modify:/data'),
        )
        assert unmanaged_tokens_for_job(tokens, vo=None) is False

    def test_all_unmanaged(self):
        """ STORAGE TOKEN (CORE): A job with only unmanaged tokens is submitted as unmanaged """
        tokens = self.items(
            unsigned_jwt('src.example.org', 'storage.read:/data'),
            unsigned_jwt('dst.example.org', 'storage.modify:/data'),
        )
        assert unmanaged_tokens_for_job(tokens, vo=None) is True

    def test_mixed_prefers_managed(self):
        """ STORAGE TOKEN (CORE): A mixed job is submitted as managed with a warning """
        tokens = self.items(
            unsigned_jwt('src.example.org', 'offline_access storage.read:/data'),
            unsigned_jwt('dst.example.org', 'storage.modify:/data'),
        )
        logged = []

        def logger(level, msg, *args):
            logged.append((level, msg % args if args else msg))

        assert unmanaged_tokens_for_job(tokens, vo=None, logger=logger) is False
        assert logged == [(logging.WARNING, 'Mixed managed and unmanaged storage tokens in one FTS job; submitting as managed')]


class ReplicaScope:
    def __init__(self, external='mock', vo='def'):
        self.external = external
        self.vo = vo

    def __str__(self):
        return self.external


class TestReaperCentralDelete:

    @staticmethod
    def replica(name: str) -> dict[str, Any]:
        return {
            'scope': ReplicaScope(),
            'name': name,
            'bytes': 1,
            'pfn': f'davs://se.example.org/{name}',
            'datatype': 'RAW',
        }

    @staticmethod
    def protocol_mock() -> MagicMock:
        """A protocol double whose set_auth_token updates auth_token, as the real one does."""
        prot = MagicMock()
        prot.attributes = {'scheme': 'davs'}
        prot.auth_token = None
        prot.set_auth_token.side_effect = lambda token: setattr(prot, 'auth_token', token)
        return prot

    @staticmethod
    def delete(replicas: list[dict[str, Any]], prot: MagicMock, token_for_replica) -> list[dict[str, Any]]:
        heartbeat_handler = MagicMock()
        heartbeat_handler.live.return_value = (None, 1, logging.log)
        rse_info = {'rse': 'MOCK-RSE', 'id': 'rse-1', 'sign_url': None}
        return delete_from_storage(
            heartbeat_handler, 'payload', replicas, prot, rse_info, False, 100,
            logger=logging.log,
            storage_token_for_replica=token_for_replica,
        )

    @patch('rucio.daemons.reaper.reaper.get_token_for_operation', return_value='tok')
    def test_central_delete_token_always_passes_did(self, mock_get):
        """ REAPER (DAEMON): The central-delete token request carries the RSE, DID and VO """
        assert _central_delete_token('rse-1', self.replica('file.root'), logging.log) == 'tok'
        ctx = mock_get.call_args.args[0]
        assert ctx.operation == StorageTokenOperation.CENTRAL_DELETE
        assert ctx.rse_id == 'rse-1'
        assert ctx.did == ('mock', 'file.root')
        assert ctx.vo == 'def'

    @patch('rucio.daemons.reaper.reaper.add_message')
    def test_delete_from_storage_sets_bearer_per_replica(self, mock_msg):
        """ REAPER (DAEMON): Each replica is deleted with its own token over one connection """
        replicas = [self.replica('a.root'), self.replica('b.root')]
        tokens = {'a.root': 'tok-a', 'b.root': 'tok-b'}
        prot = self.protocol_mock()

        deleted = self.delete(replicas, prot, lambda replica: tokens[replica['name']])

        assert [item['name'] for item in deleted] == ['a.root', 'b.root']
        # The pre-connect bind covers the first replica, so it is not bound twice.
        assert prot.set_auth_token.call_args_list == [call('tok-a'), call('tok-b')]
        assert prot.delete.call_args_list == [call(replicas[0]['pfn']), call(replicas[1]['pfn'])]
        prot.connect.assert_called_once()

    @patch('rucio.daemons.reaper.reaper.add_message')
    def test_delete_from_storage_binds_a_shared_token_once(self, mock_msg):
        """ REAPER (DAEMON): A token shared by every replica is set once """
        replicas = [self.replica('a.root'), self.replica('b.root'), self.replica('c.root')]
        prot = self.protocol_mock()

        self.delete(replicas, prot, lambda replica: 'prefix-tok')

        assert prot.set_auth_token.call_args_list == [call('prefix-tok')]

    @patch('rucio.daemons.reaper.reaper.add_message')
    def test_delete_from_storage_without_a_token_still_deletes(self, mock_msg):
        """ REAPER (DAEMON): Deletion proceeds without a bearer when no token is available """
        replicas = [self.replica('a.root')]
        prot = self.protocol_mock()

        self.delete(replicas, prot, lambda replica: None)

        prot.set_auth_token.assert_not_called()
        assert prot.delete.call_args_list == [call(replicas[0]['pfn'])]

    def test_webdav_set_auth_token_updates_authorization_header(self):
        """ RSE PROTOCOL (WEBDAV): Setting or clearing the token updates the Authorization header """
        prot = MagicMock()
        headers: dict[str, str] = {}
        prot.session.headers = headers
        prot.auth_token = 'tok-2'
        WebDAV._on_auth_token_changed(prot)
        assert headers['Authorization'] == 'Bearer tok-2'
        prot.auth_token = None
        WebDAV._on_auth_token_changed(prot)
        assert 'Authorization' not in headers


def idp_config(issuer: str, idp: str, scope_algorithm: str = 'default') -> dict[str, Any]:
    return {
        'overrides': [
            ('oidc', 'admin_issuer', issuer),
            ('oidc', 'idp', idp),
            ('oidc', 'token_scope', scope_algorithm),
            ('reaper', 'use_token_operation_interface', 'True'),
        ],
        'removes': [('policy', 'package')],
    }


def file_path(rse_id: str, scope: str, name: str) -> str:
    pfns = rsemgr.lfns2pfns(get_rse_info(rse_id), [{'scope': scope, 'name': name}], operation='delete', scheme='davs')
    return normalize_scope_path(urlparse(next(iter(pfns.values()))).path)


def file_scope(ctx: StorageTokenContext) -> str:
    """A VO-style token_scope override: one file, not the RSE prefix."""
    assert ctx.rse_id is not None and ctx.did is not None
    path = file_path(ctx.rse_id, *ctx.did)
    return f'storage.modify:{path} storage.read:{path}'


def claim_values(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        return set(value.split())
    return {part for item in value for part in str(item).split()}


def assert_file_scope(vo: str, did: dict[str, Any], granted: set[str]) -> None:
    path = file_path(get_rse_id(rse=RSE_NAME, vo=vo), did['scope'].external, did['name'])
    assert path.startswith('/rucio/') and path.endswith('/' + did['name'])
    assert granted == {f'storage.modify:{path}', f'storage.read:{path}'}


@pytest.fixture
def real_idp(vo, did_factory, caches_mock, file_config_mock, monkeypatch):
    """Point the process at the configured issuer and return a mint-and-delete helper.

    ``admin_issuer`` is read once at import of ``rucio.core.oidc``, so it is
    patched here. Policy-package defaults are cached without the package name,
    so the cache is cleared to keep the in-tree algorithms.
    """
    monkeypatch.delenv('RUCIO_POLICY_PACKAGE', raising=False)
    monkeypatch.setattr(PolicyPackageAlgorithms, '_default_algorithms', {})
    monkeypatch.setitem(PolicyPackageAlgorithms._ALGORITHMS['token_scope'], 'file', file_scope)
    monkeypatch.setattr(oidc_core, 'ADMIN_ISSUER_ID', dict(file_config_mock.items('oidc'))['admin_issuer'])
    monkeypatch.setattr(oidc_core, 'OIDC_CONFIGURATION_RUN', False)
    monkeypatch.setattr(oidc_core, 'OIDC_CLIENT_ID', '')
    monkeypatch.setattr(oidc_core, 'OIDC_CLIENT_SECRET', '')
    monkeypatch.setattr(oidc_core, 'OIDC_PROVIDER_ENDPOINT', '')

    def mint_and_delete() -> tuple[dict[str, Any], set[str]]:
        did = did_factory.upload_test_file(RSE_NAME)
        for rule in list(rule_core.list_associated_rules_for_file(**did)):
            rule_core.delete_rule(rule['id'])

        rse_id = get_rse_id(rse=RSE_NAME, vo=vo)
        token = get_token_for_operation(StorageTokenContext(
            operation=StorageTokenOperation.CENTRAL_DELETE,
            rse_id=rse_id,
            did=(did['scope'].external, did['name']),
            vo=vo,
        ))
        assert token is not None
        claims = JWT().unpack(token).payload()
        assert set(determine_audience_for_rse(rse_id).split()) <= claim_values(claims.get('aud'))
        granted = {item for item in claim_values(claims.get('scope')) if item.startswith(PATH_SCOPES)}

        reaper(once=True, rses=[], include_rses=RSE_NAME, exclude_rses=None, chunk_size=1000, greedy=True, scheme='davs')
        assert list(replica_core.list_replicas(dids=[did], rse_expression=RSE_NAME)) == []
        return did, granted

    return mint_and_delete


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason='leaves files in WEB1 if deletion fails')
@pytest.mark.needs_iam
@pytest.mark.noparallel(groups=[NoParallelGroups.WEB])
@pytest.mark.parametrize('caches_mock', [{'caches_to_mock': [
    'rucio.daemons.reaper.reaper.REGION',
    'rucio.core.token.request.REGION',
]}], indirect=True)
class TestRealIdP:
    """ STORAGE TOKEN (INTEGRATION): CENTRAL_DELETE on WEB1 against the dev indigoiam and Keycloak.

    WEB1 only checks ``aud``, so the scope claim is what tells the widths apart.
    """

    @pytest.mark.parametrize('file_config_mock', [idp_config('indigoiam', 'iam')], indirect=True)
    def test_rse_wide_token_iam(self, real_idp):
        """ STORAGE TOKEN (INTEGRATION): IAM mints an RSE-wide token and the reaper deletes with it """
        _did, granted = real_idp()
        assert granted == RSE_WIDE_SCOPE

    @pytest.mark.parametrize('file_config_mock', [idp_config('indigoiam', 'iam', scope_algorithm='file')], indirect=True)
    def test_file_specific_token_iam(self, vo, real_idp):
        """ STORAGE TOKEN (INTEGRATION): IAM mints a file-specific token and the reaper deletes with it """
        did, granted = real_idp()
        assert_file_scope(vo, did, granted)

    @pytest.mark.parametrize('file_config_mock', [idp_config('keycloak', 'rfc')], indirect=True)
    def test_rse_wide_token_keycloak(self, real_idp):
        """ STORAGE TOKEN (INTEGRATION): Keycloak mints an RSE-wide token and the reaper deletes with it """
        _did, granted = real_idp()
        assert granted == RSE_WIDE_SCOPE

    @pytest.mark.parametrize('file_config_mock', [idp_config('keycloak', 'rfc', scope_algorithm='file')], indirect=True)
    def test_file_specific_token_keycloak(self, vo, real_idp):
        """ STORAGE TOKEN (INTEGRATION): Keycloak mints a file-specific token and the reaper deletes with it """
        did, granted = real_idp()
        assert_file_scope(vo, did, granted)
