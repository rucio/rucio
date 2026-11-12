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

import logging
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from unittest.mock import MagicMock, patch

import pytest
import requests
from dogpile.cache.api import NoValue
from jwkest.jwt import JWT

from rucio.common.constants import RseAttr
from rucio.common.exception import InvalidRequest
from rucio.common.plugins import PolicyPackageAlgorithms
from rucio.core import oidc as oidc_core
from rucio.core import replica as replica_core
from rucio.core import rule as rule_core
from rucio.core.rse import add_protocol, add_rse_attribute, determine_audience_for_rse, determine_scope_for_rse, get_rse_id
from rucio.core.token import (
    JobTransferToken,
    StorageTokenContext,
    StorageTokenOperation,
    TokenCache,
    TokenRequest,
    get_token_for_operation,
    token_is_managed,
    unmanaged_tokens_for_job,
)
from rucio.core.token.cache import token_cache_key
from rucio.core.token.scope import normalize_scope_path
from rucio.daemons.reaper.reaper import _central_delete_token, delete_from_storage, reaper
from rucio.tests.common import skip_rse_tests_with_accounts
from tests.ruciopytest import NoParallelGroups

TOKEN_ENDPOINT = 'https://iam.example.org/token'
PATH_SCOPES = ('storage.read:', 'storage.modify:')
RSE_WIDE_SCOPE = {'storage.modify:/rucio', 'storage.read:/rucio'}

BASE_PATH = '/webdav/atlas/'
DISK_PREFIX = '/webdav/atlas/atlasdatadisk/rucio/'
DISK_SCOPE_PATH = '/atlasdatadisk/rucio/'
SOURCE_SCOPE = f'offline_access storage.read:{DISK_SCOPE_PATH}'
DESTINATION_SCOPE = f'offline_access storage.modify:{DISK_SCOPE_PATH} storage.read:{DISK_SCOPE_PATH}'
DELETE_SCOPE = f'storage.modify:{DISK_SCOPE_PATH} storage.read:{DISK_SCOPE_PATH}'

_PROTOCOL_DOMAINS = {
    'lan': {'read': 1, 'write': 1, 'delete': 1},
    'wan': {'read': 1, 'write': 1, 'delete': 1},
}
_UNSUPPORTED_OPERATIONS = (
    StorageTokenOperation.TPC_STAGE,
    StorageTokenOperation.TPC_POLL,
    StorageTokenOperation.CLIENT_DELETE,
    StorageTokenOperation.CLIENT_DOWNLOAD,
    StorageTokenOperation.CLIENT_UPLOAD,
)
_RSE_OPERATIONS = (
    StorageTokenOperation.TPC_SOURCE,
    StorageTokenOperation.TPC_DESTINATION,
    StorageTokenOperation.CENTRAL_DELETE,
)
_ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token'
_TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange'


def token_with(**claims: Any) -> str:
    return JWT().pack([claims])


def future_exp(hours: int = 1) -> int:
    return int((datetime.now(tz=timezone.utc) + timedelta(hours=hours)).timestamp())


def token_response(token: str, **fields: str) -> MagicMock:
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {'access_token': token, **fields}
    return response


def exchange_response(token: str, **fields: str) -> MagicMock:
    fields.setdefault('token_type', 'Bearer')
    fields.setdefault('issued_token_type', _ACCESS_TOKEN_TYPE)
    return token_response(token, **fields)


def fts_context(**extras: Any) -> StorageTokenContext:
    extras.setdefault('fts_hostname', 'fts.example.org')
    return StorageTokenContext(operation=StorageTokenOperation.FTS_AUTH, extras=extras)


def add_storage_protocol(
        rse_id: str,
        scheme: str,
        hostname: str,
        prefix: str,
        extended_attributes: Optional[dict[str, str]] = None,
) -> None:
    parameter: dict[str, Any] = {
        'scheme': scheme,
        'hostname': hostname,
        'port': 443,
        'prefix': prefix,
        'impl': 'rucio.rse.protocols.gfal.Default',
        'domains': _PROTOCOL_DOMAINS,
    }
    if extended_attributes is not None:
        parameter['extended_attributes'] = extended_attributes
    add_protocol(rse_id, parameter)


def disk_rse(rse_factory, hosts: tuple[str, ...] = ('se.example.org',)) -> str:
    """An RSE whose davs prefix sits under ``BASE_PATH``, plus a root protocol that must be ignored."""
    _, rse_id = rse_factory.make_rse()
    for hostname in hosts:
        add_storage_protocol(rse_id, 'davs', hostname, DISK_PREFIX)
    add_storage_protocol(rse_id, 'root', 'root.example.org', '/root/')
    add_rse_attribute(rse_id, RseAttr.OIDC_BASE_PATH, BASE_PATH)
    return rse_id


@contextmanager
def oidc_ready(idp: Optional[str] = 'iam', credentials: bool = True):
    """Provide storage-token client credentials and select ``[oidc] idp``.

    ``idp=None`` makes the option unreadable, which the request layer treats as IAM.
    ``credentials=False`` leaves the client id, secret, and token endpoint empty.
    """
    values = {
        'OIDC_CLIENT_ID': 'client-id' if credentials else '',
        'OIDC_CLIENT_SECRET': 'client-secret' if credentials else '',
        'OIDC_PROVIDER_ENDPOINT': TOKEN_ENDPOINT if credentials else '',
        'OIDC_CONFIGURATION_RUN': True,
    }
    if idp is None:
        config_patch = patch('rucio.core.token.request.config_get', side_effect=RuntimeError('no config'))
    else:
        config_patch = patch('rucio.core.token.request.config_get', return_value=idp)
    with patch.multiple('rucio.core.token.request.oidc_core', **values), config_patch:
        yield


class TestNormalizeScopePath:

    @pytest.mark.parametrize('prefix,expected', [
        ('//rucio', '/rucio'),  # xrootd spells the prefix with an extra slash
        ('rucio', '/rucio'),
        ('/webdav//atlas///rucio/', '/webdav/atlas/rucio/'),
        ('', '/'),
    ])
    def test_normalization(self, prefix, expected):
        """ STORAGE TOKEN (CORE): Scope paths have one leading slash and no repeated slashes """
        assert normalize_scope_path(prefix) == expected


class TestRseTokenClaims:

    def test_audience_is_the_sorted_davs_hostnames(self, rse_factory):
        """ STORAGE TOKEN (CORE): The audience is the RSE's davs hostnames, in sorted order """
        _, rse_id = rse_factory.make_rse()
        add_storage_protocol(rse_id, 'davs', 'b.example.org', DISK_PREFIX)
        add_storage_protocol(rse_id, 'davs', 'a.example.org', DISK_PREFIX)
        add_storage_protocol(rse_id, 'root', 'root.example.org', '/root/')
        assert determine_audience_for_rse(rse_id) == 'a.example.org b.example.org'

    def test_rse_attribute_base_path_leaves_an_absolute_scope_path(self, rse_factory):
        """ STORAGE TOKEN (CORE): Stripping the RSE oidc_base_path leaves an absolute scope path """
        _, rse_id = rse_factory.make_rse()
        add_storage_protocol(rse_id, 'davs', 'se.example.org', DISK_PREFIX)
        add_rse_attribute(rse_id, RseAttr.OIDC_BASE_PATH, BASE_PATH)
        assert determine_scope_for_rse(rse_id, ['storage.read']) == f'storage.read:{DISK_SCOPE_PATH}'

    def test_protocol_base_path_wins_over_the_rse_attribute(self, rse_factory):
        """ STORAGE TOKEN (CORE): A protocol oidc_base_path takes precedence over the RSE attribute """
        _, rse_id = rse_factory.make_rse()
        add_storage_protocol(
            rse_id,
            'davs',
            'se.example.org',
            '/webdav/atlas/atlasdatadisk/',
            {RseAttr.OIDC_BASE_PATH: '/webdav/atlas'},
        )
        add_rse_attribute(rse_id, RseAttr.OIDC_BASE_PATH, '/not-used')
        assert determine_scope_for_rse(rse_id, ['storage.read']) == 'storage.read:/atlasdatadisk/'

    def test_prefix_outside_the_base_path_is_kept(self, rse_factory):
        """ STORAGE TOKEN (CORE): A prefix that does not start with oidc_base_path is kept """
        _, rse_id = rse_factory.make_rse()
        add_storage_protocol(rse_id, 'davs', 'se.example.org', '/data/rucio')
        add_rse_attribute(rse_id, RseAttr.OIDC_BASE_PATH, BASE_PATH)
        assert determine_scope_for_rse(rse_id, ['storage.read']) == 'storage.read:/data/rucio'

    def test_each_davs_prefix_is_its_own_scope_entry(self, rse_factory):
        """ STORAGE TOKEN (CORE): Each davs prefix becomes its own scope entry """
        _, rse_id = rse_factory.make_rse()
        add_storage_protocol(rse_id, 'davs', 'a.example.org', '/rucio')
        add_storage_protocol(rse_id, 'davs', 'b.example.org', '/atlas/rucio/')
        add_storage_protocol(rse_id, 'root', 'root.example.org', '/ignored/')
        assert determine_scope_for_rse(rse_id, ['storage.read']) == 'storage.read:/atlas/rucio/ storage.read:/rucio'


class TestGetTokenForOperation:

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_fts_auth_posts_the_hostname_and_fts_scope(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): FTS authentication asks IAM for audience=hostname and scope=fts """
        mock_region.get.return_value = NoValue()
        mock_post.return_value = token_response('tok-1')
        ctx = fts_context(expiry_time=3600, resource='https://se.example.org')
        with oidc_ready():
            assert get_token_for_operation(ctx) == 'tok-1'
        assert mock_post.call_args.kwargs['url'] == TOKEN_ENDPOINT
        assert mock_post.call_args.kwargs['auth'] == ('client-id', 'client-secret')
        assert mock_post.call_args.kwargs['data'] == {
            'grant_type': 'client_credentials',
            'audience': 'fts.example.org',
            'scope': 'fts',
        }

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_fts_auth_without_a_hostname_does_not_contact_the_idp(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): FTS authentication without a hostname raises and contacts no IdP """
        ctx = StorageTokenContext(operation=StorageTokenOperation.FTS_AUTH, extras={'expiry_time': 3600})
        with oidc_ready():
            with pytest.raises(InvalidRequest):
                get_token_for_operation(ctx)
        mock_post.assert_not_called()

    @pytest.mark.parametrize('operation,scope', [
        (StorageTokenOperation.TPC_SOURCE, SOURCE_SCOPE),
        (StorageTokenOperation.TPC_DESTINATION, DESTINATION_SCOPE),
        (StorageTokenOperation.CENTRAL_DELETE, DELETE_SCOPE),
    ])
    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_rse_operation_posts_the_davs_audience_and_its_scope(self, mock_post, mock_region, operation, scope, rse_factory):
        """ STORAGE TOKEN (CORE): Copy and central-delete tokens use the davs audience and the operation's scope """
        mock_region.get.return_value = NoValue()
        mock_post.return_value = token_response('tok-1')
        ctx = StorageTokenContext(operation=operation, rse_id=disk_rse(rse_factory))
        with oidc_ready():
            assert get_token_for_operation(ctx) == 'tok-1'
        assert mock_post.call_args.kwargs['data'] == {
            'grant_type': 'client_credentials',
            'audience': 'se.example.org',
            'scope': scope,
        }

    @pytest.mark.parametrize('operation', _UNSUPPORTED_OPERATIONS)
    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_unsupported_operation_does_not_contact_the_idp(self, mock_post, mock_region, operation):
        """ STORAGE TOKEN (CORE): Stage, poll, and client operations raise before any IdP request """
        ctx = StorageTokenContext(operation=operation, rse_id='rse-1', extras={'fts_hostname': 'fts.example.org'})
        with oidc_ready():
            with pytest.raises(InvalidRequest):
                get_token_for_operation(ctx)
        mock_post.assert_not_called()

    @pytest.mark.parametrize('operation', _RSE_OPERATIONS)
    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_rse_operation_without_an_rse_does_not_contact_the_idp(self, mock_post, mock_region, operation):
        """ STORAGE TOKEN (CORE): A copy or central-delete token without an RSE raises and contacts no IdP """
        ctx = StorageTokenContext(operation=operation)
        with oidc_ready():
            with pytest.raises(InvalidRequest):
                get_token_for_operation(ctx)
        mock_post.assert_not_called()

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_missing_credentials_return_none(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): Missing client credentials return no token and contact no IdP """
        with oidc_ready(credentials=False):
            assert get_token_for_operation(fts_context()) is None
        mock_post.assert_not_called()

    @pytest.mark.parametrize('token_type', ['Bearer', 'bearer', 'omitted'])
    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_accepts_bearer_or_missing_token_type(self, mock_post, mock_region, token_type):
        """ STORAGE TOKEN (CORE): A Bearer token type is case-insensitive and may be omitted """
        mock_region.get.return_value = NoValue()
        fields = {} if token_type == 'omitted' else {'token_type': token_type}
        mock_post.return_value = token_response('tok-1', **fields)
        with oidc_ready():
            assert get_token_for_operation(fts_context()) == 'tok-1'

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_rejects_a_non_bearer_token(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): A token that is not a Bearer token is not returned or cached """
        mock_region.get.return_value = NoValue()
        mock_post.return_value = token_response('tok-1', token_type='N_A')
        with oidc_ready():
            assert get_token_for_operation(fts_context()) is None
        mock_region.set.assert_not_called()

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_idp_failure_returns_none(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): An IdP error returns no token """
        mock_region.get.return_value = NoValue()
        mock_post.side_effect = requests.ConnectionError('no route to IdP')
        with oidc_ready():
            assert get_token_for_operation(fts_context()) is None
        mock_post.assert_called_once()
        mock_region.set.assert_not_called()

    @pytest.mark.parametrize('idp,contacts_idp', [
        pytest.param('cilogon', True, id='cilogon'),
        pytest.param(None, True, id='missing'),
        pytest.param('keycloak', False, id='unknown'),
    ])
    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_idp_selection(self, mock_post, mock_region, idp, contacts_idp):
        """ STORAGE TOKEN (CORE): cilogon and a missing idp option use IAM; an unknown idp contacts no one """
        mock_region.get.return_value = NoValue()
        mock_post.return_value = token_response('tok')
        with oidc_ready(idp):
            result = get_token_for_operation(fts_context())
        if contacts_idp:
            assert result == 'tok'
            assert mock_post.call_args.kwargs['data'] == {
                'grant_type': 'client_credentials',
                'audience': 'fts.example.org',
                'scope': 'fts',
            }
        else:
            assert result is None
            mock_post.assert_not_called()


class TestRfcIdentityProvider:

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_exchanges_a_client_credentials_token_for_each_davs_hostname(self, mock_post, mock_region, rse_factory):
        """ STORAGE TOKEN (CORE): Keycloak grant is client-credentials, then one exchange with an audience per davs hostname """
        mock_region.get.return_value = NoValue()
        mock_post.side_effect = [token_response('subject-tok'), exchange_response('exchanged-tok')]
        ctx = StorageTokenContext(
            operation=StorageTokenOperation.CENTRAL_DELETE,
            rse_id=disk_rse(rse_factory, hosts=('a.example.org', 'b.example.org')),
        )
        with oidc_ready('rfc'):
            assert get_token_for_operation(ctx) == 'exchanged-tok'

        credentials, exchange = mock_post.call_args_list
        assert credentials.kwargs['data'] == {
            'grant_type': 'client_credentials',
            'scope': DELETE_SCOPE,
        }
        assert exchange.kwargs['url'] == TOKEN_ENDPOINT
        assert exchange.kwargs['auth'] == ('client-id', 'client-secret')
        assert exchange.kwargs['data'] == [
            ('grant_type', _TOKEN_EXCHANGE_GRANT),
            ('subject_token', 'subject-tok'),
            ('subject_token_type', _ACCESS_TOKEN_TYPE),
            ('requested_token_type', _ACCESS_TOKEN_TYPE),
            ('scope', DELETE_SCOPE),
            ('audience', 'a.example.org'),
            ('audience', 'b.example.org'),
        ]

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_without_davs_hostnames_returns_the_client_credentials_token(self, mock_post, mock_region, rse_factory):
        """ STORAGE TOKEN (CORE): Keycloak grant without davs hostnames returns the client-credentials token """
        mock_region.get.return_value = NoValue()
        mock_post.return_value = token_response('subject-tok')
        _, rse_id = rse_factory.make_rse()
        add_storage_protocol(rse_id, 'root', 'root.example.org', '/root/')
        ctx = StorageTokenContext(operation=StorageTokenOperation.CENTRAL_DELETE, rse_id=rse_id)
        with oidc_ready('rfc'):
            assert get_token_for_operation(ctx) == 'subject-tok'
        mock_post.assert_called_once()
        assert mock_post.call_args.kwargs['data'] == {
            'grant_type': 'client_credentials',
            'scope': '',
        }

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_does_not_exchange_when_client_credentials_fail(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): Keycloak grant sends no exchange when client-credentials fails """
        mock_region.get.return_value = NoValue()
        mock_post.side_effect = requests.ConnectionError('no route')
        with oidc_ready('rfc'):
            assert get_token_for_operation(fts_context()) is None
        mock_post.assert_called_once()
        mock_region.set.assert_not_called()

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_rejects_an_exchange_that_is_not_an_access_token(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): Keycloak exchange must issue a Bearer access token """
        mock_region.get.return_value = NoValue()
        mock_post.side_effect = [
            token_response('subject-tok'),
            exchange_response('exchanged-tok', issued_token_type='urn:ietf:params:oauth:token-type:refresh_token'),
        ]
        with oidc_ready('rfc'):
            assert get_token_for_operation(fts_context()) is None
        assert mock_post.call_count == 2
        mock_region.set.assert_not_called()

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_accepts_a_bearer_exchange_that_omits_issued_token_type(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): A Bearer Keycloak exchange may omit issued_token_type """
        mock_region.get.return_value = NoValue()
        mock_post.side_effect = [
            token_response('subject-tok'),
            token_response('exchanged-tok', token_type='Bearer'),
        ]
        with oidc_ready('rfc'):
            assert get_token_for_operation(fts_context()) == 'exchanged-tok'


class TestTokenCache:

    def test_key_depends_only_on_audience_and_scope(self):
        """ STORAGE TOKEN (CORE): The cache key changes with audience and scope, and with nothing else on the context """
        bare = StorageTokenContext(operation=StorageTokenOperation.TPC_SOURCE, rse_id='rse-1')

        class _Account:
            vo = 'def'

        with_facts = StorageTokenContext(
            operation=StorageTokenOperation.TPC_DESTINATION,
            rse_id='other-rse',
            did=('mock', 'file.root'),
            account=_Account(),
            extras={'fts_hostname': 'fts.example.org'},
        )
        key = token_cache_key('davs.example.org', 'storage.read:/data', bare)
        assert key == token_cache_key('davs.example.org', 'storage.read:/data', with_facts)
        assert key != token_cache_key('other.example.org', 'storage.read:/data', bare)
        assert key != token_cache_key('davs.example.org', 'storage.modify:/data', bare)

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_cache_hit_skips_the_idp(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): A valid cached token is returned without contacting the IdP """
        cached = token_with(exp=future_exp())
        mock_region.get.return_value = cached
        with oidc_ready():
            assert get_token_for_operation(fts_context()) == cached
        mock_post.assert_not_called()

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_a_new_token_is_stored_and_reused(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): A newly minted token is stored and the next request reuses it """
        fresh = token_with(exp=future_exp())
        stored: dict[str, str] = {}

        def cache_get(key: str) -> Any:
            return stored.get(key, NoValue())

        def cache_set(key: str, value: str) -> None:
            stored[key] = value

        mock_region.get.side_effect = cache_get
        mock_region.set.side_effect = cache_set
        mock_post.return_value = token_response(fresh)
        with oidc_ready():
            assert get_token_for_operation(fts_context()) == fresh
            assert get_token_for_operation(fts_context()) == fresh
        mock_post.assert_called_once()
        assert list(stored.values()) == [fresh]

    @pytest.mark.parametrize('kind', ['invalid', 'expired', 'expiring'])
    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_an_unusable_cached_token_is_minted_again(self, mock_post, mock_region, kind):
        """ STORAGE TOKEN (CORE): A cached token that is invalid, expired, or inside the minimum lifetime is minted again """
        now = datetime.now(tz=timezone.utc)
        if kind == 'invalid':
            cached = 'not-a-jwt'
        elif kind == 'expired':
            cached = token_with(exp=int((now - timedelta(minutes=1)).timestamp()))
        else:
            cached = token_with(exp=int((now + timedelta(minutes=1)).timestamp()))
        fresh = token_with(exp=future_exp())
        mock_region.get.return_value = cached
        mock_post.return_value = token_response(fresh)
        with oidc_ready():
            assert get_token_for_operation(fts_context()) == fresh
        mock_post.assert_called_once()
        assert mock_region.set.call_args.args[1] == fresh

    @pytest.mark.parametrize('operation,cached', [
        (StorageTokenOperation.FTS_AUTH, True),
        (StorageTokenOperation.TPC_SOURCE, True),
        (StorageTokenOperation.TPC_DESTINATION, True),
        (StorageTokenOperation.TPC_STAGE, True),
        (StorageTokenOperation.TPC_POLL, True),
        (StorageTokenOperation.CENTRAL_DELETE, True),
        (StorageTokenOperation.CLIENT_DELETE, False),
        (StorageTokenOperation.CLIENT_DOWNLOAD, False),
        (StorageTokenOperation.CLIENT_UPLOAD, False),
    ])
    def test_which_operations_are_cached(self, operation, cached):
        """ STORAGE TOKEN (CORE): FTS, transfer, and central-delete tokens are cached; client tokens are not """
        assert TokenCache.default(StorageTokenContext(operation=operation)) is cached

    @patch('rucio.core.token.request.REGION')
    @patch('rucio.core.token.request.requests.post')
    def test_client_download_is_not_read_from_or_written_to_the_cache(self, mock_post, mock_region):
        """ STORAGE TOKEN (CORE): The request step neither reads nor writes a client-download token """
        mock_post.return_value = token_response('tok-file')
        ctx = StorageTokenContext(operation=StorageTokenOperation.CLIENT_DOWNLOAD, rse_id='rse-1')
        with oidc_ready():
            assert TokenRequest.default('davs.example.org', 'storage.read:/file', ctx) == 'tok-file'
        mock_region.get.assert_not_called()
        mock_region.set.assert_not_called()
        mock_post.assert_called_once()


class TestTokenManaged:

    def test_offline_access_in_a_scope_string_is_managed(self):
        """ STORAGE TOKEN (CORE): offline_access in the scope string marks a token as managed """
        ctx = StorageTokenContext(operation=StorageTokenOperation.TPC_SOURCE)
        token = token_with(scope='offline_access storage.read:/data')
        assert token_is_managed(ctx, token) is True

    def test_offline_access_in_a_scope_list_is_managed(self):
        """ STORAGE TOKEN (CORE): offline_access in a scope list marks a token as managed """
        ctx = StorageTokenContext(operation=StorageTokenOperation.TPC_SOURCE)
        token = token_with(scope=['offline_access', 'storage.read:/data'])
        assert token_is_managed(ctx, token) is True

    def test_invalid_token_is_unmanaged(self):
        """ STORAGE TOKEN (CORE): A token that cannot be parsed is unmanaged """
        ctx = StorageTokenContext(operation=StorageTokenOperation.TPC_SOURCE)
        assert token_is_managed(ctx, 'not-a-jwt') is False


class TestUnmanagedTokensForJob:

    @staticmethod
    def items(*tokens: str) -> list[JobTransferToken]:
        return [JobTransferToken(token=token) for token in tokens]

    def test_all_managed(self):
        """ STORAGE TOKEN (CORE): A job with only managed tokens is submitted as managed """
        tokens = self.items(
            token_with(scope='offline_access storage.read:/data'),
            token_with(scope='offline_access storage.modify:/data'),
        )
        assert unmanaged_tokens_for_job(tokens, vo=None) is False

    def test_all_unmanaged(self):
        """ STORAGE TOKEN (CORE): A job with only unmanaged tokens is submitted as unmanaged """
        tokens = self.items(
            token_with(scope='storage.read:/data'),
            token_with(scope='storage.modify:/data'),
        )
        assert unmanaged_tokens_for_job(tokens, vo=None) is True

    def test_mixed_job_is_submitted_as_managed(self):
        """ STORAGE TOKEN (CORE): A mixed job is submitted as managed with a warning """
        tokens = self.items(
            token_with(scope='offline_access storage.read:/data'),
            token_with(scope='storage.modify:/data'),
        )
        logged = []

        def logger(level, msg, *args):
            logged.append((level, msg % args if args else msg))

        assert unmanaged_tokens_for_job(tokens, vo=None, logger=logger) is False
        assert logged == [(logging.WARNING, 'Mixed managed and unmanaged storage tokens in one FTS job; submitting as managed')]

    def test_empty_job_is_not_unmanaged(self):
        """ STORAGE TOKEN (CORE): A job with no tokens is not submitted as unmanaged """
        assert unmanaged_tokens_for_job([], vo=None) is False


class _RecordingProtocol:
    """Records the bearer present at connect and each delete, which is where a real protocol applies it."""

    def __init__(self, auth_token: Optional[str] = None) -> None:
        self.attributes = {'scheme': 'davs'}
        self.auth_token = auth_token
        self.events: list[tuple[str, Optional[str]]] = []

    def connect(self) -> None:
        self.events.append(('connect', self.auth_token))

    def delete(self, pfn: str) -> None:
        self.events.append(('delete', pfn))

    def close(self) -> None:
        self.events.append(('close', None))


class _ReplicaScope:
    def __init__(self, external: str = 'mock', vo: str = 'def') -> None:
        self.external = external
        self.vo = vo

    def __str__(self) -> str:
        return self.external


class TestReaperCentralDelete:

    @staticmethod
    def replica(name: str) -> dict[str, Any]:
        return {
            'scope': _ReplicaScope(),
            'name': name,
            'bytes': 1,
            'pfn': f'davs://se.example.org/{name}',
            'datatype': 'RAW',
        }

    @staticmethod
    def delete(replicas: list[dict[str, Any]], prot: _RecordingProtocol, token_for_vo) -> list[dict[str, Any]]:
        heartbeat_handler = MagicMock()
        heartbeat_handler.live.return_value = (None, 1, logging.log)
        rse_info = {'rse': 'MOCK-RSE', 'id': 'rse-1', 'sign_url': None}
        return delete_from_storage(
            heartbeat_handler, 'payload', replicas, prot, rse_info, False, 100,
            logger=logging.log,
            central_delete_token=token_for_vo,
        )

    @patch('rucio.daemons.reaper.reaper.get_token_for_operation', return_value='tok')
    def test_central_delete_token_is_rse_wide(self, mock_get):
        """ REAPER (DAEMON): The central-delete token request carries the RSE and VO but no DID """
        assert _central_delete_token('rse-1', 'def', logging.log) == 'tok'
        ctx = mock_get.call_args.args[0]
        assert ctx.operation == StorageTokenOperation.CENTRAL_DELETE
        assert ctx.rse_id == 'rse-1'
        assert ctx.did is None
        assert ctx.vo == 'def'

    @patch('rucio.daemons.reaper.reaper.get_token_for_operation', side_effect=RuntimeError('idp down'))
    def test_central_delete_token_failure_returns_none(self, mock_get):
        """ REAPER (DAEMON): A failed central-delete token request returns no token """
        assert _central_delete_token('rse-1', 'def', logging.log) is None

    @patch('rucio.daemons.reaper.reaper.add_message')
    def test_token_is_bound_before_connect(self, mock_msg):
        """ REAPER (DAEMON): One token is bound before connect, then each replica is deleted """
        replicas = [self.replica('a.root'), self.replica('b.root'), self.replica('c.root')]
        prot = _RecordingProtocol()
        requested = []

        def token_for_vo(vo: str) -> str:
            requested.append(vo)
            return 'rse-tok'

        deleted = self.delete(replicas, prot, token_for_vo)

        assert [item['name'] for item in deleted] == ['a.root', 'b.root', 'c.root']
        assert requested == ['def']
        assert prot.events == [
            ('connect', 'rse-tok'),
            ('delete', replicas[0]['pfn']),
            ('delete', replicas[1]['pfn']),
            ('delete', replicas[2]['pfn']),
            ('close', None),
        ]

    @patch('rucio.daemons.reaper.reaper.add_message')
    def test_an_unchanged_token_is_kept_and_a_new_one_replaces_it(self, mock_msg):
        """ REAPER (DAEMON): The bearer already on the protocol is reused, and a later call replaces it before connect """
        prot = _RecordingProtocol(auth_token='rse-tok')
        tokens = iter(['rse-tok', 'new-tok'])

        self.delete([self.replica('a.root')], prot, lambda vo: next(tokens))
        self.delete([self.replica('b.root')], prot, lambda vo: next(tokens))

        assert prot.events == [
            ('connect', 'rse-tok'),
            ('delete', 'davs://se.example.org/a.root'),
            ('close', None),
            ('connect', 'new-tok'),
            ('delete', 'davs://se.example.org/b.root'),
            ('close', None),
        ]

    @patch('rucio.daemons.reaper.reaper.add_message')
    def test_deletion_proceeds_without_a_token(self, mock_msg):
        """ REAPER (DAEMON): Deletion proceeds without a bearer when no token is available """
        replicas = [self.replica('a.root')]
        prot = _RecordingProtocol()

        self.delete(replicas, prot, lambda vo: None)

        assert prot.events == [
            ('connect', None),
            ('delete', replicas[0]['pfn']),
            ('close', None),
        ]


def idp_config(issuer: str, idp: str) -> dict[str, Any]:
    return {
        'overrides': [
            ('oidc', 'admin_issuer', issuer),
            ('oidc', 'idp', idp),
            ('oidc', 'token_scope', 'default'),
            ('reaper', 'use_token_operation_interface', 'True'),
        ],
        'removes': [('policy', 'package')],
    }


def claim_values(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        return set(value.split())
    return {part for item in value for part in str(item).split()}


@pytest.fixture
def real_idp(vo, did_factory, caches_mock, file_config_mock, monkeypatch):
    """Point the process at the configured issuer and return a mint-and-delete helper.

    ``admin_issuer`` is read once at import of ``rucio.core.oidc``, so it is
    patched here. Policy-package defaults are cached without the package name,
    so the cache is cleared to keep the in-tree algorithms.
    """
    monkeypatch.delenv('RUCIO_POLICY_PACKAGE', raising=False)
    monkeypatch.setattr(PolicyPackageAlgorithms, '_default_algorithms', {})
    monkeypatch.setattr(oidc_core, 'ADMIN_ISSUER_ID', dict(file_config_mock.items('oidc'))['admin_issuer'])
    monkeypatch.setattr(oidc_core, 'OIDC_CONFIGURATION_RUN', False)
    monkeypatch.setattr(oidc_core, 'OIDC_CLIENT_ID', '')
    monkeypatch.setattr(oidc_core, 'OIDC_CLIENT_SECRET', '')
    monkeypatch.setattr(oidc_core, 'OIDC_PROVIDER_ENDPOINT', '')

    def mint_and_delete(rse_name: str) -> set[str]:
        did = did_factory.upload_test_file(rse_name)
        for rule in list(rule_core.list_associated_rules_for_file(**did)):
            rule_core.delete_rule(rule['id'])

        rse_id = get_rse_id(rse=rse_name, vo=vo)
        token = get_token_for_operation(StorageTokenContext(
            operation=StorageTokenOperation.CENTRAL_DELETE,
            rse_id=rse_id,
            vo=vo,
        ))
        assert token is not None
        claims = JWT().unpack(token).payload()
        assert set(determine_audience_for_rse(rse_id).split()) <= claim_values(claims.get('aud'))
        granted = {item for item in claim_values(claims.get('scope')) if item.startswith(PATH_SCOPES)}

        reaper(once=True, rses=[], include_rses=rse_name, exclude_rses=None, chunk_size=1000, greedy=True, scheme='davs')
        assert list(replica_core.list_replicas(dids=[did], rse_expression=rse_name)) == []
        return granted

    return mint_and_delete


@skip_rse_tests_with_accounts
@pytest.mark.dirty(reason='leaves files on WEB1 or XRD5 if deletion fails')
@pytest.mark.needs_iam
@pytest.mark.noparallel(groups=[NoParallelGroups.WEB, NoParallelGroups.XRD])
@pytest.mark.parametrize('caches_mock', [{'caches_to_mock': [
    'rucio.daemons.reaper.reaper.REGION',
    'rucio.core.token.request.REGION',
]}], indirect=True)
class TestRealIdP:
    """ STORAGE TOKEN (INTEGRATION): CENTRAL_DELETE on WEB1 and XRD5.

    XRD5 also has root and magnet protocols. The audience and scope come from its davs protocol,
    whose prefix ``//rucio`` is the same scope path as WEB1. The storage checks ``aud``; the scope
    claim is checked here.

    Keycloak is limited to WEB1. The dev realm has no client for the ``xrd5`` audience, so the
    exchange returns ``Audience not found``.
    """

    @pytest.mark.parametrize('rse_name', ['WEB1', 'XRD5'])
    @pytest.mark.parametrize('file_config_mock', [idp_config('indigoiam', 'iam')], indirect=True)
    def test_rse_wide_token_iam(self, real_idp, rse_name):
        """ STORAGE TOKEN (INTEGRATION): IAM mints an RSE-wide token and the reaper deletes with it """
        assert real_idp(rse_name) == RSE_WIDE_SCOPE

    @pytest.mark.parametrize('file_config_mock', [idp_config('keycloak', 'rfc')], indirect=True)
    def test_rse_wide_token_keycloak(self, real_idp):
        """ STORAGE TOKEN (INTEGRATION): Keycloak mints an RSE-wide token and the reaper deletes with it """
        assert real_idp('WEB1') == RSE_WIDE_SCOPE
