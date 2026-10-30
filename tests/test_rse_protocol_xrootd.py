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

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from rucio.common import exception
from rucio.common.checksum import GLOBALLY_SUPPORTED_CHECKSUMS, PREFERRED_CHECKSUM
from rucio.common.utils import execute
from rucio.rse import rsemanager
from rucio.rse.protocols import xrootd
from rucio.tests.common import load_test_conf_file, skip_rse_tests_with_accounts

from .rsemgr_api_test import MgrTestCases


class _XRootDError(RuntimeError):
    pass


class _NotFound(_XRootDError):
    pass


class _Authorization(_XRootDError):
    pass


class _Checksum(_XRootDError):
    pass


class _AlreadyExists(_XRootDError):
    pass


class _Timeout(_XRootDError):
    pass


def _bindings(storage=None):
    storage = storage or MagicMock()
    storage_client = MagicMock()
    storage_client.from_environment.return_value = storage
    return SimpleNamespace(
        STORAGE_CLIENT_API_VERSION=2,
        StorageClient=storage_client,
        XRootDError=_XRootDError,
        XRootDNotFoundError=_NotFound,
        XRootDAuthorizationError=_Authorization,
        XRootDChecksumError=_Checksum,
        XRootDAlreadyExistsError=_AlreadyExists,
        XRootDTimeoutError=_Timeout,
    )


def _protocol(scheme='root', auth_token=None, verify_checksum=True):
    instance = object.__new__(xrootd.Default)
    instance.scheme = scheme
    instance.hostname = 'storage.example'
    instance.port = '1094' if scheme in xrootd.Default._ROOT_SCHEMES else '443'
    instance.attributes = {
        'scheme': scheme,
        'hostname': instance.hostname,
        'port': int(instance.port),
        'prefix': '/rucio/',
        'extended_attributes': None,
    }
    instance.auth_token = auth_token
    instance.rse = {'verify_checksum': verify_checksum}
    instance.logger = lambda *_args, **_kwargs: None
    instance._Default__client = None
    instance._Default__client_lock = threading.Lock()
    return instance


def test_native_xrootd_requires_high_level_client(monkeypatch):
    monkeypatch.setattr(xrootd, '_xrootd_client', SimpleNamespace())

    with pytest.raises(exception.MissingDependency, match='StorageClient'):
        xrootd._client()


def test_xrootd_url_operations_do_not_require_optional_binding(monkeypatch):
    monkeypatch.setattr(xrootd, '_xrootd_client', None)

    root_protocol = _protocol()
    dav_protocol = _protocol(scheme='davs')

    assert root_protocol.path2pfn('/rucio/file') == \
        'root://storage.example:1094//rucio/file'
    assert dav_protocol.path2pfn('/rucio/file') == \
        'davs://storage.example:443/rucio/file'
    assert root_protocol.pfn2path(
        'root://storage.example:1094//rucio/file') == '//rucio/file'
    assert root_protocol.lfns2pfns({
        'scope': 'test', 'name': 'file', 'path': 'file',
    }) == {
        'test:file': 'root://storage.example:1094/rucio/file',
    }

    dav_protocol.attributes['prefix'] = '//rucio/'
    assert dav_protocol.lfns2pfns({
        'scope': 'test', 'name': 'file', 'path': 'file',
    }) == {
        'test:file': 'davs://storage.example:443//rucio/file',
    }


def test_native_xrootd_bearer_auth_is_object_scoped(monkeypatch):
    storage = MagicMock()
    bindings = _bindings(storage)
    monkeypatch.setattr(xrootd, '_xrootd_client', bindings)
    monkeypatch.setattr(
        xrootd.Default, '_configured_x509_proxy', staticmethod(lambda: None))
    before = {
        key: os.environ.get(key)
        for key in ('BEARER_TOKEN', 'BEARER_TOKEN_FILE', 'XrdSecPROTOCOL')
    }

    protocol = _protocol(auth_token='transfer-token')
    assert protocol._storage_client() is storage

    bindings.StorageClient.from_environment.assert_called_once_with(
        timeout=300,
        token='transfer-token',
        proxy=None,
        fallback='none',
        use_bearer_environment=False,
    )
    assert before == {
        key: os.environ.get(key)
        for key in ('BEARER_TOKEN', 'BEARER_TOKEN_FILE', 'XrdSecPROTOCOL')
    }


def test_native_xrootd_uses_selected_proxy(monkeypatch, tmp_path):
    proxy = tmp_path / 'proxy'
    proxy.write_text('credential')
    bindings = _bindings()
    monkeypatch.setattr(xrootd, '_xrootd_client', bindings)
    monkeypatch.setenv('RUCIO_CLIENT_PROXY', str(proxy))

    _protocol().prepare_credentials()

    bindings.StorageClient.from_environment.assert_called_once_with(
        timeout=300,
        token=None,
        proxy=str(proxy),
        fallback='none',
        use_bearer_environment=False,
    )


def test_native_webdav_can_be_explicitly_anonymous(monkeypatch):
    bindings = _bindings()
    monkeypatch.setattr(xrootd, '_xrootd_client', bindings)
    for variable in (
            'RUCIO_CLIENT_PROXY', 'XrdSecGSIUSERPROXY', 'X509_USER_PROXY',
            'XrdSecGSIUSERCERT', 'XrdSecGSIUSERKEY', 'X509_USER_CERT',
            'X509_USER_KEY'):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(xrootd.Default, '_configured_x509_proxy', staticmethod(lambda: None))

    _protocol(scheme='https').prepare_credentials()

    bindings.StorageClient.from_environment.assert_called_once_with(
        timeout=300,
        token=None,
        proxy=None,
        fallback='anonymous',
        use_bearer_environment=False,
    )


def test_native_operations_delegate_to_storage_client(monkeypatch, tmp_path):
    storage = MagicMock()
    storage.exists.return_value = True
    bindings = _bindings(storage)
    monkeypatch.setattr(xrootd, '_xrootd_client', bindings)
    source = tmp_path / 'source'
    source.write_bytes(b'data')
    protocol = _protocol(auth_token='token')

    assert protocol.exists('/rucio/file')
    protocol.get('/rucio/file', str(tmp_path / 'target'), transfer_timeout='17')
    protocol.put(source.name, '/rucio/uploaded', str(tmp_path), transfer_timeout='19')
    protocol.rename('/rucio/uploaded', '/rucio/final')
    protocol.delete('/rucio/final')

    remote = 'root://storage.example:1094//rucio/file'
    storage.exists.assert_called_once_with(remote)
    storage.get.assert_called_once_with(
        remote, str(tmp_path / 'target'), timeout=17, force=True)
    storage.put.assert_called_once_with(
        str(source.resolve()),
        'root://storage.example:1094//rucio/uploaded',
        timeout=19, force=True, create_parents=True)
    storage.move.assert_called_once_with(
        'root://storage.example:1094//rucio/uploaded',
        'root://storage.example:1094//rucio/final',
        create_parents=True)
    storage.delete.assert_called_once_with(
        'root://storage.example:1094//rucio/final')


def test_native_stat_uses_supported_checksum_fallback(monkeypatch):
    storage = MagicMock()
    storage.info.return_value = SimpleNamespace(
        size=1234,
        checksum=SimpleNamespace(algorithm='md5', value='deadbeef'),
    )
    monkeypatch.setattr(xrootd, '_xrootd_client', _bindings(storage))

    result = _protocol(auth_token='token').stat('/rucio/file')

    assert result == {'filesize': '1234', 'md5': 'deadbeef'}
    storage.info.assert_called_once_with(
        'root://storage.example:1094//rucio/file',
        checksum_algorithms=[PREFERRED_CHECKSUM] + [
            algorithm for algorithm in GLOBALLY_SUPPORTED_CHECKSUMS
            if algorithm != PREFERRED_CHECKSUM],
        require_checksum=True,
    )


def test_native_stat_can_skip_checksum(monkeypatch):
    storage = MagicMock()
    storage.info.return_value = SimpleNamespace(size=1234, checksum=None)
    monkeypatch.setattr(xrootd, '_xrootd_client', _bindings(storage))

    result = _protocol(auth_token='token', verify_checksum=False).stat('/rucio/file')

    assert result == {'filesize': '1234'}
    storage.info.assert_called_once_with(
        'root://storage.example:1094//rucio/file',
        checksum_algorithms=(),
        require_checksum=False,
    )


@pytest.mark.parametrize('native_error,rucio_error,kwargs', [
    (_NotFound('missing'), exception.SourceNotFound, {'source_not_found': True}),
    (_Authorization('denied'), exception.RSEAccessDenied, {}),
    (_Checksum('bad checksum'), exception.RSEChecksumUnavailable, {}),
    (_AlreadyExists('exists'), exception.DestinationNotAccessible, {'destination': True}),
    (_Timeout('expired'), exception.ServiceUnavailable, {}),
])
def test_native_errors_use_rucio_exception_contract(
        monkeypatch, native_error, rucio_error, kwargs):
    monkeypatch.setattr(xrootd, '_xrootd_client', _bindings())

    with pytest.raises(rucio_error):
        _protocol()._translate_error(native_error, **kwargs)


def test_native_client_is_initialized_once_across_threads(monkeypatch):
    storage = MagicMock()
    bindings = _bindings(storage)
    monkeypatch.setattr(xrootd, '_xrootd_client', bindings)
    protocol = _protocol(auth_token='token')

    with ThreadPoolExecutor(max_workers=8) as executor:
        clients = list(executor.map(lambda _: protocol._storage_client(), range(32)))

    assert all(client is storage for client in clients)
    bindings.StorageClient.from_environment.assert_called_once()


def test_native_close_releases_storage_client(monkeypatch):
    bindings = _bindings()
    monkeypatch.setattr(xrootd, '_xrootd_client', bindings)
    protocol = _protocol(auth_token='token')
    protocol.prepare_credentials()

    protocol.close()

    bindings.StorageClient.from_environment.return_value.close.assert_called_once()


def test_native_connect_performs_bounded_probe(monkeypatch):
    storage = MagicMock()
    monkeypatch.setattr(xrootd, '_xrootd_client', _bindings(storage))

    _protocol(auth_token='token').connect()

    storage.probe.assert_called_once_with(
        'root://storage.example:1094//rucio/', timeout=10)


def test_native_space_usage_uses_high_level_query(monkeypatch):
    storage = MagicMock()
    storage.space.return_value = {'total': 100, 'free': 75, 'used': 25}
    monkeypatch.setattr(xrootd, '_xrootd_client', _bindings(storage))

    assert _protocol(auth_token='token').get_space_usage() == (100, 75)

    storage.space.assert_called_once_with(
        'root://storage.example:1094//rucio/')


@pytest.mark.noparallel(reason='creates and removes a test directory with a fixed name')
@skip_rse_tests_with_accounts
class TestRseXROOTD(MgrTestCases):

    @classmethod
    @pytest.fixture(scope='class')
    def setup_rse_and_files(cls, vo, tmp_path_factory):
        """XROOTD (RSE/PROTOCOLS): Creating necessary directories and files."""
        cmd = "rucio list-rses --rses 'test_container_xrd=True'"
        exitcode, out, err = execute(cmd)
        print(out, err)
        rses = out.split()

        data = load_test_conf_file('rse_repository.json')
        prefix = data['WJ-XROOTD']['protocols']['supported']['xroot']['prefix']

        if len(rses) == 0:
            rse_name = 'WJ-XROOTD'
            hostname = data['WJ-XROOTD']['protocols']['supported']['xroot']['hostname']
        else:
            rse_name = 'XRD1'
            hostname = 'xrd1'
            prefix = '/rucio/'

        try:
            os.mkdir(prefix)
        except Exception as error:
            print(error)

        rse_settings, tmpdir, user = cls.setup_common_test_env(
            rse_name, vo, tmp_path_factory)

        protocol_instance = rsemanager.create_protocol(rse_settings, 'write')
        try:
            protocol_instance.connect()
            os.system('dd if=/dev/urandom of=%s/data.raw bs=1024 count=1024' % prefix)

            for filename in cls.files_remote:
                path = protocol_instance.path2pfn(
                    prefix + protocol_instance._get_path('user.%s' % user, filename))
                execute('xrdcp %s/data.raw %s' % (prefix, path))

            for filename in MgrTestCases.files_local_and_remote:
                path = protocol_instance.path2pfn(
                    prefix + protocol_instance._get_path('user.%s' % user, filename))
                execute('xrdcp %s/%s %s' % (tmpdir, filename, path))
        finally:
            protocol_instance.close()

        yield rse_settings, tmpdir, user

        clean_files = str(execute(
            'xrdfs %s ls %s/user.%s' % (hostname, prefix, user))[1]).split('\n')
        clean_files += str(execute(
            'xrdfs %s ls %s/group.%s' % (hostname, prefix, user))[1]).split('\n')
        clean_files.append('%s/data.raw' % prefix)
        for filename in clean_files:
            execute('xrdfs %s rm %s' % (hostname, filename))

        clean_directories = str(execute(
            'xrdfs %s ls %s' % (hostname, prefix))[1]).split('\n')
        clean_directories.append(prefix)
        for directory in clean_directories:
            execute('xrdfs %s rmdir %s' % (hostname, directory))

    @pytest.fixture(autouse=True)
    def setup_obj(self, setup_rse_and_files, vo):
        rse_settings, tmpdir, user = setup_rse_and_files
        self.init(tmpdir=tmpdir, rse_settings=rse_settings, user=user, vo=vo)

    def test_delete_mgr_ok_dir(self):
        raise pytest.skip('Not implemented')
