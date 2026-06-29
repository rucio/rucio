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
from contextlib import nullcontext

import pytest

from rucio.common.utils import execute
from rucio.rse import rsemanager
from rucio.rse.protocols import xrootd
from rucio.tests.common import load_test_conf_file, skip_rse_tests_with_accounts

from .rsemgr_api_test import MgrTestCases


class _Status:
    def __init__(self, ok=True, message=''):
        self.ok = ok
        self.message = message


class _StatInfo:
    size = 1234


class _QueryCode:
    CHECKSUM = 'checksum'


class _MkDirFlags:
    MAKEPATH = 'makepath'


class _Flags:
    QueryCode = _QueryCode
    MkDirFlags = _MkDirFlags


class _FileSystem:
    def __init__(self):
        self.renamed = False

    def stat(self, path):
        return _Status(), _StatInfo()

    def query(self, query_code, path):
        return _Status(), b'adler32 deadbeef\n\0'

    def mkdir(self, path, flags):
        return _Status(ok=False, message='[ERROR] Unable to mkdir {}; file exists'.format(path)), None

    def mv(self, path, new_path):
        self.renamed = True
        return _Status(), None


class _XRootDClient:
    def __init__(self, version='6.0.0'):
        self.__version__ = version
        self.env = []

    def EnvPutString(self, key, value):  # noqa: N802 - match XRootD client API
        self.env.append((key, value))


def test_native_xrootd_requires_version_6_or_newer():
    assert not xrootd._is_supported_xrootd_version(_XRootDClient('5.8.4'))
    assert xrootd._is_supported_xrootd_version(_XRootDClient('6.0.0'))
    assert xrootd._is_supported_xrootd_version(_XRootDClient('6.0.3'))
    assert xrootd._is_supported_xrootd_version(_XRootDClient('6.1.0'))
    assert xrootd._is_supported_xrootd_version(_XRootDClient('v6.1.0'))


def test_native_xrootd_clears_unexpanded_proxy_from_env(monkeypatch):
    protocol = xrootd.Default.__new__(xrootd.Default)

    monkeypatch.setenv('X509_USER_PROXY', '$RUCIO_CLIENT_PROXY')

    protocol._clear_unexpanded_x509_proxy()

    assert 'X509_USER_PROXY' not in os.environ


def test_native_xrootd_operation_restores_auth_environment(monkeypatch):
    client = _XRootDClient()
    protocol = xrootd.Default.__new__(xrootd.Default)
    protocol.auth_token = 'new-token'

    monkeypatch.setattr(xrootd, '_xrootd_client', client)
    monkeypatch.setenv('XrdSecPROTOCOL', 'gsi')
    monkeypatch.setenv('BEARER_TOKEN', 'old-token')
    monkeypatch.delenv('X509_USER_PROXY', raising=False)

    with protocol._xrootd_operation():
        assert os.environ['XrdSecPROTOCOL'] == 'ztn'
        assert os.environ['BEARER_TOKEN'] == 'new-token'

    assert os.environ['XrdSecPROTOCOL'] == 'gsi'
    assert os.environ['BEARER_TOKEN'] == 'old-token'
    assert 'X509_USER_PROXY' not in os.environ
    assert ('XrdSecPROTOCOL', 'gsi') in client.env
    assert ('BEARER_TOKEN', 'old-token') in client.env
    assert ('X509_USER_PROXY', '') in client.env


def test_native_xrootd_stat_accepts_bytes_checksum(monkeypatch):
    protocol = xrootd.Default.__new__(xrootd.Default)
    protocol.logger = lambda *args, **kwargs: None
    protocol.rse = {'verify_checksum': True}
    protocol._filesystem = lambda: _FileSystem()
    protocol._xrootd_operation = nullcontext

    monkeypatch.setattr(xrootd, '_xrootd_flags', _Flags)

    assert protocol.stat('/tmp/file') == {'filesize': '1234', 'adler32': 'deadbeef'}


def test_native_xrootd_rename_ignores_existing_directory(monkeypatch):
    fs = _FileSystem()
    protocol = xrootd.Default.__new__(xrootd.Default)
    protocol.logger = lambda *args, **kwargs: None
    protocol._filesystem = lambda: fs
    protocol._xrootd_operation = nullcontext
    protocol.exists = lambda pfn: True
    protocol.pfn2path = lambda pfn: pfn

    monkeypatch.setattr(xrootd, '_xrootd_flags', _Flags)

    protocol.rename('/tmp/file.rucio.upload', '/tmp/file')

    assert fs.renamed


@pytest.mark.noparallel(reason='creates and removes a test directory with a fixed name')
@skip_rse_tests_with_accounts
class TestRseXROOTD(MgrTestCases):

    @classmethod
    @pytest.fixture(scope='class')
    def setup_rse_and_files(cls, vo, tmp_path_factory):
        """XROOTD (RSE/PROTOCOLS): Creating necessary directories and files """

        cmd = "rucio list-rses --rses 'test_container_xrd=True'"
        print(cmd)
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
        except Exception as e:
            print(e)

        rse_settings, tmpdir, user = cls.setup_common_test_env(rse_name, vo, tmp_path_factory)

        protocol = rsemanager.create_protocol(rse_settings, 'write')
        protocol.connect()

        os.system('dd if=/dev/urandom of=%s/data.raw bs=1024 count=1024' % prefix)

        for f in cls.files_remote:
            path = protocol.path2pfn(prefix + protocol._get_path('user.%s' % user, f))
            cmd = 'xrdcp %s/data.raw %s' % (prefix, path)
            execute(cmd)

        for f in MgrTestCases.files_local_and_remote:
            path = protocol.path2pfn(prefix + protocol._get_path('user.%s' % user, f))
            cmd = 'xrdcp %s/%s %s' % (tmpdir, f, path)
            execute(cmd)

        yield rse_settings, tmpdir, user

        clean_raw = '%s/data.raw' % prefix
        list_files_cmd_user = 'xrdfs %s ls %s/user.%s' % (hostname, prefix, user)
        clean_files = str(execute(list_files_cmd_user)[1]).split('\n')
        list_files_cmd_group = 'xrdfs %s ls %s/group.%s' % (hostname, prefix, user)
        clean_files += str(execute(list_files_cmd_group)[1]).split('\n')
        clean_files.append(clean_raw)
        for files in clean_files:
            clean_cmd = 'xrdfs %s rm %s' % (hostname, files)
            execute(clean_cmd)

        clean_prefix = '%s' % prefix
        list_directory = 'xrdfs %s ls %s' % (hostname, prefix)
        clean_directory = str(execute(list_directory)[1]).split('\n')
        clean_directory.append(clean_prefix)
        for directory in clean_directory:
            clean_cmd = 'xrdfs %s rmdir %s' % (hostname, directory)
            execute(clean_cmd)

    @pytest.fixture(autouse=True)
    def setup_obj(self, setup_rse_and_files, vo):
        rse_settings, tmpdir, user = setup_rse_and_files
        self.init(tmpdir=tmpdir, rse_settings=rse_settings, user=user, vo=vo)

    def test_delete_mgr_ok_dir(self):
        raise pytest.skip("Not implemented")
