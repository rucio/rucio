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
import os
import shutil
import tempfile
from pathlib import Path
from random import choice
from string import ascii_uppercase

from rucio.client.client import Client
from rucio.client.uploadclient import UploadClient
from rucio.common.schema import get_schema_value
from rucio.common.types import InternalScope
from rucio.common.utils import execute, generate_uuid
from rucio.core import rse as rse_core
from rucio.db.sqla import models
from rucio.db.sqla.session import transactional_session
from rucio.tests.common import did_name_generator
from rucio.tests.common_server import cleanup_db_deps
from sqlalchemy import and_, or_, delete


class TemporaryRSEFactory:
    """
    Factory which keeps track of created RSEs and cleans up everything related to these RSEs at the end
    """

    def __init__(self, vo, name_prefix, **kwargs):
        self.vo = vo
        self.name_prefix = name_prefix.upper().replace('_', '-')
        self.created_rses = set()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def cleanup(self):
        if not self.created_rses:
            return

        self._cleanup_db_deps()

    @transactional_session
    def _cleanup_db_deps(self, session=None):
        cleanup_db_deps(
            model=models.RSE,
            select_rows_stmt=models.RSE.id.in_(self.created_rses),
            session=session,
        )

    def _cleanup_rses(self):
        for rse_id in self.created_rses:
            # Only archive RSE instead of deleting. Account handling code doesn't expect RSEs to ever be deleted.
            # So running test in parallel results in some tests failing on foreign key errors.
            rse_core.del_rse(rse_id)

    def _make_rse(self, scheme, protocol_impl, parameters=None, add_rse_kwargs=None):
        rse_name = self.name_prefix + ''.join(choice(ascii_uppercase) for _ in range(6))
        if add_rse_kwargs and 'vo' in add_rse_kwargs:
            rse_id = rse_core.add_rse(rse_name, **add_rse_kwargs)
        else:
            rse_id = rse_core.add_rse(rse_name, vo=self.vo, **(add_rse_kwargs or {}))
        if scheme and protocol_impl:
            prefix = '/test_%s/' % rse_id
            if protocol_impl == 'rucio.rse.protocols.posix.Default':
                prefix = '/tmp/rucio_rse/test_%s/' % rse_id
            protocol_parameters = {
                'scheme': scheme,
                'hostname': '%s.cern.ch' % rse_id,
                'port': 0,
                'prefix': prefix,
                'impl': protocol_impl,
                'domains': {
                    'wan': {
                        'read': 1,
                        'write': 1,
                        'delete': 1,
                        'third_party_copy_read': 1,
                        'third_party_copy_write': 1,
                    },
                    'lan': {
                        'read': 1,
                        'write': 1,
                        'delete': 1,
                    }
                }
            }
            protocol_parameters.update(parameters or {})
            rse_core.add_protocol(rse_id=rse_id, parameter=protocol_parameters)
        self.created_rses.add(rse_id)
        return rse_name, rse_id

    def make_rse(self, scheme=None, protocol_impl=None, **kwargs):
        return self._make_rse(scheme=scheme, protocol_impl=protocol_impl, add_rse_kwargs=kwargs)

    def make_posix_rse(self, **kwargs):
        return self._make_rse(scheme='file', protocol_impl='rucio.rse.protocols.posix.Default', add_rse_kwargs=kwargs)

    def make_mock_rse(self, **kwargs):
        return self._make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.mock.Default', add_rse_kwargs=kwargs)

    def make_xroot_rse(self, **kwargs):
        return self._make_rse(scheme='root', protocol_impl='rucio.rse.protocols.xrootd.Default', add_rse_kwargs=kwargs)

    def make_srm_rse(self, **kwargs):
        parameters = {
            "extended_attributes": {"web_service_path": "/srm/managerv2?SFN=", "space_token": "RUCIODISK"},
        }
        return self._make_rse(scheme='srm', protocol_impl='rucio.rse.protocols.srm.Default', parameters=parameters, add_rse_kwargs=kwargs)


class TemporaryDidFactory:
    """
    Factory which keeps track of created dids and cleans up everything related to these dids at the end.
    All files related to the same test will have the same uuid in the name for easier debugging.
    """

    def __init__(self, default_scope, vo, name_prefix, file_factory):
        self.default_scope = default_scope
        self.vo = vo
        self.name_prefix = name_prefix
        self.file_factory = file_factory

        self._client = None
        self._upload_client = None

        self.created_dids = set()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    @property
    def client(self):
        if not self._client:
            self._client = Client(vo=self.vo)
        return self._client

    @property
    def upload_client(self):
        if not self._upload_client:
            self._upload_client = UploadClient(self.client)
        return self._upload_client

    @transactional_session
    def cleanup(self, session=None):
        if not self.created_dids:
            return

        select_dids_stmt = or_(and_(models.DataIdentifier.scope == scope,
                                    models.DataIdentifier.name == name)
                               for scope, name in self.created_dids)
        cleanup_db_deps(
            model=models.DataIdentifier,
            select_rows_stmt=select_dids_stmt,
            session=session,
        )

        stmt = delete(
            models.DataIdentifier
        ).where(
            select_dids_stmt
        ).execution_options(
            synchronize_session=False
        )
        session.execute(stmt)

    def register_dids(self, dids):
        """
        Register the provided dids to be cleaned up on teardown
        """
        self.created_dids.update((did['scope'], did['name']) for did in dids)

    def _sanitize_or_set_scope(self, scope):
        if not scope:
            scope = self.default_scope
        elif isinstance(scope, str):
            scope = InternalScope(scope, vo=self.vo)
        return scope

    def _random_did(self, did_type, scope, name_suffix=''):
        scope = self._sanitize_or_set_scope(scope)
        name = did_name_generator(did_type=did_type, name_prefix=self.name_prefix, name_suffix=name_suffix)
        did = {'scope': scope, 'name': name}
        self.created_dids.add((scope, name))
        return did

    def random_file_did(self, scope=None, name_suffix=''):
        did = self._random_did(did_type='file', scope=scope, name_suffix=name_suffix)
        return did

    def random_dataset_did(self, scope=None):
        did = self._random_did(did_type='dataset', scope=scope)
        return did

    def random_container_did(self, scope=None):
        did = self._random_did(did_type='container', scope=scope)
        return did

    def make_dataset(self, scope=None):
        did = self.random_dataset_did(scope=scope)
        self.client.add_dataset(scope=did['scope'].external, name=did['name'])
        return did

    def make_container(self, scope=None):
        did = self.random_container_did(scope=scope)
        self.client.add_container(scope=did['scope'].external, name=did['name'])
        return did

    def upload_test_file(self, rse_name, scope=None, name=None, path=None, size=2, return_full_item=False):
        scope = self._sanitize_or_set_scope(scope)
        if not path:
            path = self.file_factory.file_generator(size=size)
        if not name:
            name = did_name_generator('file')
        item = {
            'path': path,
            'rse': rse_name,
            'did_scope': str(scope),
            'did_name': name,
            'guid': generate_uuid(),
        }
        activity = get_schema_value('ACTIVITY')['enum'][0]
        self.upload_client.upload([item], activity=activity)
        did = {'scope': scope, 'name': name}
        self.created_dids.add((scope, name))
        return item if return_full_item else did

    def upload_test_dataset(self, rse_name, scope=None, size=2, nb_files=2):
        scope = self._sanitize_or_set_scope(scope)
        dataset = self.make_dataset(scope=scope)
        self.created_dids.add((scope, dataset['name']))
        items = list()
        for _ in range(0, nb_files):
            # TODO : Call did_name_generator
            path = self.file_factory.file_generator(size=size)
            name = did_name_generator('file')
            items.append({
                         'path': path,
                         'rse': rse_name,
                         'dataset_scope': str(scope),
                         'dataset_name': dataset['name'],
                         'did_scope': str(scope),
                         'did_name': name,
                         'guid': generate_uuid(),
                         })
            self.created_dids.add((scope, name))
        self.upload_client.upload(items)
        return items


class TemporaryFileFactory:
    """
    Factory which keeps track of creation and cleanup of created local test files and directories.
    If initialized with tmp_path_factory fixture, the basedir is managed by pytest.
    Otherwise, the basedir is handled by this factory itself.
    """

    def __init__(self, pytest_path_factory=None) -> None:
        self.pytest_path_factory = pytest_path_factory
        self.base_uuid = generate_uuid()
        self._base_dir = None
        self.non_basedir_files = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.pytest_path_factory is None:
            shutil.rmtree(self.base_dir)
        self.cleanup()

    @property
    def base_dir(self):
        if not self._base_dir:
            if self.pytest_path_factory is not None:
                self._base_dir = self.pytest_path_factory.mktemp(basename=self.base_uuid, numbered=True)
            else:
                tmp_dir = tempfile.mkdtemp(prefix=self.base_uuid)
                self._base_dir = Path(tmp_dir)

        return self._base_dir

    def _make_temp_file(self, data, size, namelen, use_basedir, path):
        fn = ''.join(choice(ascii_uppercase) for x in range(namelen))
        if use_basedir:
            fp = self.base_dir / path / fn if path is not None else self.base_dir / fn
        else:
            fp = Path(tempfile.gettempdir()) / path / fn if path is not None else Path(tempfile.gettempdir()) / fn
            self.non_basedir_files.append(fp)

        if data is not None:
            with open(fp, 'w', encoding='utf-8') as f:
                f.write(data)
        else:
            execute('dd if=/dev/urandom of={0} count={1} bs=1'.format(fp, size))

        return fp

    def _make_temp_folder(self, namelen, use_basedir, path):
        fn = ''.join(choice(ascii_uppercase) for x in range(namelen))
        if use_basedir:
            fp = self.base_dir / path / fn if path is not None else self.base_dir / fn
        else:
            fp = Path(tempfile.gettempdir()) / path / fn if path is not None else Path(tempfile.gettempdir()) / fn
            self.non_basedir_files.append(fp)

        os.makedirs(fp, exist_ok=True)

        return fp

    def file_generator(self, data=None, size=2, namelen=10, use_basedir=False, path=None):
        """
        Creates a temporary file
        :param data        : The content to be written in the file. If provided, the size parameter is ignored.
        :param size        : The size of random bytes to be written in the file
        :param namelen     : The length of filename
        :param use_basedir : If True, the file is created under the base_dir for this TemporaryFileFactory instance.
        :param path        : Relative path of the file, can be under basedir (if use_basedir True) or from the temp dir
        :returns: The absolute path of the generated file
        """
        return self._make_temp_file(data, size, namelen, use_basedir, path)

    def folder_generator(self, namelen=10, use_basedir=False, path=None):
        """
        Creates an empty temporary folder
        :param namelen     : The length of folder. Only used if path is None.
        :param use_basedir : If True, the folder is created under the base_dir for this TemporaryFileFactory instance.
        :param path        : Relative path of the folder, can be under basedir (if use_basedir True).
        :returns: The absolute path of the generated folder
        """
        return self._make_temp_folder(namelen, use_basedir, path)

    def cleanup(self):
        for fp in self.non_basedir_files:
            if os.path.isfile(fp):
                os.remove(fp)
