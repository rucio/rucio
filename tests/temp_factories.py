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
from typing import TYPE_CHECKING, Any, Literal, Optional, TypedDict, Union, overload

from sqlalchemy import and_, delete, or_

from rucio.client.client import Client
from rucio.client.uploadclient import UploadClient
from rucio.common.exception import UnsupportedOperation
from rucio.common.types import DIDDict, FileToUploadDict, InternalAccount, InternalScope, PathTypeAlias
from rucio.common.utils import execute, generate_uuid
from rucio.core import did as did_core
from rucio.core import rse as rse_core
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType
from rucio.db.sqla.session import transactional_session
from rucio.tests.common import did_name_generator
from rucio.tests.common_server import cleanup_db_deps

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pytest import TempPathFactory
    from sqlalchemy.orm.session import Session

    class ToExternalDict(TypedDict):
        scope: Optional[str]
        name: str


def _to_external(did: DIDDict) -> "ToExternalDict":
    return {'scope': did['scope'].external, 'name': did['name']}


class TemporaryRSEFactory:
    """
    Factory which keeps track of created RSEs and cleans up everything related to these RSEs at the end
    """

    def __init__(
            self,
            vo: str,
            name_prefix: str,
            db_session: Optional["Session"] = None,
            **kwargs
    ):
        self.vo = vo
        self.name_prefix = name_prefix.upper().replace('_', '-')
        self.created_rses = set()
        self.db_session = db_session

        self.client_mode = False
        if os.environ.get("SUITE") == 'client':
            self.client_mode = True
            self.client = Client(vo=self.vo)

    def __enter__(self) -> "TemporaryRSEFactory":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def cleanup(self, session: Optional["Session"] = None) -> None:
        if not self.created_rses:
            return

        if not self.client_mode:
            self._cleanup_db_deps(session=session or self.db_session)
        else:
            self._clean_client()

    def _clean_client(self) -> None:
        for rse in self.created_rses:
            self.client.delete_rse(rse)

    @transactional_session
    def _cleanup_db_deps(
        self,
        *,
        session: Optional["Session"] = None
    ) -> None:
        cleanup_db_deps(
            model=models.RSE,
            select_rows_stmt=models.RSE.id.in_(self.created_rses),
            session=session,
        )

    def _cleanup_rses(self) -> None:
        for rse_id in self.created_rses:
            # Only archive RSE instead of deleting. Account handling code doesn't expect RSEs to ever be deleted.
            # So running test in parallel results in some tests failing on foreign key errors.
            rse_core.del_rse(rse_id)

    def _make_rse_client(
            self,
            rse_name: str,
            scheme: Optional[str],
            protocol_impl: Optional[str],
            parameters: Optional[dict[str, Any]] = None,
            add_rse_kwargs: Optional[dict[str, Any]] = None,
    ) -> str:

        # Uses the RSE Client instead of RSE Core - only to be used on client only test suite
        self.client.add_rse(
            rse=rse_name,
            **(add_rse_kwargs or {})
        )
        rse_id = self.client.get_rse(rse=rse_name)['id']

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
            if scheme == 'srm':
                protocol_parameters["extended_attributes"] = {"web_service_path": "/srm/managerv2?SFN=", "space_token": "RUCIODISK"}
            protocol_parameters.update(parameters or {})

            self.client.add_protocol(
                rse_name,
                params=protocol_parameters
            )
        return rse_id

    def _make_rse(
            self,
            scheme: Optional[str],
            protocol_impl: Optional[str],
            parameters: Optional[dict[str, Any]] = None,
            add_rse_kwargs: Optional[dict[str, Any]] = None,
            session: Optional["Session"] = None
    ) -> tuple[str, str]:
        session = session or self.db_session
        rse_name = self.name_prefix + ''.join(choice(ascii_uppercase) for _ in range(6))

        if self.client_mode:
            return rse_name, self._make_rse_client(rse_name, scheme, protocol_impl, parameters, add_rse_kwargs)

        if add_rse_kwargs and 'vo' in add_rse_kwargs:
            rse_id = rse_core.add_rse(rse_name, session=session, **add_rse_kwargs)
        else:
            rse_id = rse_core.add_rse(rse_name, vo=self.vo, session=session, **(add_rse_kwargs or {}))
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
            if scheme == 'srm':
                protocol_parameters["extended_attributes"] = {"web_service_path": "/srm/managerv2?SFN=", "space_token": "RUCIODISK"}
            protocol_parameters.update(parameters or {})
            rse_core.add_protocol(rse_id=rse_id, parameter=protocol_parameters, session=session)
        self.created_rses.add(rse_id)
        return rse_name, rse_id

    def make_rse(
            self,
            scheme: Optional[str] = None,
            protocol_impl: Optional[str] = None,
            **kwargs
    ) -> tuple[str, str]:
        return self._make_rse(scheme=scheme, protocol_impl=protocol_impl, add_rse_kwargs=kwargs)

    def make_posix_rse(
            self,
            session: Optional["Session"] = None,
            **kwargs
    ) -> tuple[str, str]:
        return self._make_rse(scheme='file', protocol_impl='rucio.rse.protocols.posix.Default', add_rse_kwargs=kwargs, session=session)

    def make_mock_rse(
            self,
            session: Optional["Session"] = None,
            **kwargs
    ) -> tuple[str, str]:
        return self._make_rse(scheme='mock', protocol_impl='rucio.rse.protocols.mock.Default', add_rse_kwargs=kwargs, session=session)

    def make_xroot_rse(
            self,
            session: Optional["Session"] = None,
            **kwargs
    ) -> tuple[str, str]:
        return self._make_rse(scheme='root', protocol_impl='rucio.rse.protocols.xrootd.Default', add_rse_kwargs=kwargs, session=session)

    def make_srm_rse(
            self,
            session: Optional["Session"] = None,
            **kwargs
    ) -> tuple[str, str]:
        parameters = {
            "extended_attributes": {"web_service_path": "/srm/managerv2?SFN=", "space_token": "RUCIODISK"},
        }
        return self._make_rse(scheme='srm', protocol_impl='rucio.rse.protocols.srm.Default', parameters=parameters, add_rse_kwargs=kwargs, session=session)


class TemporaryDidFactory:
    """
    Factory which keeps track of created DIDs and cleans up everything related to these DIDs at the end.
    All files related to the same test will have the same uuid in the name for easier debugging.
    """

    def __init__(
            self,
            default_scope: InternalScope,
            vo: str,
            name_prefix: str,
            file_factory: "TemporaryFileFactory",
            default_account: InternalAccount,
            db_session: Optional["Session"] = None
    ):
        self.default_account = default_account
        self.default_scope = default_scope
        self.vo = vo
        self.name_prefix = name_prefix
        self.file_factory = file_factory
        self.db_session = db_session

        self._client = None
        self._upload_client = None

        self.created_dids = set()
        self.client_mode = False
        if os.environ.get("SUITE") == 'client':
            self.client_mode = True

    def __enter__(self) -> "TemporaryDidFactory":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    @property
    def upload_client(self) -> UploadClient:
        if not self._upload_client:
            client = Client(vo=self.vo)
            self._upload_client = UploadClient(client)
        return self._upload_client

    @property
    def client(self) -> Client:
        if not self._client:
            self._client = Client(vo=self.vo)
        return self._client

    def cleanup(
            self,
            session: Optional["Session"] = None
    ) -> None:
        if not self.created_dids:
            return

        if not self.client_mode:
            self._cleanup_db_deps(session=session or self.db_session)
        else:
            self._cleanup_client()

    def _cleanup_client(self) -> None:
        for scope, name in self.created_dids:
            if isinstance(scope, InternalScope):
                scope = scope.external
            # Remove rules associated with the dids
            for rule in self.client.list_associated_rules_for_file(scope=scope, name=name):

                def remove_rules(rule_id: str) -> None:
                    try:
                        self.client.delete_replication_rule(rule_id=rule_id, purge_replicas=True)
                    except UnsupportedOperation:
                        # The rule has a child rule so we cannot delete it
                        rule_info = self.client.get_replication_rule(rule['id'])
                        child_rule = rule_info['child_rule_id']
                        # Try to remove the child rules recursively
                        remove_rules(child_rule)

                remove_rules(rule['id'])

        # Then run the undertaker
        execute('rucio-undertaker --run-once')

    @transactional_session
    def _cleanup_db_deps(
        self,
        *,
        session: Optional["Session"] = None
    ) -> None:
        select_dids_stmt = or_(and_(models.DataIdentifier.scope == scope,  # type: ignore
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
        session.execute(stmt)  # type: ignore (Session could be None)

    def register_dids(
            self,
            dids: "Iterable[DIDDict]"
    ) -> None:
        """
        Register the provided DIDs to be cleaned up on teardown
        """
        self.created_dids.update((did['scope'], did['name']) for did in dids)

    def _sanitize_or_set_scope(
            self,
            scope: Optional[Union[str, InternalScope]]
    ) -> InternalScope:
        if not scope:
            scope = self.default_scope
        elif isinstance(scope, str):
            scope = InternalScope(scope, vo=self.vo)
        return scope

    def _random_did(
            self,
            did_type: str,
            scope: Optional[Union[str, InternalScope]],
            name_suffix: str = ''
    ) -> DIDDict:
        scope = self._sanitize_or_set_scope(scope)
        name = did_name_generator(did_type=did_type, name_prefix=self.name_prefix, name_suffix=name_suffix)
        did: DIDDict = {'scope': scope, 'name': name}
        self.created_dids.add((scope, name))
        return did

    @overload
    def random_file_did(
            self,
            scope: Optional[Union[str, InternalScope]] = None,
            name_suffix: str = '',
            *,
            external: Literal[True]
    ) -> "ToExternalDict":
        ...

    @overload
    def random_file_did(
            self,
            scope: Optional[Union[str, InternalScope]] = None,
            name_suffix: str = '',
            *,
            external: Literal[False] = False
    ) -> DIDDict:
        ...

    def random_file_did(
            self,
            scope: Optional[Union[str, InternalScope]] = None,
            name_suffix: str = '',
            *,
            external: bool = False
    ) -> Union[DIDDict, "ToExternalDict"]:
        did = self._random_did(did_type='file', scope=scope, name_suffix=name_suffix)
        return _to_external(did) if external else did

    @overload
    def random_dataset_did(
            self,
            scope: Optional[Union[str, InternalScope]] = None,
            *,
            external: Literal[True]
    ) -> "ToExternalDict":
        ...

    @overload
    def random_dataset_did(
            self,
            scope: Optional[Union[str, InternalScope]] = None,
            *,
            external: Literal[False] = False
    ) -> DIDDict:
        ...

    def random_dataset_did(
            self,
            scope: Optional[Union[str, InternalScope]] = None,
            *,
            external: bool = False
    ) -> Union[DIDDict, "ToExternalDict"]:
        did = self._random_did(did_type='dataset', scope=scope)
        return _to_external(did) if external else did

    @overload
    def random_container_did(
            self,
            scope: Optional[Union[str, InternalScope]] = None,
            *,
            external: Literal[True]
    ) -> "ToExternalDict":
        ...

    @overload
    def random_container_did(
            self,
            scope: Optional[Union[str, InternalScope]] = None,
            *,
            external: Literal[False] = False
    ) -> DIDDict:
        ...

    def random_container_did(
            self,
            scope: Optional[Union[str, InternalScope]] = None,
            *,
            external: bool = False
    ) -> Union[DIDDict, "ToExternalDict"]:
        did = self._random_did(did_type='container', scope=scope)
        return _to_external(did) if external else did

    @overload
    def make_dataset(
            self,
            scope: Optional[Union[str, InternalScope]] = None,
            account: Optional[InternalAccount] = None,
            session: Optional["Session"] = None,
            *,
            external: Literal[True]
    ) -> "ToExternalDict":
        ...

    @overload
    def make_dataset(
            self,
            scope: Optional[Union[str, InternalScope]] = None,
            account: Optional[InternalAccount] = None,
            session: Optional["Session"] = None,
            *,
            external: Literal[False] = False
    ) -> DIDDict:
        ...

    def _add_did(self, did: dict[str, Union[str, InternalScope]], did_type: DIDType, account: Optional[InternalAccount] = None, session: Optional["Session"] = None) -> None:
        if not self.client_mode:
            did_core.add_did(**did, did_type=did_type, account=account, session=session)

        else:
            scope = did['scope']
            if isinstance(scope, InternalScope):
                scope = scope.external
            name = did['name']
            self.client.add_did(scope, name, did_type=did_type,  lifetime=-1)  # Lifetime set to -1 so undertaker can delete it

    def make_dataset(
            self,
            scope: Optional[Union[str, InternalScope]] = None,
            account: Optional[InternalAccount] = None,
            session: Optional["Session"] = None,
            *,
            external: bool = False
    ) -> Union[DIDDict, "ToExternalDict"]:
        account = account or self.default_account
        session = session or self.db_session
        did = self.random_dataset_did(scope=scope)
        self._add_did(did, did_type=DIDType.DATASET, account=account, session=session)
        return _to_external(did) if external else did

    @overload
    def make_container(
            self,
            scope: Optional[Union[str, InternalScope]] = None,
            account: Optional[InternalAccount] = None,
            session: Optional["Session"] = None,
            *,
            external: Literal[True]
    ) -> "ToExternalDict":
        ...

    @overload
    def make_container(
            self,
            scope: Optional[Union[str, InternalScope]] = None,
            account: Optional[InternalAccount] = None,
            session: Optional["Session"] = None,
            *,
            external: Literal[False] = False
    ) -> DIDDict:
        ...

    def make_container(
            self,
            scope: Optional[Union[str, InternalScope]] = None,
            account: Optional[InternalAccount] = None,
            session: Optional["Session"] = None,
            *,
            external: bool = False
    ) -> Union[DIDDict, "ToExternalDict"]:
        account = account or self.default_account
        session = session or self.db_session
        did = self.random_container_did(scope=scope)
        self._add_did(did, did_type=DIDType.CONTAINER, account=account, session=session)
        return _to_external(did) if external else did

    @overload
    def upload_test_file(
            self,
            rse_name: str,
            *,
            return_full_item: Literal[True]
    ) -> FileToUploadDict:
        ...

    @overload
    def upload_test_file(
            self,
            rse_name: str,
            scope: Optional[Union[str, InternalScope]] = None,
            name: Optional[str] = None,
            path: Optional[PathTypeAlias] = None,
            size: int = 2,
            return_full_item: Literal[False] = False
    ) -> DIDDict:
        ...

    def upload_test_file(
            self,
            rse_name: str,
            scope: Optional[Union[str, InternalScope]] = None,
            name: Optional[str] = None,
            path: Optional[PathTypeAlias] = None,
            size: int = 2,
            return_full_item: bool = False
    ) -> Union[DIDDict, FileToUploadDict]:
        scope = self._sanitize_or_set_scope(scope)
        if not path:
            path = self.file_factory.file_generator(size=size)
        if not name:
            name = did_name_generator('file')
        item: FileToUploadDict = {
            'path': path,
            'rse': rse_name,
            'did_scope': str(scope),
            'did_name': name,
            'guid': generate_uuid(),
        }
        activity = "Staging"
        self.upload_client.upload(items=[item], activity=activity)
        did: DIDDict = {'scope': scope, 'name': name}
        self.created_dids.add((scope, name))
        return item if return_full_item else did

    def upload_test_dataset(
            self,
            rse_name: str,
            scope: Optional[Union[str, InternalScope]] = None,
            size: int = 2,
            nb_files: int = 2
    ) -> list[FileToUploadDict]:
        scope = self._sanitize_or_set_scope(scope)
        dataset = self.make_dataset(scope=scope)
        self.created_dids.add((scope, dataset['name']))
        items: list[FileToUploadDict] = list()
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
        self.upload_client.upload(items=items)
        return items


class TemporaryFileFactory:
    """
    Factory which keeps track of creation and cleanup of created local test files and directories.
    If initialized with tmp_path_factory fixture, the basedir is managed by pytest.
    Otherwise, the basedir is handled by this factory itself.
    """

    def __init__(
            self,
            pytest_path_factory: Optional["TempPathFactory"] = None
    ) -> None:
        self.pytest_path_factory = pytest_path_factory
        self.base_uuid = generate_uuid()
        self._base_dir: Optional[Path] = None
        self.non_basedir_files = []

    def __enter__(self) -> "TemporaryFileFactory":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.pytest_path_factory is None:
            shutil.rmtree(self.base_dir)
        self.cleanup()

    @property
    def base_dir(self) -> Path:
        if not self._base_dir:
            if self.pytest_path_factory is not None:
                self._base_dir = self.pytest_path_factory.mktemp(basename=self.base_uuid, numbered=True)
            else:
                tmp_dir = tempfile.mkdtemp(prefix=self.base_uuid)
                self._base_dir = Path(tmp_dir)

        return self._base_dir

    def _make_temp_file(
            self,
            data: Optional[str],
            size: int,
            namelen: int,
            use_basedir: bool,
            path: Optional[Path]
    ) -> Path:
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

    def _make_temp_folder(
            self,
            namelen: int,
            use_basedir: bool,
            path: Optional[Path]
    ) -> Path:
        fn = ''.join(choice(ascii_uppercase) for x in range(namelen))
        if use_basedir:
            fp = self.base_dir / path / fn if path is not None else self.base_dir / fn
        else:
            fp = Path(tempfile.gettempdir()) / path / fn if path is not None else Path(tempfile.gettempdir()) / fn
            self.non_basedir_files.append(fp)

        os.makedirs(fp, exist_ok=True)

        return fp

    def file_generator(
            self,
            data: Optional[str] = None,
            size: int = 2,
            namelen: int = 10,
            use_basedir: bool = False,
            path: Optional[Path] = None
    ) -> Path:
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

    def folder_generator(
            self,
            namelen: int = 10,
            use_basedir: bool = False,
            path: Optional[Path] = None
    ) -> Path:
        """
        Creates an empty temporary folder
        :param namelen     : The length of folder. Only used if path is None.
        :param use_basedir : If True, the folder is created under the base_dir for this TemporaryFileFactory instance.
        :param path        : Relative path of the folder, can be under basedir (if use_basedir True).
        :returns: The absolute path of the generated folder
        """
        return self._make_temp_folder(namelen, use_basedir, path)

    def cleanup(self) -> None:
        for fp in self.non_basedir_files:
            if os.path.isfile(fp):
                os.remove(fp)
