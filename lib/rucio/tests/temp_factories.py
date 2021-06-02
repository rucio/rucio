# -*- coding: utf-8 -*-
# Copyright 2021 CERN
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
#
# Authors:
# - Radu Carpa <radu.carpa@cern.ch>, 2021
# - Mayank Sharma <mayank.sharma@cern.ch>, 2021


import os
import shutil
import tempfile
from pathlib import Path
from random import choice
from string import ascii_uppercase

from rucio.client.client import Client
from rucio.client.uploadclient import UploadClient
from rucio.common.types import InternalScope
from rucio.common.utils import execute, generate_uuid
from rucio.core import replica as replica_core
from rucio.core import rse as rse_core
from rucio.core import rule as rule_core
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType
from rucio.db.sqla.session import transactional_session
from rucio.tests.common import file_generator, rse_name_generator
from six import PY3
from sqlalchemy import and_, or_


class TemporaryRSEFactory:
    """
    Factory which keeps track of created RSEs and cleans up everything related to these RSEs at the end
    """

    def __init__(self, vo, **kwargs):
        self.vo = vo

        self.created_rses = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    def cleanup(self):
        if not self.created_rses:
            return
        rules_to_remove = self.__get_rules_to_remove()
        self.__cleanup_transfers()
        self.__cleanup_locks_and_rules(rules_to_remove)
        self.__cleanup_replicas()
        self.__cleanup_rse_attributes()

    @transactional_session
    def __get_rules_to_remove(self, session=None):
        # Retrieve the list of rules to be cleaned up
        rules_from_requests = session.query(models.ReplicationRule.id). \
            join(models.Request, models.ReplicationRule.id == models.Request.rule_id). \
            filter(or_(models.Request.dest_rse_id.in_(self.created_rses),
                       models.Request.source_rse_id.in_(self.created_rses)))
        rules_from_locks = session.query(models.ReplicationRule.id). \
            join(models.ReplicaLock, models.ReplicationRule.id == models.ReplicaLock.rule_id). \
            filter(models.ReplicaLock.rse_id.in_(self.created_rses))
        return list(rules_from_requests.union(rules_from_locks).distinct())

    @transactional_session
    def __cleanup_transfers(self, session=None):
        # Cleanup Transfers
        session.query(models.Source).filter(or_(models.Source.dest_rse_id.in_(self.created_rses),
                                                models.Source.rse_id.in_(self.created_rses))).delete(synchronize_session=False)
        session.query(models.Request).filter(or_(models.Request.dest_rse_id.in_(self.created_rses),
                                                 models.Request.source_rse_id.in_(self.created_rses))).delete(synchronize_session=False)

    @transactional_session
    def __cleanup_locks_and_rules(self, rules_to_remove, session=None):
        for rule_id, in rules_to_remove:
            rule_core.delete_rule(rule_id, session=session, ignore_rule_lock=True)

    @transactional_session
    def __cleanup_replicas(self, session=None):
        # Cleanup Replicas and Parent Datasets
        query = session.query(models.RSEFileAssociation.scope, models.RSEFileAssociation.name, models.RSEFileAssociation.rse_id). \
            filter(models.RSEFileAssociation.rse_id.in_(self.created_rses))
        dids_by_rse = {}
        for scope, name, rse_id in query:
            dids_by_rse.setdefault(rse_id, []).append({'scope': scope, 'name': name})
        for rse_id, dids in dids_by_rse.items():
            replica_core.delete_replicas(rse_id=rse_id, files=dids, session=session)
        # Cleanup BadReplicas
        session.query(models.BadReplicas).filter(models.BadReplicas.rse_id.in_(self.created_rses)).delete(synchronize_session=False)

    @transactional_session
    def __cleanup_rse_attributes(self, session=None):
        for model in (models.RSEAttrAssociation, models.RSEProtocols, models.UpdatedRSECounter,
                      models.RSEUsage, models.RSELimit, models.RSETransferLimit, models.RSEQoSAssociation):
            session.query(model).filter(model.rse_id.in_(self.created_rses)).delete(synchronize_session=False)

        session.query(models.Distance).filter(or_(models.Distance.src_rse_id.in_(self.created_rses),
                                                  models.Distance.dest_rse_id.in_(self.created_rses))).delete(synchronize_session=False)

    def __cleanup_rses(self):
        for rse_id in self.created_rses:
            # Only archive RSE instead of deleting. Account handling code doesn't expect RSEs to ever be deleted.
            # So running test in parallel results in some tests failing on foreign key errors.
            rse_core.del_rse(rse_id)

    def _make_rse(self, scheme, protocol_impl, parameters=None, add_rse_kwargs=None):
        rse_name = rse_name_generator()
        rse_id = rse_core.add_rse(rse_name, vo=self.vo, **(add_rse_kwargs or {}))
        if scheme and protocol_impl:
            rse_core.add_protocol(rse_id=rse_id, parameter={
                'scheme': scheme,
                'hostname': '%s.cern.ch' % rse_id,
                'port': 0,
                'prefix': '/test/',
                'impl': protocol_impl,
                'domains': {
                    'wan': {
                        'read': 1,
                        'write': 1,
                        'delete': 1,
                        'third_party_copy': 1
                    }
                },
                **(parameters or {})
            })
        self.created_rses.append(rse_id)
        return rse_name, rse_id

    def make_rse(self, **kwargs):
        return self._make_rse(scheme=None, protocol_impl=None, add_rse_kwargs=kwargs)

    def make_posix_rse(self, **kwargs):
        return self._make_rse(scheme='file', protocol_impl='rucio.rse.protocols.posix.Default', add_rse_kwargs=kwargs)

    def make_mock_rse(self, **kwargs):
        return self._make_rse(scheme='MOCK', protocol_impl='rucio.rse.protocols.mock.Default', add_rse_kwargs=kwargs)

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

    def __init__(self, default_scope, vo):
        self.default_scope = default_scope
        self.vo = vo

        self.base_uuid = generate_uuid()

        self._client = None
        self._upload_client = None

        self.created_dids = []

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

    def cleanup(self):
        if not self.created_dids:
            return
        self.__cleanup_transfers()
        self.__cleanup_locks_and_rules()
        self.__cleanup_replicas()

    @transactional_session
    def __cleanup_transfers(self, session=None):
        # Cleanup Transfers
        session.query(models.Source).filter(or_(and_(models.Source.scope == did['scope'],
                                                     models.Source.name == did['name'])
                                                for did in self.created_dids)).delete(synchronize_session=False)
        session.query(models.Request).filter(or_(and_(models.Request.scope == did['scope'],
                                                      models.Request.name == did['name'])
                                                 for did in self.created_dids)).delete(synchronize_session=False)

    @transactional_session
    def __cleanup_locks_and_rules(self, session=None):
        query = session.query(models.ReplicationRule.id).filter(or_(and_(models.ReplicationRule.scope == did['scope'],
                                                                         models.ReplicationRule.name == did['name'])
                                                                    for did in self.created_dids))
        for rule_id, in query:
            rule_core.delete_rule(rule_id, session=session, ignore_rule_lock=True)

    @transactional_session
    def __cleanup_replicas(self, session=None):
        query = session.query(models.RSEFileAssociation.scope, models.RSEFileAssociation.name, models.RSEFileAssociation.rse_id). \
            filter(or_(and_(models.RSEFileAssociation.scope == did['scope'],
                            models.RSEFileAssociation.name == did['name'])
                       for did in self.created_dids))
        dids_by_rse = {}
        for scope, name, rse_id in query:
            dids_by_rse.setdefault(rse_id, []).append({'scope': scope, 'name': name})
        for rse_id, dids in dids_by_rse.items():
            replica_core.delete_replicas(rse_id=rse_id, files=dids, session=session)
        # Cleanup BadReplicas
        session.query(models.BadReplicas).filter(or_(and_(models.BadReplicas.scope == did['scope'],
                                                          models.BadReplicas.name == did['name'])
                                                     for did in self.created_dids)).delete(synchronize_session=False)

    def register_dids(self, dids):
        """
        Register the provided dids to be cleaned up on teardown
        """
        self.created_dids.extend(dids)

    def _sanitize_or_set_scope(self, scope):
        if not scope:
            scope = self.default_scope
        elif isinstance(scope, str):
            scope = InternalScope(scope, vo=self.vo)
        return scope

    def _random_did(self, scope, name_prefix, name_suffix=''):
        scope = self._sanitize_or_set_scope(scope)
        if not name_prefix:
            name_prefix = 'lfn'
        name = '%s_%s_%s%s' % (name_prefix, self.base_uuid, len(self.created_dids), name_suffix)
        did = {'scope': scope, 'name': name}
        self.created_dids.append(did)
        return did

    def random_did(self, scope=None, name_prefix=None, name_suffix=''):
        did = self._random_did(scope=scope, name_prefix=name_prefix, name_suffix=name_suffix)
        return did

    def make_dataset(self, scope=None):
        did = self._random_did(scope=scope, name_prefix='dataset')
        self.client.add_did(scope=did['scope'].external, name=did['name'], type=DIDType.DATASET)
        return did

    def make_container(self, scope=None):
        did = self._random_did(scope=scope, name_prefix='container')
        self.client.add_container(scope=did['scope'].external, name=did['name'])
        return did

    def upload_test_file(self, rse_name, scope=None, name=None, path=None, return_full_item=False):
        scope = self._sanitize_or_set_scope(scope)
        if not path:
            path = file_generator()
        if not name:
            name = os.path.basename(path)
        item = {
            'path': path,
            'rse': rse_name,
            'did_scope': str(scope),
            'did_name': name,
            'guid': generate_uuid(),
        }
        self.upload_client.upload([item])
        did = {'scope': scope, 'name': name}
        self.created_dids.append(did)
        return item if return_full_item else did


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

    def _make_temp_file(self, data, size, namelen, use_basedir):
        fn = ''.join(choice(ascii_uppercase) for x in range(namelen))
        if use_basedir:
            fp = self.base_dir / fn
        else:
            fp = Path(tempfile.gettempdir(), fn)
            self.non_basedir_files.append(fp)

        if data is not None:
            if PY3:
                with open(fp, 'w', encoding='utf-8') as f:
                    f.write(data)
            else:
                with open(fp, 'w') as f:
                    f.write(data)
        else:
            execute('dd if=/dev/urandom of={0} count={1} bs=1'.format(fp, size))

        return fp

    def file_generator(self, data=None, size=2, namelen=10, use_basedir=False):
        """
        Creates a temporary file
        :param data        : The content to be written in the file. If provided, the size parameter is ignored.
        :param size        : The size of random bytes to be written in the file
        :param namelen     : The length of filename
        :param use_basedir : If True, the file is created under the base_dir for this TemporaryFileFactory instance.
        :returns: The absolute path of the generated file
        """
        return self._make_temp_file(data, size, namelen, use_basedir)

    def cleanup(self):
        for fp in self.non_basedir_files:
            if os.path.isfile(fp):
                os.remove(fp)
