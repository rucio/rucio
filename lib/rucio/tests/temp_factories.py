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

import os

from sqlalchemy import or_, and_

from rucio.client.client import Client
from rucio.client.uploadclient import UploadClient
from rucio.common.types import InternalScope
from rucio.common.utils import generate_uuid
from rucio.core import replica as replica_core
from rucio.core import rse as rse_core
from rucio.core import rule as rule_core
from rucio.db.sqla import models
from rucio.db.sqla.session import transactional_session
from rucio.tests.common import file_generator
from rucio.tests.common import rse_name_generator


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
            rule_core.delete_rule(rule_id, session=session)

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

    def _make_rse(self, scheme, protocol_impl, add_rse_kwargs):
        rse_name = rse_name_generator()
        rse_id = rse_core.add_rse(rse_name, vo=self.vo, **add_rse_kwargs)
        rse_core.add_protocol(rse_id=rse_id, parameter={
            'scheme': scheme,
            'hostname': 'host%d' % len(self.created_rses),
            'port': 0,
            'prefix': '/test',
            'impl': protocol_impl,
            'domains': {
                'wan': {
                    'read': 1,
                    'write': 1,
                    'delete': 1,
                    'third_party_copy': 1
                }
            }
        })
        self.created_rses.append(rse_id)
        return rse_name, rse_id

    def make_posix_rse(self, **kwargs):
        return self._make_rse(scheme='file', protocol_impl='rucio.rse.protocols.posix.Default', add_rse_kwargs=kwargs)

    def make_mock_rse(self, **kwargs):
        return self._make_rse(scheme='MOCK', protocol_impl='rucio.rse.protocols.mock.Default', add_rse_kwargs=kwargs)

    def make_xroot_rse(self, **kwargs):
        return self._make_rse(scheme='root', protocol_impl='rucio.rse.protocols.xrootd.Default', add_rse_kwargs=kwargs)


class TemporaryFileFactory:
    """
    Factory which keeps track of uploaded files and cleans up everything related to these files at the end
    """
    def __init__(self, default_scope, vo):
        self.default_scope = default_scope
        self.vo = vo

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
            self._client = Client()
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

        # Cleanup Transfers
        session.query(models.Source).filter(or_(and_(models.Source.scope == did['scope'],
                                                     models.Source.name == did['name'])
                                                for did in self.created_dids)).delete(synchronize_session=False)
        session.query(models.Request).filter(or_(and_(models.Request.scope == did['scope'],
                                                      models.Request.name == did['name'])
                                                 for did in self.created_dids)).delete(synchronize_session=False)

        # Cleanup Locks Rules
        query = session.query(models.ReplicationRule.id).filter(or_(and_(models.ReplicationRule.scope == did['scope'],
                                                                         models.ReplicationRule.name == did['name'])
                                                                    for did in self.created_dids))
        for rule_id, in query:
            rule_core.delete_rule(rule_id, session=session)

        # Cleanup Replicas and Parent Datasets
        dids_by_rse = {}
        replicas = list(replica_core.list_replicas(self.created_dids, all_states=True, session=session))
        for replica in replicas:
            for rse_id in replica['rses']:
                dids_by_rse.setdefault(rse_id, []).append({'scope': replica['scope'], 'name': replica['name']})
        for rse_id, dids in dids_by_rse.items():
            replica_core.delete_replicas(rse_id=rse_id, files=dids, session=session)

    def _sanitize_or_set_scope(self, scope):
        if not scope:
            scope = self.default_scope
        elif isinstance(scope, str):
            scope = InternalScope(scope, vo=self.vo)
        return scope

    def make_dataset(self, scope=None, name=None):
        scope = self._sanitize_or_set_scope(scope)
        if not name:
            name = 'dataset_%s' % generate_uuid()
        did = {'scope': scope, 'name': name}
        self.client.add_dataset(scope.external, name)
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
