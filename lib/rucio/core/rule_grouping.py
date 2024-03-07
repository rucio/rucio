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

import logging
from collections.abc import Sequence
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import func
from sqlalchemy.orm.exc import NoResultFound

import rucio.core.did
import rucio.core.lock
import rucio.core.replica
from rucio.common.config import config_get_int
from rucio.common.exception import InsufficientTargetRSEs
from rucio.core import account_counter, rse_counter, request as request_core
from rucio.core.rse_selector import RSESelector
from rucio.core.rse import get_rse, get_rse_attribute, get_rse_name
from rucio.db.sqla import models
from rucio.db.sqla.constants import LockState, RuleGrouping, ReplicaState, RequestType, DIDType, OBSOLETE
from rucio.db.sqla.session import transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


@transactional_session
def apply_rule_grouping(datasetfiles: Sequence[dict[str, Any]], locks: dict[tuple[str, str], models.ReplicaLock],
                        replicas: dict[tuple[str, str], Any], source_replicas: dict[tuple[str, str], Any],
                        rseselector: RSESelector, rule: models.ReplicationRule, preferred_rse_ids: Sequence[str] = [],
                        source_rses: Sequence[str] = [], *,
                        session: "Session") -> tuple[dict[str, list[dict[str, models.RSEFileAssociation]]],
                                                     dict[str, list[dict[str, models.ReplicaLock]]],
                                                     list[dict[str, Any]]]:
    """
    Apply rule grouping to files.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
    :param source_replicas:    Dict holding all source_replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule object.
    :param preferred_rse_ids:  Preferred RSE's to select.
    :param source_rses:        RSE ids of eglible source replicas.
    :param session:            Session of the db.
    :returns:                  Dict of replicas to create, Dict of locks to create, List of transfers to create
    :raises:                   InsufficientQuota, InsufficientTargetRSEs, RSEOverQuota
    :attention:                This method modifies the contents of the locks and replicas input parameters.
    """

    # locks_to_create =     {'rse_id': [locks]}
    # replicas_to_create =  {'rse_id': [replicas]}
    # transfers_to_create = [{'dest_rse_id':, 'scope':, 'name':, 'request_type':, 'metadata':}]

    if rule.grouping == RuleGrouping.NONE:
        replicas_to_create, locks_to_create, \
            transfers_to_create = __apply_rule_to_files_none_grouping(datasetfiles=datasetfiles,
                                                                      locks=locks,
                                                                      replicas=replicas,
                                                                      source_replicas=source_replicas,
                                                                      rseselector=rseselector,
                                                                      rule=rule,
                                                                      preferred_rse_ids=preferred_rse_ids,
                                                                      source_rses=source_rses,
                                                                      session=session)
    elif rule.grouping == RuleGrouping.ALL:
        replicas_to_create, locks_to_create, \
            transfers_to_create = __apply_rule_to_files_all_grouping(datasetfiles=datasetfiles,
                                                                     locks=locks,
                                                                     replicas=replicas,
                                                                     source_replicas=source_replicas,
                                                                     rseselector=rseselector,
                                                                     rule=rule,
                                                                     preferred_rse_ids=preferred_rse_ids,
                                                                     source_rses=source_rses,
                                                                     session=session)
    else:  # rule.grouping == RuleGrouping.DATASET:
        replicas_to_create, locks_to_create, \
            transfers_to_create = __apply_rule_to_files_dataset_grouping(datasetfiles=datasetfiles,
                                                                         locks=locks,
                                                                         replicas=replicas,
                                                                         source_replicas=source_replicas,
                                                                         rseselector=rseselector,
                                                                         rule=rule,
                                                                         preferred_rse_ids=preferred_rse_ids,
                                                                         source_rses=source_rses,
                                                                         session=session)

    return replicas_to_create, locks_to_create, transfers_to_create


@transactional_session
def repair_stuck_locks_and_apply_rule_grouping(datasetfiles: Sequence[dict[str, Any]], locks: dict[tuple[str, str], models.ReplicaLock],
                                               replicas: dict[tuple[str, str], Any], source_replicas: dict[tuple[str, str], Any],
                                               rseselector: RSESelector, rule: models.ReplicationRule, source_rses: Sequence[str], *,
                                               session: "Session") -> tuple[dict[str, list[dict[str, models.RSEFileAssociation]]],
                                                                            dict[str, list[dict[str, models.ReplicaLock]]],
                                                                            list[dict[str, Any]],
                                                                            dict[str, list[dict[str, models.ReplicaLock]]]]:
    """
    Apply rule grouping to files.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
    :param source_replicas:    Dict holding all source_replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule object.
    :param source_rses:        RSE ids of eglible source_rses.
    :param session:            Session of the db.
    :returns:                  List of replicas to create, List of locks to create, List of transfers to create, List of locks to Delete
    :raises:                   InsufficientQuota, InsufficientTargetRSEs
    :attention:                This method modifies the contents of the locks and replicas input parameters.
    """

    # locks_to_create =     {'rse_id': [locks]}
    # replicas_to_create =  {'rse_id': [replicas]}
    # transfers_to_create = [{'dest_rse_id':, 'scope':, 'name':, 'request_type':, 'metadata':}]
    # locks_to_delete =     {'rse_id': [locks]}

    if rule.grouping == RuleGrouping.NONE:
        replicas_to_create, locks_to_create, transfers_to_create, \
            locks_to_delete = __repair_stuck_locks_with_none_grouping(datasetfiles=datasetfiles,
                                                                      locks=locks,
                                                                      replicas=replicas,
                                                                      source_replicas=source_replicas,
                                                                      rseselector=rseselector,
                                                                      rule=rule,
                                                                      source_rses=source_rses,
                                                                      session=session)
    elif rule.grouping == RuleGrouping.ALL:
        replicas_to_create, locks_to_create, transfers_to_create, \
            locks_to_delete = __repair_stuck_locks_with_all_grouping(datasetfiles=datasetfiles,
                                                                     locks=locks,
                                                                     replicas=replicas,
                                                                     source_replicas=source_replicas,
                                                                     rseselector=rseselector,
                                                                     rule=rule,
                                                                     source_rses=source_rses,
                                                                     session=session)
    else:
        replicas_to_create, locks_to_create, transfers_to_create, \
            locks_to_delete = __repair_stuck_locks_with_dataset_grouping(datasetfiles=datasetfiles,
                                                                         locks=locks,
                                                                         replicas=replicas,
                                                                         source_replicas=source_replicas,
                                                                         rseselector=rseselector,
                                                                         rule=rule,
                                                                         source_rses=source_rses,
                                                                         session=session)
    return replicas_to_create, locks_to_create, transfers_to_create, locks_to_delete


@transactional_session
def create_transfer_dict(dest_rse_id, request_type, scope, name, rule, lock=None, bytes_=None, md5=None, adler32=None, ds_scope=None, ds_name=None, copy_pin_lifetime=None, activity=None, retry_count=None, *, session: "Session"):
    """
    This method creates a transfer dictionary and returns it

    :param dest_rse_id:         The destination RSE id.
    :param request_Type:        The request type.
    :param scope:               The scope of the file.
    :param name:                The name of the file.
    :param rule:                The rule responsible for the transfer.
    :param lock:                The lock responsible for the transfer.
    :param bytes_:              The filesize of the file in bytes.
    :param md5:                 The md5 checksum of the file.
    :param adler32:             The adler32 checksum of the file.
    :param ds_scope:            Dataset the file belongs to.
    :param ds_name:             Dataset the file belongs to.
    :param copy_pin_lifetime:   Lifetime in the case of STAGIN requests.
    :param activity:            Activity to be used.
    :param session:             Session of the db.
    :returns:                   Request dictionary.
    """
    attributes = {'activity': activity or rule.activity or 'default',
                  'source_replica_expression': rule.source_replica_expression,
                  'lifetime': copy_pin_lifetime,
                  'ds_scope': ds_scope,
                  'ds_name': ds_name,
                  'bytes': bytes_,
                  'md5': md5,
                  'adler32': adler32,
                  'priority': rule.priority,
                  # 'allow_tape_source': has_account_attribute(account=rule.account, key='admin', session=session)}
                  'allow_tape_source': True}

    return {'dest_rse_id': dest_rse_id,
            'scope': scope,
            'name': name,
            'rule_id': rule.id,
            'attributes': attributes,
            'request_type': request_type,
            'retry_count': retry_count,
            'account': rule.account,
            'requested_at': lock.created_at if lock else rule.created_at}


@transactional_session
def __apply_rule_to_files_none_grouping(datasetfiles, locks, replicas, source_replicas, rseselector, rule, preferred_rse_ids=[], source_rses=[], *, session: "Session"):
    """
    Apply a rule to files with NONE grouping.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
    :param source_replicas:    Dict holding all source_replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule object.
    :param preferred_rse_ids:  Preferred RSE's to select.
    :param source_rses:        RSE ids of eglible source replicas.
    :param session:            Session of the db.
    :returns:                  replicas_to_create, locks_to_create, transfers_to_create
    :raises:                   InsufficientAccountLimit, InsufficientTargetRSEs
    :attention:                This method modifies the contents of the locks and replicas input parameters.
    """
    locks_to_create = {}            # {'rse_id': [locks]}
    replicas_to_create = {}         # {'rse_id': [replicas]}
    transfers_to_create = []        # [{'dest_rse_id':, 'scope':, 'name':, 'request_type':, 'metadata':}]

    for dataset in datasetfiles:
        selected_rse_ids = []
        for file in dataset['files']:
            if len([lock for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id]) == rule.copies:
                # Nothing to do as the file already has the requested amount of locks
                continue
            rse_coverage = {replica.rse_id: file['bytes'] for replica in replicas[(file['scope'], file['name'])] if replica.state in (ReplicaState.AVAILABLE, ReplicaState.COPYING, ReplicaState.TEMPORARY_UNAVAILABLE)}
            if len(preferred_rse_ids) == 0:
                rse_tuples = rseselector.select_rse(size=file['bytes'],
                                                    preferred_rse_ids=rse_coverage.keys(),
                                                    blocklist=[replica.rse_id for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.BEING_DELETED],
                                                    existing_rse_size=rse_coverage)
            else:
                rse_tuples = rseselector.select_rse(size=file['bytes'],
                                                    preferred_rse_ids=preferred_rse_ids,
                                                    blocklist=[replica.rse_id for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.BEING_DELETED],
                                                    existing_rse_size=rse_coverage)
            for rse_tuple in rse_tuples:
                if len([lock for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id and lock.rse_id == rse_tuple[0]]) == 1:
                    # Due to a bug a lock could have been already submitted for this, in that case, skip it
                    continue
                __create_lock_and_replica(file=file,
                                          dataset=dataset,
                                          rule=rule,
                                          rse_id=rse_tuple[0],
                                          staging_area=rse_tuple[1],
                                          availability_write=rse_tuple[2],
                                          locks_to_create=locks_to_create,
                                          locks=locks,
                                          source_rses=source_rses,
                                          replicas_to_create=replicas_to_create,
                                          replicas=replicas,
                                          source_replicas=source_replicas,
                                          transfers_to_create=transfers_to_create,
                                          session=session)
                selected_rse_ids.append(rse_tuple[0])
        if dataset['scope'] is not None:
            for rse_id in list(set(selected_rse_ids)):
                try:
                    session.query(models.CollectionReplica).filter(models.CollectionReplica.scope == dataset['scope'],
                                                                   models.CollectionReplica.name == dataset['name'],
                                                                   models.CollectionReplica.rse_id == rse_id).one()
                except NoResultFound:
                    models.CollectionReplica(scope=dataset['scope'],
                                             name=dataset['name'],
                                             did_type=DIDType.DATASET,
                                             rse_id=rse_id,
                                             bytes=0,
                                             length=0,
                                             available_bytes=0,
                                             available_replicas_cnt=0,
                                             state=ReplicaState.UNAVAILABLE).save(session=session)
                    models.UpdatedCollectionReplica(scope=dataset['scope'],
                                                    name=dataset['name'],
                                                    did_type=DIDType.DATASET).save(flush=False, session=session)

    return replicas_to_create, locks_to_create, transfers_to_create


@transactional_session
def __apply_rule_to_files_all_grouping(datasetfiles, locks, replicas, source_replicas, rseselector, rule, preferred_rse_ids=[], source_rses=[], *, session: "Session"):
    """
    Apply a rule to files with ALL grouping.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
    :param source_replicas:    Dict holding all source_replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule object.
    :param preferred_rse_ids:  Preferred RSE's to select.
    :param source_rses:        RSE ids of eglible source replicas.
    :param session:            Session of the db.
    :returns:                  replicas_to_create, locks_to_create, transfers_to_create
    :raises:                   InsufficientQuota, InsufficientTargetRSEs
    :attention:                This method modifies the contents of the locks and replicas input parameters.
    """

    locks_to_create = {}            # {'rse_id': [locks]}
    replicas_to_create = {}         # {'rse_id': [replicas]}
    transfers_to_create = []        # [{'dest_rse_id':, 'scope':, 'name':, 'request_type':, 'metadata':}]

    bytes_ = 0
    rse_coverage = {}  # {'rse_id': coverage }
    blocklist = set()
    for dataset in datasetfiles:
        for file in dataset['files']:
            bytes_ += file['bytes']
            for replica in replicas[(file['scope'], file['name'])]:
                if replica.state == ReplicaState.BEING_DELETED:
                    blocklist.add(replica.rse_id)
                    continue
                if replica.state in [ReplicaState.AVAILABLE, ReplicaState.COPYING, ReplicaState.TEMPORARY_UNAVAILABLE]:
                    if replica.rse_id in rse_coverage:
                        rse_coverage[replica.rse_id] += file['bytes']
                    else:
                        rse_coverage[replica.rse_id] = file['bytes']

    if not preferred_rse_ids:
        rse_tuples = rseselector.select_rse(size=bytes_,
                                            preferred_rse_ids=[x[0] for x in sorted(rse_coverage.items(), key=lambda tup: tup[1], reverse=True)],
                                            blocklist=list(blocklist),
                                            prioritize_order_over_weight=True,
                                            existing_rse_size=rse_coverage)
    else:
        rse_tuples = rseselector.select_rse(size=bytes_,
                                            preferred_rse_ids=preferred_rse_ids,
                                            blocklist=list(blocklist),
                                            existing_rse_size=rse_coverage)
    for rse_tuple in rse_tuples:
        for dataset in datasetfiles:
            for file in dataset['files']:
                if len([lock for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id]) == rule.copies:
                    continue
                if len([lock for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id and lock.rse_id == rse_tuple[0]]) == 1:
                    # Due to a bug a lock could have been already submitted for this, in that case, skip it
                    continue
                __create_lock_and_replica(file=file,
                                          dataset=dataset,
                                          rule=rule,
                                          rse_id=rse_tuple[0],
                                          staging_area=rse_tuple[1],
                                          availability_write=rse_tuple[2],
                                          locks_to_create=locks_to_create,
                                          locks=locks,
                                          source_rses=source_rses,
                                          replicas_to_create=replicas_to_create,
                                          replicas=replicas,
                                          source_replicas=source_replicas,
                                          transfers_to_create=transfers_to_create,
                                          session=session)
            # Add a DatasetLock to the DB
            if dataset['scope'] is not None:
                try:
                    session.query(models.DatasetLock).filter(models.DatasetLock.scope == dataset['scope'],
                                                             models.DatasetLock.name == dataset['name'],
                                                             models.DatasetLock.rule_id == rule.id,
                                                             models.DatasetLock.rse_id == rse_tuple[0]).one()
                except NoResultFound:
                    # Get dataset Information
                    is_open, bytes_, length = True, 0, 0
                    try:
                        is_open, bytes_, length = session.query(models.DataIdentifier.is_open,
                                                                models.DataIdentifier.bytes,
                                                                models.DataIdentifier.length).filter_by(scope=dataset['scope'], name=dataset['name']).one()
                    except NoResultFound:
                        pass

                    models.DatasetLock(scope=dataset['scope'],
                                       name=dataset['name'],
                                       rule_id=rule.id,
                                       rse_id=rse_tuple[0],
                                       state=LockState.REPLICATING,
                                       account=rule.account,
                                       length=length if not is_open else None,
                                       bytes=bytes_ if not is_open else None).save(flush=False, session=session)
            # Add a Dataset Replica to the DB
            if dataset['scope'] is not None:
                try:
                    session.query(models.CollectionReplica).filter(models.CollectionReplica.scope == dataset['scope'],
                                                                   models.CollectionReplica.name == dataset['name'],
                                                                   models.CollectionReplica.rse_id == rse_tuple[0]).one()
                except NoResultFound:
                    models.CollectionReplica(scope=dataset['scope'],
                                             name=dataset['name'],
                                             did_type=DIDType.DATASET,
                                             rse_id=rse_tuple[0],
                                             bytes=0,
                                             length=0,
                                             available_bytes=0,
                                             available_replicas_cnt=0,
                                             state=ReplicaState.UNAVAILABLE).save(session=session)
                    models.UpdatedCollectionReplica(scope=dataset['scope'],
                                                    name=dataset['name'],
                                                    did_type=DIDType.DATASET).save(flush=False, session=session)

    return replicas_to_create, locks_to_create, transfers_to_create


@transactional_session
def __apply_rule_to_files_dataset_grouping(datasetfiles, locks, replicas, source_replicas, rseselector, rule, preferred_rse_ids=[], source_rses=[], *, session: "Session"):
    """
    Apply a rule to files with ALL grouping.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
    :param source_replicas:    Dict holding all source replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule object.
    :param preferred_rse_ids:  Preferred RSE's to select.
    :param source_rses:        RSE ids of eglible source replicas.
    :param session:            Session of the db.
    :returns:                  replicas_to_create, locks_to_create, transfers_to_create
    :raises:                   InsufficientQuota, InsufficientTargetRSEs
    :attention:                This method modifies the contents of the locks and replicas input parameters.
    """
    locks_to_create = {}            # {'rse_id': [locks]}
    replicas_to_create = {}         # {'rse_id': [replicas]}
    transfers_to_create = []        # [{'dest_rse_id':, 'scope':, 'name':, 'request_type':, 'metadata':}]

    for dataset in datasetfiles:
        bytes_ = sum([file['bytes'] for file in dataset['files']])
        rse_coverage = {}  # {'rse_id': coverage }
        blocklist = set()
        for file in dataset['files']:
            for replica in replicas[(file['scope'], file['name'])]:
                if replica.state == ReplicaState.BEING_DELETED:
                    blocklist.add(replica.rse_id)
                    continue
                if replica.state in [ReplicaState.AVAILABLE, ReplicaState.COPYING, ReplicaState.TEMPORARY_UNAVAILABLE]:
                    if replica.rse_id in rse_coverage:
                        rse_coverage[replica.rse_id] += file['bytes']
                    else:
                        rse_coverage[replica.rse_id] = file['bytes']

        if not preferred_rse_ids:
            rse_tuples = rseselector.select_rse(size=bytes_,
                                                preferred_rse_ids=[x[0] for x in sorted(rse_coverage.items(), key=lambda tup: tup[1], reverse=True)],
                                                blocklist=list(blocklist),
                                                prioritize_order_over_weight=True,
                                                existing_rse_size=rse_coverage)
        else:
            rse_tuples = rseselector.select_rse(size=bytes_,
                                                preferred_rse_ids=preferred_rse_ids,
                                                blocklist=list(blocklist),
                                                existing_rse_size=rse_coverage)
        for rse_tuple in rse_tuples:
            for file in dataset['files']:
                if len([lock for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id]) == rule.copies:
                    continue
                if len([lock for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id and lock.rse_id == rse_tuple[0]]) == 1:
                    # Due to a bug a lock could have been already submitted for this, in that case, skip it
                    continue
                __create_lock_and_replica(file=file,
                                          dataset=dataset,
                                          rule=rule,
                                          rse_id=rse_tuple[0],
                                          staging_area=rse_tuple[1],
                                          availability_write=rse_tuple[2],
                                          locks_to_create=locks_to_create,
                                          locks=locks,
                                          source_rses=source_rses,
                                          replicas_to_create=replicas_to_create,
                                          replicas=replicas,
                                          source_replicas=source_replicas,
                                          transfers_to_create=transfers_to_create,
                                          session=session)
            # Add a DatasetLock to the DB
            if dataset['scope'] is not None:
                try:
                    session.query(models.DatasetLock).filter(models.DatasetLock.scope == dataset['scope'],
                                                             models.DatasetLock.name == dataset['name'],
                                                             models.DatasetLock.rule_id == rule.id,
                                                             models.DatasetLock.rse_id == rse_tuple[0]).one()
                except NoResultFound:
                    # Get dataset Information
                    is_open, bytes_, length = True, None, None
                    try:
                        is_open, bytes_, length = session.query(models.DataIdentifier.is_open,
                                                                models.DataIdentifier.bytes,
                                                                models.DataIdentifier.length).filter_by(scope=dataset['scope'], name=dataset['name']).one()
                    except NoResultFound:
                        pass

                    models.DatasetLock(scope=dataset['scope'],
                                       name=dataset['name'],
                                       rule_id=rule.id,
                                       rse_id=rse_tuple[0],
                                       state=LockState.REPLICATING,
                                       account=rule.account,
                                       length=length if not is_open else None,
                                       bytes=bytes_ if not is_open else None).save(flush=False, session=session)

            # Add a Dataset Replica to the DB
            if dataset['scope'] is not None:
                try:
                    session.query(models.CollectionReplica).filter(models.CollectionReplica.scope == dataset['scope'],
                                                                   models.CollectionReplica.name == dataset['name'],
                                                                   models.CollectionReplica.rse_id == rse_tuple[0]).one()
                except NoResultFound:
                    models.CollectionReplica(scope=dataset['scope'],
                                             name=dataset['name'],
                                             did_type=DIDType.DATASET,
                                             rse_id=rse_tuple[0],
                                             bytes=0,
                                             length=0,
                                             available_bytes=0,
                                             available_replicas_cnt=0,
                                             state=ReplicaState.UNAVAILABLE).save(session=session)
                    models.UpdatedCollectionReplica(scope=dataset['scope'],
                                                    name=dataset['name'],
                                                    did_type=DIDType.DATASET).save(flush=False, session=session)

    return replicas_to_create, locks_to_create, transfers_to_create


@transactional_session
def __repair_stuck_locks_with_none_grouping(datasetfiles, locks, replicas, source_replicas, rseselector, rule, source_rses, *, session: "Session", logger=logging.log):
    """
    Apply a rule to files with NONE grouping.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
    :param source_replicas:    Dict holding all source_replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule object.
    :param source_rses:        RSE ids of eglible source replicas.
    :param session:            Session of the db.
    :param logger:             Optional decorated logger that can be passed from the calling daemons or servers.
    :returns:                  replicas_to_create, locks_to_create, transfers_to_create, locks_to_delete
    :raises:                   InsufficientAccountLimit, InsufficientTargetRSEs
    :attention:                This method modifies the contents of the locks and replicas input parameters.
    """

    locks_to_create = {}            # {'rse_id': [locks]}
    replicas_to_create = {}         # {'rse_id': [replicas]}
    transfers_to_create = []        # [{'dest_rse_id':, 'scope':, 'name':, 'request_type':, 'metadata':}]
    locks_to_delete = {}            # {'rse_id': [locks]}

    selector_rse_dict = rseselector.get_rse_dictionary()

    # Iterate the datasetfiles structure and search for stuck locks
    for dataset in datasetfiles:
        for file in dataset['files']:
            # Iterate and try to repair STUCK locks
            for lock in [stucked_lock for stucked_lock in locks[(file['scope'], file['name'])] if stucked_lock.rule_id == rule.id and stucked_lock.state == LockState.STUCK]:
                # Check if there are actually already enough locks
                if len([good_lock for good_lock in locks[(file['scope'], file['name'])] if good_lock.rule_id == rule.id and good_lock.state != LockState.STUCK]) >= rule.copies:
                    # Remove the lock
                    logger(logging.DEBUG, 'There are too many locks for %s:%s for rule %s. Deleting lock', file['scope'], file['name'], str(rule.id))
                    if lock.rse_id in locks_to_delete:
                        locks_to_delete[lock.rse_id].append(lock)
                    else:
                        locks_to_delete[lock.rse_id] = [lock]
                    rule.locks_stuck_cnt -= 1
                    continue
                # Check if the replica is AVAILABLE now
                if [replica for replica in replicas[(file['scope'], file['name'])] if replica.state in [ReplicaState.AVAILABLE, ReplicaState.TEMPORARY_UNAVAILABLE] and replica.rse_id == lock.rse_id]:
                    lock.state = LockState.OK
                    rule.locks_stuck_cnt -= 1
                    rule.locks_ok_cnt += 1
                    # Recalculate the replica_lock_cnt
                    associated_replica = [replica for replica in replicas[(file['scope'], file['name'])] if replica.state in [ReplicaState.AVAILABLE, ReplicaState.TEMPORARY_UNAVAILABLE] and replica.rse_id == lock.rse_id][0]
                    associated_replica.tombstone = None
                    associated_replica.lock_cnt = session.query(func.count(models.ReplicaLock.rule_id)).filter_by(scope=associated_replica.scope, name=associated_replica.name, rse_id=lock.rse_id).one()[0]
                    continue
                # Check if this is a STUCK lock due to source_replica filtering
                if source_rses:
                    associated_replica = [replica for replica in replicas[(file['scope'], file['name'])] if replica.rse_id == lock.rse_id][0]
                    # Check if there is an eglible source replica for this lock
                    if set(source_replicas.get((file['scope'], file['name']), [])).intersection(source_rses) and (selector_rse_dict.get(lock.rse_id, {}).get('availability_write', True) or rule.ignore_availability):
                        __update_lock_replica_and_create_transfer(lock=lock,
                                                                  replica=associated_replica,
                                                                  rule=rule,
                                                                  dataset=dataset,
                                                                  transfers_to_create=transfers_to_create,
                                                                  session=session)
                else:
                    blocklist_rses = [bl_lock.rse_id for bl_lock in locks[(file['scope'], file['name'])] if bl_lock.rule_id == rule.id]
                    try:
                        rse_coverage = {replica.rse_id: file['bytes'] for replica in replicas[(file['scope'], file['name'])] if replica.state in (ReplicaState.AVAILABLE, ReplicaState.COPYING, ReplicaState.TEMPORARY_UNAVAILABLE)}
                        rse_tuples = rseselector.select_rse(size=file['bytes'],
                                                            preferred_rse_ids=rse_coverage.keys(),
                                                            copies=1,
                                                            blocklist=[replica.rse_id for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.BEING_DELETED] + blocklist_rses + [lock.rse_id],
                                                            existing_rse_size=rse_coverage)
                        for rse_tuple in rse_tuples:
                            __create_lock_and_replica(file=file,
                                                      dataset=dataset,
                                                      rule=rule,
                                                      rse_id=rse_tuple[0],
                                                      staging_area=rse_tuple[1],
                                                      availability_write=rse_tuple[2],
                                                      locks_to_create=locks_to_create,
                                                      locks=locks,
                                                      source_rses=source_rses,
                                                      replicas_to_create=replicas_to_create,
                                                      replicas=replicas,
                                                      source_replicas=source_replicas,
                                                      transfers_to_create=transfers_to_create,
                                                      session=session)
                            rule.locks_stuck_cnt -= 1
                            __set_replica_unavailable(replica=[replica for replica in replicas[(file['scope'], file['name'])] if replica.rse_id == lock.rse_id][0],
                                                      session=session)
                            if lock.rse_id in locks_to_delete:
                                locks_to_delete[lock.rse_id].append(lock)
                            else:
                                locks_to_delete[lock.rse_id] = [lock]
                    except InsufficientTargetRSEs:
                        # Just retry the already existing lock
                        if __is_retry_required(lock=lock, activity=rule.activity) and (selector_rse_dict.get(lock.rse_id, {}).get('availability_write', True) or rule.ignore_availability):
                            associated_replica = [replica for replica in replicas[(file['scope'], file['name'])] if replica.rse_id == lock.rse_id][0]
                            __update_lock_replica_and_create_transfer(lock=lock,
                                                                      replica=associated_replica,
                                                                      rule=rule,
                                                                      dataset=dataset,
                                                                      transfers_to_create=transfers_to_create,
                                                                      session=session)

    return replicas_to_create, locks_to_create, transfers_to_create, locks_to_delete


@transactional_session
def __repair_stuck_locks_with_all_grouping(datasetfiles, locks, replicas, source_replicas, rseselector, rule, source_rses, *, session: "Session", logger=logging.log):
    """
    Apply a rule to files with ALL grouping.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
    :param source_replicas:    Dict holding all source_replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule object.
    :param source_rses:        RSE ids of eglible source replicas.
    :param session:            Session of the db.
    :param logger:             Optional decorated logger that can be passed from the calling daemons or servers.
    :returns:                  replicas_to_create, locks_to_create, transfers_to_create, locks_to_delete
    :raises:                   InsufficientAccountLimit, InsufficientTargetRSEs
    :attention:                This method modifies the contents of the locks and replicas input parameters.
    """

    locks_to_create = {}            # {'rse_id': [locks]}
    replicas_to_create = {}         # {'rse_id': [replicas]}
    transfers_to_create = []        # [{'dest_rse_id':, 'scope':, 'name':, 'request_type':, 'metadata':}]
    locks_to_delete = {}            # {'rse_id': [locks]}

    selector_rse_dict = rseselector.get_rse_dictionary()

    # Iterate the datasetfiles structure and search for stuck locks
    for dataset in datasetfiles:
        for file in dataset['files']:
            # Iterate and try to repair STUCK locks
            for lock in [stucked_lock for stucked_lock in locks[(file['scope'], file['name'])] if stucked_lock.rule_id == rule.id and stucked_lock.state == LockState.STUCK]:
                # Check if there are actually already enough locks
                if len([good_lock for good_lock in locks[(file['scope'], file['name'])] if good_lock.rule_id == rule.id and good_lock.state != LockState.STUCK]) >= rule.copies:
                    # Remove the lock
                    logger(logging.DEBUG, 'There are too many locks for %s:%s for rule %s. Deleting lock', file['scope'], file['name'], str(rule.id))
                    if lock.rse_id in locks_to_delete:
                        locks_to_delete[lock.rse_id].append(lock)
                    else:
                        locks_to_delete[lock.rse_id] = [lock]
                    rule.locks_stuck_cnt -= 1
                    continue
                # Check if the replica is AVAILABLE now
                if [replica for replica in replicas[(file['scope'], file['name'])] if replica.state in [ReplicaState.AVAILABLE, ReplicaState.TEMPORARY_UNAVAILABLE] and replica.rse_id == lock.rse_id]:
                    lock.state = LockState.OK
                    rule.locks_stuck_cnt -= 1
                    rule.locks_ok_cnt += 1
                    # Recalculate the replica_lock_cnt
                    associated_replica = [replica for replica in replicas[(file['scope'], file['name'])] if replica.state in [ReplicaState.AVAILABLE, ReplicaState.TEMPORARY_UNAVAILABLE] and replica.rse_id == lock.rse_id][0]
                    associated_replica.tombstone = None
                    associated_replica.lock_cnt = session.query(func.count(models.ReplicaLock.rule_id)).filter_by(scope=associated_replica.scope, name=associated_replica.name, rse_id=lock.rse_id).one()[0]
                    continue
                # Check if this is a STUCK lock due to source_replica filtering
                if source_rses:
                    associated_replica = [replica for replica in replicas[(file['scope'], file['name'])] if replica.rse_id == lock.rse_id][0]
                    # Check if there is an eglible source replica for this lock
                    if set(source_replicas.get((file['scope'], file['name']), [])).intersection(source_rses) and (selector_rse_dict.get(lock.rse_id, {}).get('availability_write', True) or rule.ignore_availability):
                        __update_lock_replica_and_create_transfer(lock=lock,
                                                                  replica=associated_replica,
                                                                  rule=rule,
                                                                  dataset=dataset,
                                                                  transfers_to_create=transfers_to_create,
                                                                  session=session)
                else:
                    # Just retry the already existing lock
                    if __is_retry_required(lock=lock, activity=rule.activity) and (selector_rse_dict.get(lock.rse_id, {}).get('availability_write', True) or rule.ignore_availability):
                        associated_replica = [replica for replica in replicas[(file['scope'], file['name'])] if replica.rse_id == lock.rse_id][0]
                        __update_lock_replica_and_create_transfer(lock=lock,
                                                                  replica=associated_replica,
                                                                  rule=rule,
                                                                  dataset=dataset,
                                                                  transfers_to_create=transfers_to_create,
                                                                  session=session)

    return replicas_to_create, locks_to_create, transfers_to_create, locks_to_delete


@transactional_session
def __repair_stuck_locks_with_dataset_grouping(datasetfiles, locks, replicas, source_replicas, rseselector, rule, source_rses, *, session: "Session", logger=logging.log):
    """
    Apply a rule to files with DATASET grouping.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
    :param source_replicas:    Dict holding all source_replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule object.
    :param source_rses:        RSE ids of eglible source replicas.
    :param session:            Session of the db.
    :param logger:             Optional decorated logger that can be passed from the calling daemons or servers.
    :returns:                  replicas_to_create, locks_to_create, transfers_to_create, locks_to_delete
    :raises:                   InsufficientAccountLimit, InsufficientTargetRSEs
    :attention:                This method modifies the contents of the locks and replicas input parameters.
    """

    locks_to_create = {}            # {'rse_id': [locks]}
    replicas_to_create = {}         # {'rse_id': [replicas]}
    transfers_to_create = []        # [{'dest_rse_id':, 'scope':, 'name':, 'request_type':, 'metadata':}]
    locks_to_delete = {}            # {'rse_id': [locks]}

    selector_rse_dict = rseselector.get_rse_dictionary()

    # Iterate the datasetfiles structure and search for stuck locks
    for dataset in datasetfiles:
        for file in dataset['files']:
            # Iterate and try to repair STUCK locks
            for lock in [stucked_lock for stucked_lock in locks[(file['scope'], file['name'])] if stucked_lock.rule_id == rule.id and stucked_lock.state == LockState.STUCK]:
                # Check if there are actually already enough locks
                if len([good_lock for good_lock in locks[(file['scope'], file['name'])] if good_lock.rule_id == rule.id and good_lock.state != LockState.STUCK]) >= rule.copies:
                    # Remove the lock
                    logger(logging.DEBUG, 'There are too many locks for %s:%s for rule %s. Deleting lock', file['scope'], file['name'], str(rule.id))
                    if lock.rse_id in locks_to_delete:
                        locks_to_delete[lock.rse_id].append(lock)
                    else:
                        locks_to_delete[lock.rse_id] = [lock]
                    rule.locks_stuck_cnt -= 1
                    continue
                # Check if the replica is AVAILABLE now
                if [replica for replica in replicas[(file['scope'], file['name'])] if replica.state in [ReplicaState.AVAILABLE, ReplicaState.TEMPORARY_UNAVAILABLE] and replica.rse_id == lock.rse_id]:
                    lock.state = LockState.OK
                    rule.locks_stuck_cnt -= 1
                    rule.locks_ok_cnt += 1
                    # Recalculate the replica_lock_cnt
                    associated_replica = [replica for replica in replicas[(file['scope'], file['name'])] if replica.state in [ReplicaState.AVAILABLE, ReplicaState.TEMPORARY_UNAVAILABLE] and replica.rse_id == lock.rse_id][0]
                    associated_replica.tombstone = None
                    associated_replica.lock_cnt = session.query(func.count(models.ReplicaLock.rule_id)).filter_by(scope=associated_replica.scope, name=associated_replica.name, rse_id=lock.rse_id).one()[0]
                    continue
                # Check if this is a STUCK lock due to source_replica filtering
                if source_rses:
                    associated_replica = [replica for replica in replicas[(file['scope'], file['name'])] if replica.rse_id == lock.rse_id][0]
                    # Check if there is an eglible source replica for this lock
                    if set(source_replicas.get((file['scope'], file['name']), [])).intersection(source_rses) and (selector_rse_dict.get(lock.rse_id, {}).get('availability_write', True) or rule.ignore_availability):
                        __update_lock_replica_and_create_transfer(lock=lock,
                                                                  replica=associated_replica,
                                                                  rule=rule,
                                                                  dataset=dataset,
                                                                  transfers_to_create=transfers_to_create,
                                                                  session=session)
                else:
                    # Just retry the already existing lock
                    if __is_retry_required(lock=lock, activity=rule.activity) and (selector_rse_dict.get(lock.rse_id, {}).get('availability_write', True) or rule.ignore_availability):
                        associated_replica = [replica for replica in replicas[(file['scope'], file['name'])] if replica.rse_id == lock.rse_id][0]
                        __update_lock_replica_and_create_transfer(lock=lock,
                                                                  replica=associated_replica,
                                                                  rule=rule,
                                                                  dataset=dataset,
                                                                  transfers_to_create=transfers_to_create,
                                                                  session=session)

    return replicas_to_create, locks_to_create, transfers_to_create, locks_to_delete


def __is_retry_required(lock, activity):
    """
    :param lock:                 The lock to check.
    :param activity:             The activity of the rule.
    """

    created_at_diff = (datetime.utcnow() - lock.created_at).days * 24 * 3600 + (datetime.utcnow() - lock.created_at).seconds
    updated_at_diff = (datetime.utcnow() - lock.updated_at).days * 24 * 3600 + (datetime.utcnow() - lock.updated_at).seconds

    if activity == 'Express':
        if updated_at_diff > 3600 * 2:
            return True
    elif activity == 'DebugJudge':
        return True
    elif created_at_diff < 24 * 3600:  # First Day
        # Retry every 2 hours
        if updated_at_diff > 3600 * 2:
            return True
    elif created_at_diff < 2 * 24 * 3600:  # Second Day
        # Retry every 4 hours
        if updated_at_diff > 3600 * 4:
            return True
    elif created_at_diff < 3 * 24 * 3600:  # Third Day
        # Retry every 6 hours
        if updated_at_diff > 3600 * 6:
            return True
    else:  # Four and more days
        if updated_at_diff > 3600 * 8:
            return True
    return False


@transactional_session
def __create_lock_and_replica(file, dataset, rule, rse_id, staging_area, availability_write, locks_to_create, locks, source_rses, replicas_to_create, replicas, source_replicas, transfers_to_create, *, session: "Session", logger=logging.log):
    """
    This method creates a lock and if necessary a new replica and fills the corresponding dictionaries.

    :param file:                 File dictionary holding the file information.
    :param dataset:              Dataset dictionary holding the dataset information.
    :param rule:                 Rule object.
    :param rse_id:               RSE id the lock and replica should be created at.
    :param staging_area:         Boolean variable if the RSE is a staging area.
    :param availability_write:   Boolean variable if the RSE is write enabled.
    :param locks_to_create:      Dictionary of the locks to create.
    :param locks:                Dictionary of all locks.
    :param source_rses:          RSE ids of eglible source replicas.
    :param replicas_to_create:   Dictionary of the replicas to create.
    :param replicas:             Dictionary of the replicas.
    :param source_replicas:      Dictionary of the source replicas.
    :param transfers_to_create:  List of transfers to create.
    :param session:              The db session in use.
    :param logger:               Optional decorated logger that can be passed from the calling daemons or servers.
    :returns:                    True, if the created lock is replicating, False otherwise.
    :attention:                  This method modifies the contents of the locks, locks_to_create, replicas_to_create and replicas input parameters.
    """

    if rule.expires_at:
        copy_pin_lifetime = rule.expires_at - datetime.utcnow()
        copy_pin_lifetime = copy_pin_lifetime.seconds + copy_pin_lifetime.days * 24 * 3600
    else:
        copy_pin_lifetime = None

    # If it is a Staging Area, the pin has to be extended
    if staging_area:
        transfers_to_create.append(create_transfer_dict(dest_rse_id=rse_id,
                                                        request_type=RequestType.STAGEIN,
                                                        scope=file['scope'],
                                                        name=file['name'],
                                                        rule=rule,
                                                        bytes_=file['bytes'],
                                                        md5=file['md5'],
                                                        adler32=file['adler32'],
                                                        ds_scope=dataset['scope'],
                                                        ds_name=dataset['name'],
                                                        copy_pin_lifetime=copy_pin_lifetime,
                                                        session=session))

    # If staging_required type RSE then set pin to RSE attribute maximum_pin_lifetime
    staging_required = get_rse_attribute(rse_id, 'staging_required', session=session)
    maximum_pin_lifetime = get_rse_attribute(rse_id, 'maximum_pin_lifetime', session=session)

    if staging_required:
        if (not copy_pin_lifetime and maximum_pin_lifetime) or (copy_pin_lifetime and maximum_pin_lifetime and copy_pin_lifetime < int(maximum_pin_lifetime)):
            copy_pin_lifetime = maximum_pin_lifetime
        rse_name = get_rse_name(rse_id=rse_id, session=session)
        logger(logging.DEBUG, f'Destination RSE {rse_name} is type staging_required with pin value: {copy_pin_lifetime}')

    existing_replicas = [replica for replica in replicas[(file['scope'], file['name'])] if replica.rse_id == rse_id]

    if existing_replicas:  # A replica already exists (But could be UNAVAILABLE)
        existing_replica = existing_replicas[0]

        # Replica is fully available -- AVAILABLE
        if existing_replica.state in [ReplicaState.AVAILABLE, ReplicaState.TEMPORARY_UNAVAILABLE]:
            new_lock = __create_lock(rule=rule,
                                     rse_id=rse_id,
                                     scope=file['scope'],
                                     name=file['name'],
                                     bytes_=file['bytes'],
                                     existing_replica=existing_replica,
                                     state=LockState.OK if not staging_required else LockState.REPLICATING)
            if rse_id not in locks_to_create:
                locks_to_create[rse_id] = []
            locks_to_create[rse_id].append(new_lock)
            locks[(file['scope'], file['name'])].append(new_lock)
            if not staging_required:
                return False

            transfers_to_create.append(create_transfer_dict(dest_rse_id=rse_id,
                                                            request_type=RequestType.STAGEIN,
                                                            scope=file['scope'],
                                                            name=file['name'],
                                                            rule=rule,
                                                            lock=new_lock,
                                                            bytes_=file['bytes'],
                                                            md5=file['md5'],
                                                            adler32=file['adler32'],
                                                            ds_scope=dataset['scope'],
                                                            ds_name=dataset['name'],
                                                            copy_pin_lifetime=copy_pin_lifetime,
                                                            session=session))

        # Replica is not available -- UNAVAILABLE
        elif existing_replica.state == ReplicaState.UNAVAILABLE:
            available_source_replica = True
            if source_rses:
                available_source_replica = False
                # Check if there is an eglible source replica for this lock
                if set(source_replicas.get((file['scope'], file['name']), [])).intersection(source_rses):
                    available_source_replica = True
            new_lock = __create_lock(rule=rule,
                                     rse_id=rse_id,
                                     scope=file['scope'],
                                     name=file['name'],
                                     bytes_=file['bytes'],
                                     existing_replica=existing_replica,
                                     state=LockState.REPLICATING if (available_source_replica and availability_write) else LockState.STUCK)
            if rse_id not in locks_to_create:
                locks_to_create[rse_id] = []
            locks_to_create[rse_id].append(new_lock)
            locks[(file['scope'], file['name'])].append(new_lock)
            if not staging_area and not staging_required and available_source_replica and availability_write:
                transfers_to_create.append(create_transfer_dict(dest_rse_id=rse_id,
                                                                request_type=RequestType.TRANSFER,
                                                                scope=file['scope'],
                                                                name=file['name'],
                                                                rule=rule,
                                                                lock=new_lock,
                                                                bytes_=file['bytes'],
                                                                md5=file['md5'],
                                                                adler32=file['adler32'],
                                                                ds_scope=dataset['scope'],
                                                                ds_name=dataset['name'],
                                                                session=session))
                return True
            return False
        # Replica is not available at the rse yet -- COPYING
        else:
            new_lock = __create_lock(rule=rule,
                                     rse_id=rse_id,
                                     scope=file['scope'],
                                     name=file['name'],
                                     bytes_=file['bytes'],
                                     existing_replica=existing_replica,
                                     state=LockState.REPLICATING)
            if rse_id not in locks_to_create:
                locks_to_create[rse_id] = []
            locks_to_create[rse_id].append(new_lock)
            locks[(file['scope'], file['name'])].append(new_lock)
            return True
    else:  # Replica has to be created
        available_source_replica = True
        if source_rses:
            available_source_replica = False
            # Check if there is an eglible source replica for this lock
            if set(source_replicas.get((file['scope'], file['name']), [])).intersection(source_rses):
                available_source_replica = True

        new_replica = __create_replica(rse_id=rse_id,
                                       scope=file['scope'],
                                       name=file['name'],
                                       bytes_=file['bytes'],
                                       md5=file['md5'],
                                       adler32=file['adler32'],
                                       state=ReplicaState.COPYING if (available_source_replica and availability_write) else ReplicaState.UNAVAILABLE)
        if rse_id not in replicas_to_create:
            replicas_to_create[rse_id] = []
        replicas_to_create[rse_id].append(new_replica)
        replicas[(file['scope'], file['name'])].append(new_replica)

        new_lock = __create_lock(rule=rule,
                                 rse_id=rse_id,
                                 scope=file['scope'],
                                 name=file['name'],
                                 bytes_=file['bytes'],
                                 existing_replica=new_replica,
                                 state=LockState.REPLICATING if (available_source_replica and availability_write) else LockState.STUCK)
        if rse_id not in locks_to_create:
            locks_to_create[rse_id] = []
        locks_to_create[rse_id].append(new_lock)
        locks[(file['scope'], file['name'])].append(new_lock)

        if not staging_area and not staging_required and available_source_replica and availability_write:
            transfers_to_create.append(create_transfer_dict(dest_rse_id=rse_id,
                                                            request_type=RequestType.TRANSFER,
                                                            scope=file['scope'],
                                                            name=file['name'],
                                                            rule=rule,
                                                            lock=new_lock,
                                                            bytes_=file['bytes'],
                                                            md5=file['md5'],
                                                            adler32=file['adler32'],
                                                            ds_scope=dataset['scope'],
                                                            ds_name=dataset['name'],
                                                            session=session))
            return True
        elif staging_required:
            transfers_to_create.append(create_transfer_dict(dest_rse_id=rse_id,
                                                            request_type=RequestType.TRANSFER,
                                                            scope=file['scope'],
                                                            name=file['name'],
                                                            rule=rule,
                                                            lock=new_lock,
                                                            bytes_=file['bytes'],
                                                            md5=file['md5'],
                                                            adler32=file['adler32'],
                                                            ds_scope=dataset['scope'],
                                                            ds_name=dataset['name'],
                                                            session=session))
            return True
        return False


def __create_lock(rule, rse_id, scope, name, bytes_, state, existing_replica, logger=logging.log):
    """
    Create and return a new SQLAlchemy Lock object.

    :param rule:              The SQLAlchemy rule object.
    :param rse_id:            The rse_id of the lock.
    :param scope:             The scope of the lock.
    :param name:              The name of the lock.
    :param bytes_:             Bytes of the lock.
    :param state:             State of the lock.
    :param existing_replica:  Replica object.
    :param logger:            Optional decorated logger that can be passed from the calling daemons or servers.
    """

    new_lock = models.ReplicaLock(rule_id=rule.id,
                                  rse_id=rse_id,
                                  scope=scope,
                                  name=name,
                                  account=rule.account,
                                  bytes=bytes_,
                                  state=state)
    if state == LockState.OK:
        existing_replica.lock_cnt += 1
        existing_replica.tombstone = None
        rule.locks_ok_cnt += 1
        logger(logging.DEBUG, 'Creating OK Lock %s:%s on %s for rule %s', scope, name, rse_id, str(rule.id))
    elif state == LockState.REPLICATING:
        existing_replica.state = ReplicaState.COPYING
        existing_replica.lock_cnt += 1
        existing_replica.tombstone = None
        rule.locks_replicating_cnt += 1
        logger(logging.DEBUG, 'Creating REPLICATING Lock %s:%s on %s for rule %s', scope, rse_id, name, str(rule.id))
    elif state == LockState.STUCK:
        existing_replica.lock_cnt += 1
        existing_replica.tombstone = None
        rule.locks_stuck_cnt += 1
        logger(logging.DEBUG, 'Creating STUCK Lock %s:%s on %s for rule %s', scope, name, rse_id, str(rule.id))
    return new_lock


def __create_replica(rse_id, scope, name, bytes_, state, md5, adler32, logger=logging.log):
    """
    Create and return a new SQLAlchemy replica object.

    :param rse_id:        RSE id of the replica.
    :param scope:         Scope of the replica.
    :param name:          Name of the replica.
    :param bytes_:         Bytes of the replica.
    :param state:         State of the replica.
    :param md5:           MD5 checksum of the replica.
    :param adler32:       ADLER32 checksum of the replica.
    :param logger:        Optional decorated logger that can be passed from the calling daemons or servers.
    """

    new_replica = models.RSEFileAssociation(rse_id=rse_id,
                                            scope=scope,
                                            name=name,
                                            bytes=bytes_,
                                            md5=md5,
                                            adler32=adler32,
                                            tombstone=None,
                                            state=state,
                                            lock_cnt=0)
    logger(logging.DEBUG, 'Creating %s replica for %s:%s on %s', state, scope, name, rse_id)
    return new_replica


@transactional_session
def __update_lock_replica_and_create_transfer(lock, replica, rule, dataset, transfers_to_create, *, session: "Session", logger=logging.log):
    """
    This method updates a lock and replica and fills the corresponding dictionaries.

    :param lock:                 The lock to update.
    :param replica:              The replica to update.
    :param rule:                 Rule to update.
    :param dataset:              Dataset dictionary holding the dataset information.
    :param transfers_to_create:  List of transfers to create.
    :param session:              The db session in use.
    :param logger:               Optional decorated logger that can be passed from the calling daemons or servers.
    :attention:                  This method modifies the contents of the transfers_to_create input parameters.
    """

    logger(logging.DEBUG, 'Updating Lock %s:%s for rule %s', lock.scope, lock.name, str(rule.id))
    lock.state = LockState.REPLICATING
    rule.locks_stuck_cnt -= 1
    rule.locks_replicating_cnt += 1
    replica.state = ReplicaState.COPYING

    if not lock.repair_cnt:
        lock.repair_cnt = 1
    else:
        lock.repair_cnt += 1

    if get_rse(rse_id=lock.rse_id, session=session)['staging_area']:
        copy_pin_lifetime = rule.expires_at - datetime.utcnow()
        copy_pin_lifetime = copy_pin_lifetime.seconds + copy_pin_lifetime.days * 24 * 3600
        transfers_to_create.append(create_transfer_dict(dest_rse_id=lock.rse_id,
                                                        scope=lock.scope,
                                                        name=lock.name,
                                                        rule=rule,
                                                        lock=lock,
                                                        bytes_=replica.bytes,
                                                        md5=replica.md5,
                                                        adler32=replica.adler32,
                                                        ds_scope=dataset['scope'],
                                                        ds_name=dataset['name'],
                                                        copy_pin_lifetime=copy_pin_lifetime,
                                                        request_type=RequestType.STAGEIN,
                                                        session=session))
    else:
        transfers_to_create.append(create_transfer_dict(dest_rse_id=lock.rse_id,
                                                        scope=lock.scope,
                                                        name=lock.name,
                                                        rule=rule,
                                                        lock=lock,
                                                        bytes_=replica.bytes,
                                                        md5=replica.md5,
                                                        adler32=replica.adler32,
                                                        ds_scope=dataset['scope'],
                                                        ds_name=dataset['name'],
                                                        request_type=RequestType.TRANSFER,
                                                        retry_count=1,
                                                        session=session))


@transactional_session
def __set_replica_unavailable(replica, *, session: "Session"):
    """
    This method updates a replica and sets it to UNAVAILABLE.

    :param replica:              The replica to update.
    :param session:              The db session in use.
    """

    replica.lock_cnt -= 1
    if replica.lock_cnt == 0:
        replica.tombstone = OBSOLETE
        replica.state = ReplicaState.UNAVAILABLE


# # debug helper functions used in apply_rule
#
# def prnt(x, header=None):
#     print()
#     if header:
#         print(header)
#     if isinstance(x, list) and len(x):
#         for elem in x:
#             print('  ', elem)
#     elif isinstance(x, dict) and len(x) and isinstance(x.values()[0], list):
#         for k, v in x.items():
#             if isinstance(v,list) and len(v):
#                 print('  ', k, ':')
#                 for elem in v:
#                     print('    ', elem)
#             else:
#                 print('  ', k, ':', v)
#     else:
#         print(x)
#
# import os
# def mem():
#     # start your debug python session with harmless -R option to easily grep it out
#     os.system("ps -U root -o pid,user,rss:10,vsz:10,args:100 | grep 'python -R' | grep -v bin | grep -v grep")


@transactional_session
def apply_rule(did, rule, rses, source_rses, rseselector, *, session: "Session", logger=logging.log):
    """
    Apply a replication rule to one did.

    :param did:          the did object
    :param rule:         the rule object
    :param rses:         target rses_ids
    :param source_rses:  source rses_ids
    :param rseselector:  the rseselector object
    :param logger:       Optional decorated logger that can be passed from the calling daemons or servers.
    :param session:      the database session in use
    """

    max_partition_size = config_get_int('rules', 'apply_rule_max_partition_size', default=2000, session=session)  # process dataset files in bunches of max this size

    # accounting counters
    rse_counters_files = {}
    rse_counters_bytes = {}
    account_counters_files = {}
    account_counters_bytes = {}

    if did.did_type == DIDType.FILE:
        # NOTE: silently ignore rule.grouping
        if True:  # instead of -> if rule.grouping == RuleGrouping.NONE:
            locks = {}            # {(scope,name): [SQLAlchemy]}
            replicas = {}         # {(scope, name): [SQLAlchemy]}
            source_replicas = {}  # {(scope, name): [rse_id]
            # get files and replicas, lock the replicas
            replicas[(did.scope, did.name)] = rucio.core.replica.get_and_lock_file_replicas(scope=did.scope, name=did.name, nowait=True, restrict_rses=rses,
                                                                                            session=session)
            # prnt(did, 'file')
            # prnt(replicas, 'replicas')

            # get and lock the locks
            locks[(did.scope, did.name)] = rucio.core.lock.get_replica_locks(scope=did.scope, name=did.name, nowait=True, restrict_rses=rses,
                                                                             session=session)
            # prnt(locks, 'locks')

            # if needed get source replicas
            if source_rses:
                source_replicas[(did.scope, did.name)] = rucio.core.replica.get_source_replicas(scope=did.scope, name=did.name, source_rses=source_rses,
                                                                                                session=session)
            else:
                source_replicas = {}
            # prnt(source_replicas, 'source_replicas')

            # to align code with cases below, create file dict
            file = {'name': did.name, 'scope': did.scope,
                    'bytes': did.bytes, 'md5': did.md5, 'adler32': did.adler32}

            # calculate target RSEs
            rse_coverage = {replica.rse_id: file['bytes'] for replica in replicas[(file['scope'], file['name'])]}
            # prnt(rse_coverage)
            preferred_rse_ids = rse_coverage.keys()
            # prnt(preferred_rse_ids)
            rse_tuples = rseselector.select_rse(size=file['bytes'], preferred_rse_ids=preferred_rse_ids,
                                                prioritize_order_over_weight=True, existing_rse_size=rse_coverage)
            # prnt(rse_tuples)

            # initialize accumulators for __create_lock_and_replica calls
            locks_to_create = {}            # {'rse_id': [locks]}
            replicas_to_create = {}         # {'rse_id': [replicas]}
            transfers_to_create = []        # [{'dest_rse_id':, 'scope':, 'name':, 'request_type':, 'metadata':}]

            for rse_id, staging_area, availability_write in rse_tuples:
                # check for bug ????
                if len([lock for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id and lock.rse_id == rse_id]) == 1:
                    logger(logging.DEBUG, '>>> WARNING unexpected duplicate lock for file %s at RSE %s' % (file, rse_id))
                    continue
                # proceed
                __create_lock_and_replica(file=file, dataset={'scope': None, 'name': None}, rule=rule,
                                          rse_id=rse_id, staging_area=staging_area, availability_write=availability_write, source_rses=source_rses,
                                          replicas=replicas, locks=locks, source_replicas=source_replicas,
                                          locks_to_create=locks_to_create, replicas_to_create=replicas_to_create, transfers_to_create=transfers_to_create,
                                          session=session)

            # prnt(locks_to_create, 'locks_to_create')
            # prnt(replicas_to_create, 'replicas_to_create')
            # prnt(transfers_to_create, 'transfers_to_create')

            # flush to DB
            session.add_all([item for sublist in replicas_to_create.values() for item in sublist])
            session.add_all([item for sublist in locks_to_create.values() for item in sublist])
            request_core.queue_requests(requests=transfers_to_create, session=session)
            session.flush()

            # increment counters
            # align code with the one used inside the file loop below
            for rse_id in replicas_to_create.keys():
                rse_counters_files[rse_id] = len(replicas_to_create[rse_id]) + rse_counters_files.get(rse_id, 0)
                rse_counters_bytes[rse_id] = sum([replica.bytes for replica in replicas_to_create[rse_id]]) + rse_counters_bytes.get(rse_id, 0)
            # prnt(rse_counters_files, 'rse_counters_files')
            # prnt(rse_counters_bytes, 'rse_counters_bytes')

            for rse_id in locks_to_create.keys():
                account_counters_files[rse_id] = len(locks_to_create[rse_id]) + account_counters_files.get(rse_id, 0)
                account_counters_bytes[rse_id] = sum([lock.bytes for lock in locks_to_create[rse_id]]) + account_counters_bytes.get(rse_id, 0)
            # prnt(account_counters_files, 'account_counters_files')
            # prnt(account_counters_bytes, 'account_counters_bytes')

    else:
        # handle dataset case by converting it to singleton container case
        # NOTE: this will handle DATASET/ALL as if it was DATASET/DATASET
        datasets = []  # [(scope,name)]
        if did.did_type == DIDType.DATASET:
            datasets.append((did.scope, did.name, ))
        elif did.did_type == DIDType.CONTAINER:
            for child_dataset in rucio.core.did.list_child_datasets(scope=did.scope, name=did.name, session=session):
                # ensure theer are no duplicates
                newds = (child_dataset['scope'], child_dataset['name'], )
                if newds not in datasets:
                    datasets.append(newds)
        # sort alphabetically for deterministic order
        try:
            datasets = sorted(datasets)
        except Exception:
            pass

        # prnt(datasets)

        rse_coverage = {}   # rse_coverage = { rse_id : bytes }
        rse_tuples = []     # rse_tuples = [(rse_id, staging_area, availability_write)]
        used_rse_ids = []   # for NONE grouping keep track of actual used RSEs

        if rule.grouping == RuleGrouping.ALL:
            # calculate target RSEs
            nbytes = 0
            rse_coverage = {}
            # simply loop over child datasets
            # this is an approximation because ignoring the possibility of file overlap
            for ds_scope, ds_name in datasets:
                ds = rucio.core.did.get_did(scope=ds_scope, name=ds_name, dynamic_depth=DIDType.FILE, session=session)  # this will be retrieved again later on -> could be optimized
                nbytes += ds['bytes']
                one_rse_coverage = rucio.core.replica.get_RSEcoverage_of_dataset(scope=ds_scope, name=ds_name, session=session)
                for rse_id, bytes_ in one_rse_coverage.items():
                    rse_coverage[rse_id] = bytes_ + rse_coverage.get(rse_id, 0)

            # prnt(rse_coverage)
            preferred_rse_ids = [x[0] for x in sorted(rse_coverage.items(), key=lambda tup: tup[1], reverse=True)]
            # prnt(preferred_rse_ids)
            rse_tuples = rseselector.select_rse(size=nbytes, preferred_rse_ids=preferred_rse_ids,
                                                prioritize_order_over_weight=True, existing_rse_size=rse_coverage)
            # prnt(rse_tuples)

        for ds_scope, ds_name in datasets:
            # prnt(('processing dataset ',ds_scope, ds_name))
            #
            ds = rucio.core.did.get_did(scope=ds_scope, name=ds_name, dynamic_depth=DIDType.FILE, session=session)
            ds_length = ds['length']
            ds_bytes = ds['bytes']
            ds_open = ds['open']
            # prnt(ds)

            # calculate number of partitions based on nr of files
            npartitions = int(ds_length / max_partition_size) + 1
            # prnt(npartitions)

            if rule.grouping == RuleGrouping.DATASET:
                # calculate target RSEs
                rse_coverage = rucio.core.replica.get_RSEcoverage_of_dataset(scope=ds_scope, name=ds_name, session=session)
                # prnt(rse_coverage)
                preferred_rse_ids = [x[0] for x in sorted(rse_coverage.items(), key=lambda tup: tup[1], reverse=True)]
                # prnt(preferred_rse_ids)
                rse_tuples = rseselector.select_rse(size=ds_bytes, preferred_rse_ids=preferred_rse_ids,
                                                    prioritize_order_over_weight=True, existing_rse_size=rse_coverage)
                # prnt(rse_tuples)

            # loop over the partitions even if it is just one
            for p in range(npartitions):
                # prnt(('processing partition ', p, npartitions))

                # files is [{'scope':, 'name':, 'bytes':, 'md5':, 'adler32':}]
                # locks is {(scope,name): [SQLAlchemy]}
                # replicas = {(scope, name): [SQLAlchemy]}
                # source replicas is {(scope, name): [SQLAlchemy]}

                # get files and replicas, lock the replicas
                files, replicas = rucio.core.replica.get_and_lock_file_replicas_for_dataset(scope=ds_scope, name=ds_name, nowait=True, restrict_rses=rses,
                                                                                            total_threads=npartitions, thread_id=p, session=session)
                # prnt(files, 'files')
                # prnt(replicas, 'replicas')

                # get and lock the replica locks
                locks = rucio.core.lock.get_files_and_replica_locks_of_dataset(scope=ds_scope, name=ds_name, nowait=True, restrict_rses=rses,
                                                                               total_threads=npartitions, thread_id=p, session=session)
                # prnt(locks, 'locks')

                # if needed get source replicas
                if source_rses:
                    source_replicas = rucio.core.replica.get_source_replicas_for_dataset(scope=ds_scope, name=ds_name, source_rses=source_rses,
                                                                                         total_threads=npartitions, thread_id=p, session=session)
                else:
                    source_replicas = {}
                # prnt(source_replicas, 'source_replicas')

                # initialize accumulators for __create_lock_and_replica calls
                locks_to_create = {}            # {'rse_id': [locks]}
                replicas_to_create = {}         # {'rse_id': [replicas]}
                transfers_to_create = []        # [{'dest_rse_id':, 'scope':, 'name':, 'request_type':, 'metadata':}]

                # loop over the rse tuples
                for file in files:
                    # check for duplicate due to dataset overlap within container
                    if len([lock for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id]) == rule.copies:
                        logger(logging.DEBUG, '>>> WARNING skipping (shared?) file %s' % file)
                        continue

                    if rule.grouping == RuleGrouping.NONE:
                        # calculate target RSEs
                        rse_coverage = {replica.rse_id: file['bytes'] for replica in replicas[(file['scope'], file['name'])]}
                        # prnt(rse_coverage)
                        preferred_rse_ids = rse_coverage.keys()
                        # prnt(preferred_rse_ids)
                        rse_tuples = rseselector.select_rse(size=file['bytes'], preferred_rse_ids=preferred_rse_ids,
                                                            prioritize_order_over_weight=True, existing_rse_size=rse_coverage)
                        # prnt(rse_tuples)
                        # keep track of used RSEs
                        for rt in rse_tuples:
                            if not rt[0] in used_rse_ids:
                                used_rse_ids.append(rt[0])

                    for rse_id, staging_area, availability_write in rse_tuples:
                        # check for bug ????
                        if len([lock for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id and lock.rse_id == rse_id]) == 1:
                            logger(logging.DEBUG, '>>> WARNING unexpected duplicate lock for file %s at RSE %s' % (file, rse_id))
                            continue
                        # proceed
                        __create_lock_and_replica(file=file, dataset={'scope': ds_scope, 'name': ds_name}, rule=rule,
                                                  rse_id=rse_id, staging_area=staging_area, availability_write=availability_write, source_rses=source_rses,
                                                  replicas=replicas, locks=locks, source_replicas=source_replicas,
                                                  locks_to_create=locks_to_create, replicas_to_create=replicas_to_create, transfers_to_create=transfers_to_create,
                                                  session=session)

                # prnt(locks_to_create, 'locks_to_create')
                # prnt(replicas_to_create, 'replicas_to_create')
                # prnt(transfers_to_create, 'transfers_to_create')

                # flush to DB
                session.add_all([item for sublist in replicas_to_create.values() for item in sublist])
                session.add_all([item for sublist in locks_to_create.values() for item in sublist])
                request_core.queue_requests(requests=transfers_to_create, session=session)
                session.flush()

                # increment counters
                # do not update (and lock !) counters inside loop here, update at very end and only once
                for rse_id in replicas_to_create.keys():
                    rse_counters_files[rse_id] = len(replicas_to_create[rse_id]) + rse_counters_files.get(rse_id, 0)
                    rse_counters_bytes[rse_id] = sum([replica.bytes for replica in replicas_to_create[rse_id]]) + rse_counters_bytes.get(rse_id, 0)
                # prnt(rse_counters_files, 'rse_counters_files')
                # prnt(rse_counters_bytes, 'rse_counters_bytes')

                for rse_id in locks_to_create.keys():
                    account_counters_files[rse_id] = len(locks_to_create[rse_id]) + account_counters_files.get(rse_id, 0)
                    account_counters_bytes[rse_id] = sum([lock.bytes for lock in locks_to_create[rse_id]]) + account_counters_bytes.get(rse_id, 0)
                # prnt(account_counters_files, 'account_counters_files')
                # prnt(account_counters_bytes, 'account_counters_bytes')

                # mem()

            # dataset lock/replica
            u_rses = (used_rse_ids if rule.grouping == RuleGrouping.NONE else [x[0] for x in rse_tuples])
            # prnt(u_rses, 'used RSE ids')
            for u_rse in u_rses:
                # prnt('creating dataset lock/replica for %s on %s' % (ds_name,u_rse))
                if rule.grouping == RuleGrouping.DATASET or rule.grouping == RuleGrouping.ALL:
                    # add dataset lock
                    models.DatasetLock(scope=ds_scope, name=ds_name,
                                       rule_id=rule.id,
                                       rse_id=u_rse,
                                       state=LockState.REPLICATING,
                                       account=rule.account,
                                       length=ds_length if not ds_open else None,
                                       bytes=ds_bytes if not ds_open else None
                                       ).save(session=session)

                # add dataset replica if not already existing (rule_id is not in PK)
                try:
                    session.query(models.CollectionReplica).filter(models.CollectionReplica.scope == ds_scope,
                                                                   models.CollectionReplica.name == ds_name,
                                                                   models.CollectionReplica.rse_id == u_rse).one()
                except NoResultFound:
                    models.CollectionReplica(scope=ds_scope, name=ds_name, did_type=DIDType.DATASET,
                                             rse_id=u_rse,
                                             bytes=0, length=0, available_bytes=0, available_replicas_cnt=0,
                                             state=ReplicaState.UNAVAILABLE
                                             ).save(session=session)

                    models.UpdatedCollectionReplica(scope=ds_scope, name=ds_name, did_type=DIDType.DATASET
                                                    ).save(session=session)

    # update account and rse counters
    for rse_id in rse_counters_files:
        rse_counter.increase(rse_id=rse_id, files=rse_counters_files[rse_id], bytes_=rse_counters_bytes[rse_id], session=session)
    for rse_id in account_counters_files:
        account_counter.increase(rse_id=rse_id, account=rule.account, files=account_counters_files[rse_id], bytes_=account_counters_bytes[rse_id], session=session)
    session.flush()

    return
