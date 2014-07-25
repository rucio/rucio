# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

from datetime import datetime

from sqlalchemy.orm.exc import NoResultFound

from rucio.db import models
from rucio.db.constants import LockState, RuleGrouping, ReplicaState, RequestType
from rucio.db.session import transactional_session


@transactional_session
def apply_rule_grouping(datasetfiles, locks, replicas, rseselector, rule, preferred_rse_ids=[], source_rses=[], session=None):
    """
    Apply rule grouping to files.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule object.
    :param preferred_rse_ids:  Preferred RSE's to select.
    :param source_rses:        RSE ids of eglible source replicas.
    :param session:            Session of the db.
    :returns:                  List of replicas to create, List of locks to create, List of transfers to create
    :raises:                   InsufficientQuota, InsufficientTargetRSEs
    :attention:                This method modifies the contents of the locks and replicas input parameters.
    """

    # locks_to_create =     {'rse_id': [locks]}
    # replicas_to_create =  {'rse_id': [replicas]}
    # transfers_to_create = [{'dest_rse_id':, 'scope':, 'name':, 'request_type':, 'metadata':}]

    if rule.grouping == RuleGrouping.NONE:
        replicas_to_create, locks_to_create,\
            transfers_to_create = __apply_rule_to_files_none_grouping(datasetfiles=datasetfiles,
                                                                      locks=locks,
                                                                      replicas=replicas,
                                                                      rseselector=rseselector,
                                                                      rule=rule,
                                                                      preferred_rse_ids=preferred_rse_ids,
                                                                      source_rses=source_rses,
                                                                      session=session)
    elif rule.grouping == RuleGrouping.ALL:
        replicas_to_create, locks_to_create,\
            transfers_to_create = __apply_rule_to_files_all_grouping(datasetfiles=datasetfiles,
                                                                     locks=locks,
                                                                     replicas=replicas,
                                                                     rseselector=rseselector,
                                                                     rule=rule,
                                                                     preferred_rse_ids=preferred_rse_ids,
                                                                     source_rses=source_rses,
                                                                     session=session)
    else:  # rule.grouping == RuleGrouping.DATASET:
        replicas_to_create, locks_to_create,\
            transfers_to_create = __apply_rule_to_files_dataset_grouping(datasetfiles=datasetfiles,
                                                                         locks=locks,
                                                                         replicas=replicas,
                                                                         rseselector=rseselector,
                                                                         rule=rule,
                                                                         preferred_rse_ids=preferred_rse_ids,
                                                                         source_rses=source_rses,
                                                                         session=session)

    return replicas_to_create, locks_to_create, transfers_to_create


@transactional_session
def repair_stuck_locks_and_apply_rule_grouping(datasetfiles, locks, replicas, rseselector, rule, source_rses, session=None):
    """
    Apply rule grouping to files.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
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
        replicas_to_create, locks_to_create, transfers_to_create,\
            locks_to_delete = __repair_stuck_locks_with_none_grouping(datasetfiles=datasetfiles,
                                                                      locks=locks,
                                                                      replicas=replicas,
                                                                      rseselector=rseselector,
                                                                      rule=rule,
                                                                      source_rses=source_rses,
                                                                      session=session)
    elif rule.grouping == RuleGrouping.ALL:
        replicas_to_create, locks_to_create, transfers_to_create,\
            locks_to_delete = __repair_stuck_locks_with_all_grouping(datasetfiles=datasetfiles,
                                                                     locks=locks,
                                                                     replicas=replicas,
                                                                     rseselector=rseselector,
                                                                     rule=rule,
                                                                     source_rses=source_rses,
                                                                     session=session)
    else:
        replicas_to_create, locks_to_create, transfers_to_create,\
            locks_to_delete = __repair_stuck_locks_with_dataset_grouping(datasetfiles=datasetfiles,
                                                                         locks=locks,
                                                                         replicas=replicas,
                                                                         rseselector=rseselector,
                                                                         rule=rule,
                                                                         source_rses=source_rses,
                                                                         session=session)
    return replicas_to_create, locks_to_create, transfers_to_create, locks_to_delete


def create_transfer_dict(dest_rse_id, request_type, scope, name, rule, ds_scope=None, ds_name=None, lifetime=None):
    """
    This method creates a transfer dictionary and returns it

    :param dest_rse_id:   The destination RSE id.
    :param request_Type:  The request type.
    :param scope:         The scope of the file.
    :param name:          The name of the file.
    :param rule:          The rule responsible for the transfer.
    :param ds_scope:      Dataset the file belongs to.
    :param ds_name:       Dataset the file belongs to.
    :param lifetime:      Lifetime in the case of STAGIN requests.
    :returns:             Request dictionary.
    """
    attributes = {'activity': rule.activity,
                  'source_replica_expression': rule.source_replica_expression,
                  'lifetime': lifetime,
                  'ds_scope': ds_scope,
                  'ds_name': ds_name}

    return {'dest_rse_id': dest_rse_id,
            'scope': scope,
            'name': name,
            'rule_id': rule.id,
            'attributes': attributes,
            'request_type': request_type}


@transactional_session
def __apply_rule_to_files_none_grouping(datasetfiles, locks, replicas, rseselector, rule, preferred_rse_ids=[], source_rses=[], session=None):
    """
    Apply a rule to files with NONE grouping.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
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
        for file in dataset['files']:
            if len([lock for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id]) == rule.copies:
                # Nothing to do as the file already has the requested amount of locks
                continue
            if len(preferred_rse_ids) == 0:
                rse_tuples = rseselector.select_rse(size=file['bytes'],
                                                    preferred_rse_ids=[replica.rse_id for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.AVAILABLE or replica.state == ReplicaState.COPYING],
                                                    blacklist=[replica.rse_id for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.BEING_DELETED])
            else:
                rse_tuples = rseselector.select_rse(size=file['bytes'],
                                                    preferred_rse_ids=preferred_rse_ids,
                                                    blacklist=[replica.rse_id for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.BEING_DELETED])
            for rse_tuple in rse_tuples:
                __create_lock_and_replica(file=file,
                                          dataset=dataset,
                                          rule=rule,
                                          rse_id=rse_tuple[0],
                                          staging_area=rse_tuple[1],
                                          locks_to_create=locks_to_create,
                                          locks=locks,
                                          source_rses=source_rses,
                                          replicas_to_create=replicas_to_create,
                                          replicas=replicas,
                                          transfers_to_create=transfers_to_create)

    return replicas_to_create, locks_to_create, transfers_to_create


@transactional_session
def __apply_rule_to_files_all_grouping(datasetfiles, locks, replicas, rseselector, rule, preferred_rse_ids=[], source_rses=[], session=None):
    """
    Apply a rule to files with ALL grouping.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
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

    bytes = 0
    rse_coverage = {}  # {'rse_id': coverage }
    blacklist = set()
    for dataset in datasetfiles:
        for file in dataset['files']:
            bytes += file['bytes']
            for replica in replicas[(file['scope'], file['name'])]:
                if replica.state == ReplicaState.BEING_DELETED:
                    blacklist.add(replica.rse_id)
                    continue
                if replica.state == ReplicaState.AVAILABLE or replica.state == ReplicaState.COPYING:
                    if replica.rse_id in rse_coverage:
                        rse_coverage[replica.rse_id] += file['bytes']
                    else:
                        rse_coverage[replica.rse_id] = file['bytes']

    if len(preferred_rse_ids) == 0:
        rse_tuples = rseselector.select_rse(size=bytes,
                                            preferred_rse_ids=[x[0] for x in sorted(rse_coverage.items(), key=lambda tup: tup[1], reverse=True)],
                                            blacklist=list(blacklist))
    else:
        rse_tuples = rseselector.select_rse(size=bytes,
                                            preferred_rse_ids=preferred_rse_ids,
                                            blacklist=list(blacklist))
    for rse_tuple in rse_tuples:
        for dataset in datasetfiles:
            dataset_is_replicating = False
            for file in dataset['files']:
                if len([lock for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id]) == rule.copies:
                    continue
                if __create_lock_and_replica(file=file,
                                             dataset=dataset,
                                             rule=rule,
                                             rse_id=rse_tuple[0],
                                             staging_area=rse_tuple[1],
                                             locks_to_create=locks_to_create,
                                             locks=locks,
                                             source_rses=source_rses,
                                             replicas_to_create=replicas_to_create,
                                             replicas=replicas,
                                             transfers_to_create=transfers_to_create):
                    dataset_is_replicating = True
            # Add a DatasetLock to the DB
            if dataset['scope'] is not None:
                try:
                    dslock = session.query(models.DatasetLock).filter(models.DatasetLock.scope == dataset['scope'],
                                                                      models.DatasetLock.name == dataset['name'],
                                                                      models.DatasetLock.rule_id == rule.id,
                                                                      models.DatasetLock.rse_id == rse_tuple[0]).one()
                    if dataset_is_replicating:
                        dslock.state = LockState.REPLICATING
                except NoResultFound:
                    models.DatasetLock(scope=dataset['scope'],
                                       name=dataset['name'],
                                       rule_id=rule.id,
                                       rse_id=rse_tuple[0],
                                       state=LockState.REPLICATING if dataset_is_replicating else LockState.OK,
                                       account=rule.account).save(flush=False, session=session)

    return replicas_to_create, locks_to_create, transfers_to_create


@transactional_session
def __apply_rule_to_files_dataset_grouping(datasetfiles, locks, replicas, rseselector, rule, preferred_rse_ids=[], source_rses=[], session=None):
    """
    Apply a rule to files with ALL grouping.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
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
        bytes = sum([file['bytes'] for file in dataset['files']])
        rse_coverage = {}  # {'rse_id': coverage }
        blacklist = set()
        for file in dataset['files']:
            for replica in replicas[(file['scope'], file['name'])]:
                if replica.state == ReplicaState.BEING_DELETED:
                    blacklist.add(replica.rse_id)
                    continue
                if replica.state == ReplicaState.AVAILABLE or replica.state == ReplicaState.COPYING:
                    if replica.rse_id in rse_coverage:
                        rse_coverage[replica.rse_id] += file['bytes']
                    else:
                        rse_coverage[replica.rse_id] = file['bytes']

        if len(preferred_rse_ids) == 0:
            rse_tuples = rseselector.select_rse(size=bytes,
                                                preferred_rse_ids=[x[0] for x in sorted(rse_coverage.items(), key=lambda tup: tup[1], reverse=True)],
                                                blacklist=list(blacklist))
        else:
            rse_tuples = rseselector.select_rse(size=bytes,
                                                preferred_rse_ids=preferred_rse_ids,
                                                blacklist=list(blacklist))
        for rse_tuple in rse_tuples:
            dataset_is_replicating = False
            for file in dataset['files']:
                if len([lock for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id]) == rule.copies:
                    continue
                if __create_lock_and_replica(file=file,
                                             dataset=dataset,
                                             rule=rule,
                                             rse_id=rse_tuple[0],
                                             staging_area=rse_tuple[1],
                                             locks_to_create=locks_to_create,
                                             locks=locks,
                                             source_rses=source_rses,
                                             replicas_to_create=replicas_to_create,
                                             replicas=replicas,
                                             transfers_to_create=transfers_to_create):
                    dataset_is_replicating = True
            # Add a DatasetLock to the DB
            if dataset['scope'] is not None:
                try:
                    dslock = session.query(models.DatasetLock).filter(models.DatasetLock.scope == dataset['scope'],
                                                                      models.DatasetLock.name == dataset['name'],
                                                                      models.DatasetLock.rule_id == rule.id,
                                                                      models.DatasetLock.rse_id == rse_tuple[0]).one()
                    if dataset_is_replicating:
                        dslock.state = LockState.REPLICATING
                except NoResultFound:
                    models.DatasetLock(scope=dataset['scope'],
                                       name=dataset['name'],
                                       rule_id=rule.id,
                                       rse_id=rse_tuple[0],
                                       state=LockState.REPLICATING if dataset_is_replicating else LockState.OK,
                                       account=rule.account).save(flush=False, session=session)

    return replicas_to_create, locks_to_create, transfers_to_create


@transactional_session
def __repair_stuck_locks_with_none_grouping(datasetfiles, locks, replicas, rseselector, rule, source_rses, session=None):
    """
    Apply a rule to files with NONE grouping.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule object.
    :param source_rses:        RSE ids of eglible source replicas.
    :param session:            Session of the db.
    :returns:                  replicas_to_create, locks_to_create, transfers_to_create, locks_to_delete
    :raises:                   InsufficientAccountLimit, InsufficientTargetRSEs
    :attention:                This method modifies the contents of the locks and replicas input parameters.
    """

    locks_to_create = {}            # {'rse_id': [locks]}
    replicas_to_create = {}         # {'rse_id': [replicas]}
    transfers_to_create = []        # [{'dest_rse_id':, 'scope':, 'name':, 'request_type':, 'metadata':}]
    locks_to_delete = {}            # {'rse_id': [locks]}

    # Iterate the datasetfiles structure and search for stuck locks
    for dataset in datasetfiles:
        for file in dataset['files']:
            # Iterate and try to repair STUCK locks
            for lock in [lock for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id and lock.state == LockState.STUCK]:
                # Check if this is a STUCK lock due to source_replica filtering
                if source_rses:
                    associated_replica = [replica for replica in replicas[(file['scope'], file['name'])] if replica.rse_id == lock.rse_id][0]
                    # Check if there is an eglible source replica for this lock
                    if [replica for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.AVAILABLE and replica.rse_id in source_rses]:
                        __update_lock_replica_and_create_transfer(lock=lock,
                                                                  replica=associated_replica,
                                                                  rule=rule,
                                                                  source_rses=[replica.rse_id for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.AVAILABLE and replica.rse_id in source_rses],
                                                                  transfers_to_create=transfers_to_create)
                else:
                    blacklist_rses = [lock.rse_id for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id]
                    rse_tuples = rseselector.select_rse(size=file['bytes'],
                                                        preferred_rse_ids=[replica.rse_id for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.AVAILABLE or replica.state == ReplicaState.COPYING],
                                                        copies=1,
                                                        blacklist=[replica.rse_id for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.BEING_DELETED] + blacklist_rses + [lock.rse_id])
                    for rse_tuple in rse_tuples:
                        __create_lock_and_replica(file=file,
                                                  dataset=dataset,
                                                  rule=rule,
                                                  rse_id=rse_tuple[0],
                                                  staging_area=rse_tuple[1],
                                                  locks_to_create=locks_to_create,
                                                  locks=locks,
                                                  source_rses=source_rses,
                                                  replicas_to_create=replicas_to_create,
                                                  replicas=replicas,
                                                  transfers_to_create=transfers_to_create)
                        rule.locks_stuck_cnt -= 1
                        if lock.rse_id in locks_to_delete:
                            locks_to_delete[lock.rse_id].append(lock)
                        else:
                            locks_to_delete[lock.rse_id] = [lock]

    return replicas_to_create, locks_to_create, transfers_to_create, locks_to_delete


@transactional_session
def __repair_stuck_locks_with_all_grouping(datasetfiles, locks, replicas, rseselector, rule, source_rses, session=None):
    """
    Apply a rule to files with ALL grouping.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule object.
    :param source_rses:        RSE ids of eglible source replicas.
    :param session:            Session of the db.
    :returns:                  replicas_to_create, locks_to_create, transfers_to_create, locks_to_delete
    :raises:                   InsufficientAccountLimit, InsufficientTargetRSEs
    :attention:                This method modifies the contents of the locks and replicas input parameters.
    """

    locks_to_create = {}            # {'rse_id': [locks]}
    replicas_to_create = {}         # {'rse_id': [replicas]}
    transfers_to_create = []        # [{'dest_rse_id':, 'scope':, 'name':, 'request_type':, 'metadata':}]
    locks_to_delete = {}            # {'rse_id': [locks]}

    # Iterate the datasetfiles structure and search for stuck locks
    alternative_rses = []
    for dataset in datasetfiles:
        for file in dataset['files']:
            # Iterate and try to repair STUCK locks
            for lock in [lock for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id and lock.state == LockState.STUCK]:
                # Check if this is a STUCK lock due to source_replica filtering
                if source_rses:
                    associated_replica = [replica for replica in replicas[(file['scope'], file['name'])] if replica.rse_id == lock.rse_id][0]
                    # Check if there is an eglible source replica for this lock
                    if [replica for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.AVAILABLE and replica.rse_id in source_rses]:
                        __update_lock_replica_and_create_transfer(lock=lock,
                                                                  replica=associated_replica,
                                                                  rule=rule,
                                                                  source_rses=[replica.rse_id for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.AVAILABLE and replica.rse_id in source_rses],
                                                                  transfers_to_create=transfers_to_create)
                else:
                    blacklist_rses = [lock.rse_id for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id]
                    if not alternative_rses:
                        rse_tuples = rseselector.select_rse(size=file['bytes'],
                                                            preferred_rse_ids=[replica.rse_id for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.AVAILABLE or replica.state == ReplicaState.COPYING],
                                                            copies=1,
                                                            blacklist=[replica.rse_id for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.BEING_DELETED] + blacklist_rses + [lock.rse_id])
                    else:
                        rse_tuples = rseselector.select_rse(size=file['bytes'],
                                                            preferred_rse_ids=alternative_rses,
                                                            copies=1,
                                                            blacklist=[replica.rse_id for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.BEING_DELETED] + blacklist_rses + [lock.rse_id])
                    for rse_tuple in rse_tuples:
                        if rse_tuple[0] not in alternative_rses:
                            alternative_rses.append(rse_tuple[0])
                        __create_lock_and_replica(file=file,
                                                  dataset=dataset,
                                                  rule=rule,
                                                  rse_id=rse_tuple[0],
                                                  staging_area=rse_tuple[1],
                                                  locks_to_create=locks_to_create,
                                                  locks=locks,
                                                  source_rses=source_rses,
                                                  replicas_to_create=replicas_to_create,
                                                  replicas=replicas,
                                                  transfers_to_create=transfers_to_create)
                        rule.locks_stuck_cnt -= 1
                        if lock.rse_id in locks_to_delete:
                            locks_to_delete[lock.rse_id].append(lock)
                        else:
                            locks_to_delete[lock.rse_id] = [lock]

    return replicas_to_create, locks_to_create, transfers_to_create, locks_to_delete


@transactional_session
def __repair_stuck_locks_with_dataset_grouping(datasetfiles, locks, replicas, rseselector, rule, source_rses, session=None):
    """
    Apply a rule to files with DATASET grouping.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule object.
    :param source_rses:        RSE ids of eglible source replicas.
    :param session:            Session of the db.
    :returns:                  replicas_to_create, locks_to_create, transfers_to_create, locks_to_delete
    :raises:                   InsufficientAccountLimit, InsufficientTargetRSEs
    :attention:                This method modifies the contents of the locks and replicas input parameters.
    """

    locks_to_create = {}            # {'rse_id': [locks]}
    replicas_to_create = {}         # {'rse_id': [replicas]}
    transfers_to_create = []        # [{'dest_rse_id':, 'scope':, 'name':, 'request_type':, 'metadata':}]
    locks_to_delete = {}            # {'rse_id': [locks]}

    # Iterate the datasetfiles structure and search for stuck locks
    for dataset in datasetfiles:
        alternative_rses = []
        for file in dataset['files']:
            # Iterate and try to repair STUCK locks
            for lock in [lock for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id and lock.state == LockState.STUCK]:
                # Check if this is a STUCK lock due to source_replica filtering
                if source_rses:
                    associated_replica = [replica for replica in replicas[(file['scope'], file['name'])] if replica.rse_id == lock.rse_id][0]
                    # Check if there is an eglible source replica for this lock
                    if [replica for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.AVAILABLE and replica.rse_id in source_rses]:
                        __update_lock_replica_and_create_transfer(lock=lock,
                                                                  replica=associated_replica,
                                                                  rule=rule,
                                                                  source_rses=[replica.rse_id for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.AVAILABLE and replica.rse_id in source_rses],
                                                                  transfers_to_create=transfers_to_create)
                else:
                    blacklist_rses = [lock.rse_id for lock in locks[(file['scope'], file['name'])] if lock.rule_id == rule.id]
                    if not alternative_rses:
                        rse_tuples = rseselector.select_rse(size=file['bytes'],
                                                            preferred_rse_ids=[replica.rse_id for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.AVAILABLE or replica.state == ReplicaState.COPYING],
                                                            copies=1,
                                                            blacklist=[replica.rse_id for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.BEING_DELETED] + blacklist_rses + [lock.rse_id])
                    else:
                        rse_tuples = rseselector.select_rse(size=file['bytes'],
                                                            preferred_rse_ids=alternative_rses,
                                                            copies=1,
                                                            blacklist=[replica.rse_id for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.BEING_DELETED] + blacklist_rses + [lock.rse_id])
                    for rse_tuple in rse_tuples:
                        if rse_tuple[0] not in alternative_rses:
                            alternative_rses.append(rse_tuple[0])
                        __create_lock_and_replica(file=file,
                                                  dataset=dataset,
                                                  rule=rule,
                                                  rse_id=rse_tuple[0],
                                                  staging_area=rse_tuple[1],
                                                  locks_to_create=locks_to_create,
                                                  locks=locks,
                                                  source_rses=source_rses,
                                                  replicas_to_create=replicas_to_create,
                                                  replicas=replicas,
                                                  transfers_to_create=transfers_to_create)
                        rule.locks_stuck_cnt -= 1
                        if lock.rse_id in locks_to_delete:
                            locks_to_delete[lock.rse_id].append(lock)
                        else:
                            locks_to_delete[lock.rse_id] = [lock]

    return replicas_to_create, locks_to_create, transfers_to_create, locks_to_delete


def __create_lock_and_replica(file, dataset, rule, rse_id, staging_area, locks_to_create, locks, source_rses, replicas_to_create, replicas, transfers_to_create):
    """
    This method creates a lock and if necessary a new replica and fills the corresponding dictionaries.

    :param file:                 File dictionary holding the file information.
    :param dataset:              Dataset dictionary holding the dataset information.
    :param rule:                 Rule object.
    :param rse_id:               RSE id the lock and replica should be created at.
    :param staging_area:         Boolean variable if the RSE is a staging area.
    :param locks_to_create:      Dictionary of the locks to create.
    :param locks:                Dictionary of all locks.
    :param source_rses:          RSE ids of eglible source replicas.
    :param replicas_to_create:   Dictionary of the replicas to create.
    :param replicas:             Dictionary of the replicas.
    :param transfers_to_create:  List of transfers to create.
    :returns:                    True, if the created lock is replicating, False otherwise.
    :attention:                  This method modifies the contents of the locks, locks_to_create, replicas_to_create and replicas input parameters.
    """

    # If it is a Staging Area, the pin has to be extended
    if staging_area:
        lifetime = rule.expires_at - datetime.utcnow()
        lifetime = lifetime.seconds
        transfers_to_create.append(create_transfer_dict(dest_rse_id=rse_id,
                                                        request_type=RequestType.STAGEIN,
                                                        scope=file['scope'],
                                                        name=file['name'],
                                                        rule=rule,
                                                        ds_scope=dataset['scope'],
                                                        ds_name=dataset['name'],
                                                        lifetime=lifetime))

    existing_replicas = [replica for replica in replicas[(file['scope'], file['name'])] if replica.rse_id == rse_id]

    if len(existing_replicas) > 0:  # A replica already exists (But could be UNAVAILABLE)
        existing_replica = existing_replicas[0]

        # Replica is fully available -- AVAILABLE
        if existing_replica.state == ReplicaState.AVAILABLE:
            new_lock = __create_lock(rule=rule,
                                     rse_id=rse_id,
                                     scope=file['scope'],
                                     name=file['name'],
                                     bytes=file['bytes'],
                                     existing_replica=existing_replica,
                                     state=LockState.OK)
            if rse_id not in locks_to_create:
                locks_to_create[rse_id] = []
            locks_to_create[rse_id].append(new_lock)
            locks[(file['scope'], file['name'])].append(new_lock)
            return False

        # Replica is not available -- UNAVAILABLE
        elif existing_replica.state == ReplicaState.UNAVAILABLE:
            available_source_replica = True
            if source_rses:
                available_source_replica = False
                # Check if there is an eglible source replica for this lock
                for replica in [replica for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.AVAILABLE]:
                    if replica.rse_id in source_rses:
                        available_source_replica = True
                        break
            new_lock = __create_lock(rule=rule,
                                     rse_id=rse_id,
                                     scope=file['scope'],
                                     name=file['name'],
                                     bytes=file['bytes'],
                                     existing_replica=existing_replica,
                                     state=LockState.REPLICATING if available_source_replica else LockState.STUCK)
            if rse_id not in locks_to_create:
                locks_to_create[rse_id] = []
            locks_to_create[rse_id].append(new_lock)
            locks[(file['scope'], file['name'])].append(new_lock)
            if not staging_area and available_source_replica:
                transfers_to_create.append(create_transfer_dict(dest_rse_id=rse_id,
                                                                request_type=RequestType.TRANSFER,
                                                                scope=file['scope'],
                                                                name=file['name'],
                                                                rule=rule,
                                                                ds_scope=dataset['scope'],
                                                                ds_name=dataset['name']))
                return True
            return False
        # Replica is not available at the rse yet -- COPYING
        else:
            new_lock = __create_lock(rule=rule,
                                     rse_id=rse_id,
                                     scope=file['scope'],
                                     name=file['name'],
                                     bytes=file['bytes'],
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
            for replica in [replica for replica in replicas[(file['scope'], file['name'])] if replica.state == ReplicaState.AVAILABLE]:
                if replica.rse_id in source_rses:
                    available_source_replica = True
                    break

        new_replica = __create_replica(rse_id=rse_id,
                                       scope=file['scope'],
                                       name=file['name'],
                                       bytes=file['bytes'],
                                       md5=file['md5'],
                                       adler32=file['adler32'],
                                       state=ReplicaState.COPYING if available_source_replica else ReplicaState.UNAVAILABLE)
        if rse_id not in replicas_to_create:
            replicas_to_create[rse_id] = []
        replicas_to_create[rse_id].append(new_replica)
        replicas[(file['scope'], file['name'])].append(new_replica)

        new_lock = __create_lock(rule=rule,
                                 rse_id=rse_id,
                                 scope=file['scope'],
                                 name=file['name'],
                                 bytes=file['bytes'],
                                 existing_replica=new_replica,
                                 state=LockState.REPLICATING if available_source_replica else LockState.STUCK)
        if rse_id not in locks_to_create:
            locks_to_create[rse_id] = []
        locks_to_create[rse_id].append(new_lock)
        locks[(file['scope'], file['name'])].append(new_lock)

        if not staging_area:  # Target RSE is not a staging area
            if available_source_replica:
                transfers_to_create.append(create_transfer_dict(dest_rse_id=rse_id,
                                                                request_type=RequestType.TRANSFER,
                                                                scope=file['scope'],
                                                                name=file['name'],
                                                                rule=rule,
                                                                ds_scope=dataset['scope'],
                                                                ds_name=dataset['name']))

        if available_source_replica:
            return True
        else:
            return False


def __create_lock(rule, rse_id, scope, name, bytes, state, existing_replica):
    """
    Create and return a new SQLAlchemy Lock object.

    :param rule:              The SQLAlchemy rule object.
    :param rse_id:            The rse_id of the lock.
    :param scope:             The scope of the lock.
    :param name:              The name of the lock.
    :param bytes:             Bytes of the lock.
    :param state:             State of the lock.
    :param existing_replica:  Replica object.
    """

    new_lock = models.ReplicaLock(rule_id=rule.id,
                                  rse_id=rse_id,
                                  scope=scope,
                                  name=name,
                                  account=rule.account,
                                  bytes=bytes,
                                  state=state)
    if state == LockState.OK:
        existing_replica.lock_cnt += 1
        existing_replica.tombstone = None
        rule.locks_ok_cnt += 1
    elif state == LockState.REPLICATING:
        existing_replica.state = ReplicaState.COPYING
        existing_replica.lock_cnt += 1
        existing_replica.tombstone = None
        rule.locks_replicating_cnt += 1
    elif state == LockState.STUCK:
        existing_replica.lock_cnt += 1
        existing_replica.tombstone = None
        rule.locks_stuck_cnt += 1
    return new_lock


def __create_replica(rse_id, scope, name, bytes, state, md5, adler32):
    """
    Create and return a new SQLAlchemy replica object.

    :param rse_id:        RSE id of the replica.
    :param scope:         Scope of the replica.
    :param name:          Name of the replica.
    :param bytes:         Bytes of the replica.
    :param state:         State of the replica.
    :param md5:           MD5 checksum of the replica.
    :param adler32:       ADLER32 checksum of the replica.
    """

    new_replica = models.RSEFileAssociation(rse_id=rse_id,
                                            scope=scope,
                                            name=name,
                                            bytes=bytes,
                                            md5=md5,
                                            adler32=adler32,
                                            tombstone=None,
                                            state=state,
                                            lock_cnt=0)
    return new_replica


def __update_lock_replica_and_create_transfer(lock, replica, rule, source_rses, transfers_to_create):
    """
    This method creates a lock and if necessary a new replica and fills the corresponding dictionaries.

    :param lock:                 The lock to update.
    :param replica:              The replica to update.
    :param rule:                 Rule to update.
    :param source_rses:          RSE ids of eglible source replicas.
    :param transfers_to_create:  List of transfers to create.
    :attention:                  This method modifies the contents of the transfers_to_create input parameters.
    """

    lock.state = LockState.REPLICATING
    rule.locks_stuck_cnt -= 1
    rule.locks_replicating_cnt += 1
    replica.state = ReplicaState.COPYING
    transfers_to_create.append(create_transfer_dict(dest_rse_id=lock.rse_id,
                                                    scope=lock.scope,
                                                    name=lock.name,
                                                    rule=rule,
                                                    request_type=RequestType.TRANSFER))
