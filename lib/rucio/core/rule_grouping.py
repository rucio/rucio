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
def apply_rule_grouping(datasetfiles, locks, replicas, rseselector, rule, preferred_rse_ids=[], session=None):
    """
    Apply rule grouping to files.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule object.
    :param preferred_rse_ids:  Preferred RSE's to select.
    :param session:            Session of the db.
    :returns:                  List of replicas to create, List of locks to create, List of transfers to create
    :raises:                   InsufficientQuota, ReplicationRuleCreationFailed, InsufficientTargetRSEs, InvalidReplicationRule
    :attention:                This method modifies the contents of the locks and replicas input parameters.
    """

    # locks_to_create =     {'rse_id': [locks]}
    # replicas_to_create =  {'rse_id': [replicas]}
    # transfers_to_create = [{'dest_rse_id':, 'scope':, 'name':, 'request_type':, 'metadata':}]

    if rule.grouping == RuleGrouping.NONE:
        replicas_to_create, locks_to_create, transfers_to_create = __apply_rule_to_files_none_grouping(datasetfiles=datasetfiles, locks=locks, replicas=replicas, rseselector=rseselector, rule=rule, preferred_rse_ids=preferred_rse_ids, session=session)
    elif rule.grouping == RuleGrouping.ALL:
        replicas_to_create, locks_to_create, transfers_to_create = __apply_rule_to_files_all_grouping(datasetfiles=datasetfiles, locks=locks, replicas=replicas, rseselector=rseselector, rule=rule, preferred_rse_ids=preferred_rse_ids, session=session)
    else:  # rule.grouping == RuleGrouping.DATASET:
        replicas_to_create, locks_to_create, transfers_to_create = __apply_rule_to_files_dataset_grouping(datasetfiles=datasetfiles, locks=locks, replicas=replicas, rseselector=rseselector, rule=rule, preferred_rse_ids=preferred_rse_ids, session=session)

    return replicas_to_create, locks_to_create, transfers_to_create


@transactional_session
def __apply_rule_to_files_none_grouping(datasetfiles, locks, replicas, rseselector, rule, preferred_rse_ids=[], session=None):
    """
    Apply a rule to files with NONE grouping.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule object.
    :param preferred_rse_ids:  Preferred RSE's to select.
    :param session:            Session of the db.
    :returns:                  replicas_to_create, locks_to_create, transfers_to_create
    :raises:                   InsufficientQuota, InsufficientTargetRSEs
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
                                                    preferred_rse_ids=[replica.rse_id for replica in replicas[(file['scope'], file['name'])]],
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
                                          replicas_to_create=replicas_to_create,
                                          replicas=replicas,
                                          transfers_to_create=transfers_to_create)

    return replicas_to_create, locks_to_create, transfers_to_create


@transactional_session
def __apply_rule_to_files_all_grouping(datasetfiles, locks, replicas, rseselector, rule, preferred_rse_ids=[], session=None):
    """
    Apply a rule to files with ALL grouping.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule object.
    :param preferred_rse_ids:  Preferred RSE's to select.
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
                if replica.rse_id in rse_coverage:
                    rse_coverage[replica.rse_id] += file['bytes']
                else:
                    rse_coverage[replica.rse_id] = file['bytes']
                if replica.state == ReplicaState.BEING_DELETED:
                    blacklist.add(replica.rse_id)
    if len(preferred_rse_ids) == 0:
        rse_tuples = rseselector.select_rse(bytes, [x[0] for x in sorted(rse_coverage.items(), key=lambda tup: tup[1], reverse=True)], list(blacklist))
    else:
        rse_tuples = rseselector.select_rse(bytes, preferred_rse_ids, list(blacklist))
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
def __apply_rule_to_files_dataset_grouping(datasetfiles, locks, replicas, rseselector, rule, preferred_rse_ids=[], session=None):
    """
    Apply a rule to files with ALL grouping.

    :param datasetfiles:       Dict holding all datasets and files.
    :param locks:              Dict holding all locks.
    :param replicas:           Dict holding all replicas.
    :param rseselector:        The RSESelector to be used.
    :param rule:               The rule object.
    :param preferred_rse_ids:  Preferred RSE's to select.
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
                if replica.rse_id in rse_coverage:
                    rse_coverage[replica.rse_id] += file['bytes']
                else:
                    rse_coverage[replica.rse_id] = file['bytes']
                if replica.state == ReplicaState.BEING_DELETED:
                    blacklist.add(replica.rse_id)
        if len(preferred_rse_ids) == 0:
            rse_tuples = rseselector.select_rse(bytes, [x[0] for x in sorted(rse_coverage.items(), key=lambda tup: tup[1], reverse=True)], list(blacklist))
        else:
            rse_tuples = rseselector.select_rse(bytes, preferred_rse_ids, list(blacklist))
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


def __create_lock_and_replica(file, dataset, rule, rse_id, staging_area, locks_to_create, locks, replicas_to_create, replicas, transfers_to_create):
    """
    This method creates a lock and if necessary a new replica and fills the corresponding dictionaries.

    :param file:                 File dictionary holding the file information.
    :param dataset:              Dataset dictionary holding the dataset information.
    :param rule:                 Rule object.
    :param rse_id:               RSE id the lock and replica should be created at.
    :param staging_area:         Boolean variable if the RSE is a staging area.
    :param locks_to_create:      Dictionary of the locks to create.
    :param locks:                Dictionary of all locks.
    :param replicas_to_create:   Dictionary of the replicas to create.
    :param replicas:             Dictionary of the replicas.
    :param transfers_to_create:  List of transfers to create.
    :returns:                    True, if the created lock is replicating, False otherwise.
    :attention:                  This method modifies the contents of the locks, locks_to_create, replicas_to_create and replicas input parameters.
    """

    existing_replicas = [replica for replica in replicas[(file['scope'], file['name'])] if replica.rse_id == rse_id]
    if len(existing_replicas) > 0:  # A replica already exists
        existing_replica = existing_replicas[0]
        if staging_area:  # Staging pin has to be extended
            lifetime = rule.expires_at - datetime.utcnow()
            lifetime = lifetime.seconds
            transfers_to_create.append({'dest_rse_id': rse_id,
                                        'scope': file['scope'],
                                        'name': file['name'],
                                        'attributes': {'lifetime': lifetime},
                                        'request_type': RequestType.STAGEIN})
        if existing_replica.state == ReplicaState.AVAILABLE:  # Replica is fully available
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
        else:  # Replica is not available at rse yet
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
        new_replica = __create_replica(rse_id=rse_id,
                                       scope=file['scope'],
                                       name=file['name'],
                                       bytes=file['bytes'],
                                       md5=file['md5'],
                                       adler32=file['adler32'],
                                       state=ReplicaState.UNAVAILABLE)
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
                                 state=LockState.REPLICATING)
        if rse_id not in locks_to_create:
            locks_to_create[rse_id] = []
        locks_to_create[rse_id].append(new_lock)
        locks[(file['scope'], file['name'])].append(new_lock)
        if staging_area:  # If the target RSE is a staging area
            lifetime = rule.expires_at - datetime.utcnow()
            lifetime = lifetime.seconds
            transfers_to_create.append({'dest_rse_id': rse_id,
                                        'scope': file['scope'],
                                        'name': file['name'],
                                        'attributes': {'lifetime': lifetime},
                                        'request_type': RequestType.STAGEIN})
        else:  # Target RSE is not a staging area
            transfers_to_create.append({'dest_rse_id': rse_id,
                                        'scope': file['scope'],
                                        'name': file['name'],
                                        'attributes': {},
                                        'request_type': RequestType.TRANSFER})

        return True


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
        existing_replica.lock_cnt += 1
        existing_replica.tombstone = None
        rule.locks_replicating_cnt += 1

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
