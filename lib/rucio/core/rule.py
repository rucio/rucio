# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Martin Barisits, <martin.barisits@cern.ch>, 2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

from datetime import datetime

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql.expression import and_
from sqlalchemy.orm import aliased

from rucio.core.did import list_child_dids, list_parent_dids, list_files
from rucio.common.exception import InvalidRSEExpression, InvalidReplicationRule, InsufficientQuota, DataIdentifierNotFound, RuleNotFound, RSENotFound
from rucio.core.lock import get_replica_locks, get_files_and_replica_locks_of_dataset
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.request import queue_request
from rucio.core.rse_selector import RSESelector
from rucio.db import models
from rucio.db.constants import LockState, RuleState, RuleGrouping, DIDReEvaluation
from rucio.db.session import read_session, transactional_session


@transactional_session
def add_replication_rule(dids, account, copies, rse_expression, grouping, weight, lifetime, locked, subscription_id, session=None):
    """
    Adds a replication rule for every did in dids

    :param dids:             List of data identifiers.
    :param account:          Account issuing the rule.
    :param copies:           The number of replicas.
    :param rse_expression:   RSE expression which gets resolved into a list of rses.
    :param grouping:         ALL -  All files will be replicated to the same RSE.
                             DATASET - All files in the same dataset will be replicated to the same RSE.
                             NONE - Files will be completely spread over all allowed RSEs without any grouping considerations at all.
    :param weight:           Weighting scheme to be used.
    :param lifetime:         The lifetime of the replication rule.
    :type lifetime:          datetime.timedelta
    :param locked:           If the rule is locked.
    :param subscription_id:  The subscription_id, if the rule is created by a subscription.
    :param session:          The database session in use.
    :returns:                A list of created replication rule ids.
    :raises:                 InvalidReplicationRule, InsufficientQuota, InvalidRSEExpression, DataIdentifierNotFound
    """

    # 1. Resolve the rse_expression into a list of RSE-ids
    rse_ids = parse_expression(rse_expression, session=session)
    selector = RSESelector(account=account, rse_ids=rse_ids, weight=weight, copies=copies, session=session)

    transfers_to_create = []
    rule_ids = []

    for elem in dids:
        # 2. Get and lock the did
        try:
            did = session.query(models.DataIdentifier).filter_by(
                scope=elem['scope'],
                name=elem['name'],
                deleted=False).with_lockmode('update').one()
        except NoResultFound:
            raise DataIdentifierNotFound('Data identifier %s:%s is not valid.' % (elem['scope'], elem['name']))
        # 3. Create the replication rule
        if grouping == 'ALL':
            grouping = RuleGrouping.ALL
        elif grouping == 'NONE':
            grouping = RuleGrouping.NONE
        else:
            grouping = RuleGrouping.DATASET
        new_rule = models.ReplicationRule(account=account, name=elem['name'], scope=elem['scope'], copies=copies, rse_expression=rse_expression, locked=locked, grouping=grouping, expires_at=lifetime, weight=weight, subscription_id=subscription_id)
        try:
            new_rule.save(session=session)
        except IntegrityError, e:
            raise InvalidReplicationRule(e.args[0])
        rule_id = new_rule.id
        rule_ids.append(rule_id)
        # 4. Resolve the did
        datasetfiles = __resolve_dids_to_locks(did, session=session)
        # 5. Apply the replication rule to create locks and return a list of transfers
        transfers_to_create = __create_locks_for_rule(datasetfiles=datasetfiles,
                                                      rseselector=selector,
                                                      account=account,
                                                      rule_id=rule_id,
                                                      copies=copies,
                                                      grouping=grouping,
                                                      session=session)

    # 6. Create the transfers
    if len(transfers_to_create) > 0:
        for transfer in transfers_to_create:
            queue_request(scope=transfer['scope'], name=transfer['name'], dest_rse_id=transfer['rse_id'], req_type='TRANSFER')
    else:
        # No transfers need to be created, the rule is SATISFIED
        new_rule.state = RuleState.OK
        new_rule.save(session=session)
    return rule_ids


@transactional_session
def __resolve_dids_to_locks(did, session=None):
    """
    Resolves a did to its constituent childs and reads the locks of all the constituent files.

    :param did:          The db object of the did the rule is applied on.
    :param session:      Session of the db.
    :returns:            datasetfiles dict.
    """

    datasetfiles = []  # List of Datasets and their files in the Tree [{'scope':, 'name':, 'files:}]
                       # Files are in the format [{'scope': ,'name':, 'bytes':, 'locks': [{'rse_id':, 'state':, 'rule_id':}]}]

    # a) Resolve the did
    if did.type == 'file':
        files = [{'scope': did.scope, 'name': did.name, 'bytes': did.bytes, 'locks': get_replica_locks(scope=did.scope, name=did.name)}]
        datasetfiles = [{'scope': None, 'name': None, 'files': files}]
    elif did.type == 'dataset':
        tmp_locks = get_files_and_replica_locks_of_dataset(scope=did.scope, name=did.name)
        datasetfiles = [{'scope': did.scope, 'name': did.name, 'files': tmp_locks.values()}]
    elif did.type == 'container':
        for dscont in list_child_dids(scope=did.scope, name=did.name, lock=True, session=session):
            tmp_locks = get_files_and_replica_locks_of_dataset(scope=dscont['scope'], name=dscont['name'])
            datasetfiles.append({'scope': dscont['scope'], 'name': dscont['name'], 'files': tmp_locks.values()})
    return datasetfiles


@transactional_session
def __create_locks_for_rule(datasetfiles, rseselector, account, rule_id, copies, grouping, preferred_rse_ids=[], session=None):
    """
    Apply a created replication rule to a did

    :param datasetfiles:       Special dict holding all datasets and files.
    :param rseselector:        The RSESelector to be used.
    :param account:            The account.
    :param rule_id:            The rule_id.
    :param copies:             Number of copies.
    :param grouping:           The grouping to be used.
    :param preferred_rse_ids:  Preferred RSE's to select.
    :param session:            Session of the db.
    :returns:                  List of transfers to create
    :raises:                   InsufficientQuota
    """

    locks_to_create = []      # DB Objects
    transfers_to_create = []  # [{'rse_id': rse_id, 'scope': file['scope'], 'name': file['name']}]

    if grouping == RuleGrouping.NONE:
        # ########
        # # NONE #
        # ########
        for dataset in datasetfiles:
            for file in dataset['files']:
                if len([lock for lock in file['locks'] if lock['rule_id'] == rule_id]) == copies:
                    continue
                if len(preferred_rse_ids) == 0:
                    rse_ids = rseselector.select_rse(file['bytes'], [lock['rse_id'] for lock in file['locks']])
                else:
                    rse_ids = rseselector.select_rse(file['bytes'], preferred_rse_ids)
                for rse_id in rse_ids:
                    if rse_id in [lock['rse_id'] for lock in file['locks']]:
                        if RuleState.REPLICATING in [lock['state'] for lock in file['locks'] if lock['rse_id'] == rse_id]:
                            locks_to_create.append(models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=file['scope'], name=file['name'], account=account, bytes=file['bytes'], state=LockState.REPLICATING))
                        else:
                            locks_to_create.append(models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=file['scope'], name=file['name'], account=account, bytes=file['bytes'], state=LockState.OK))
                    else:
                        locks_to_create.append(models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=file['scope'], name=file['name'], account=account, bytes=file['bytes'], state=LockState.REPLICATING))
                        transfers_to_create.append({'rse_id': rse_id, 'scope': file['scope'], 'name': file['name']})
    elif grouping == RuleGrouping.ALL:
        # #######
        # # ALL #
        # #######
        bytes = 0
        rse_coverage = {}  # {'rse_id': coverage }
        for dataset in datasetfiles:
            for file in dataset['files']:
                bytes += file['bytes']
                for lock in file['locks']:
                    if lock['rse_id'] in rse_coverage:
                        rse_coverage[lock['rse_id']] += file['bytes']
                    else:
                        rse_coverage[lock['rse_id']] = file['bytes']
        #TODO add a threshold here?
        if len(preferred_rse_ids) == 0:
            rse_ids = rseselector.select_rse(bytes, [x[0] for x in sorted(rse_coverage.items(), key=lambda tup: tup[1], reverse=True)])
        else:
            rse_ids = rseselector.select_rse(bytes, preferred_rse_ids)
        for rse_id in rse_ids:
            for dataset in datasetfiles:
                for file in dataset['files']:
                    if len([lock for lock in file['locks'] if lock['rule_id'] == rule_id]) == copies:
                        continue
                    if rse_id in [lock['rse_id'] for lock in file['locks']]:
                        if LockState.REPLICATING in [lock['state'] for lock in file['locks'] if lock['rse_id'] == rse_id]:
                            locks_to_create.append(models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=file['scope'], name=file['name'], account=account, bytes=file['bytes'], state=LockState.REPLICATING))
                        else:
                            locks_to_create.append(models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=file['scope'], name=file['name'], account=account, bytes=file['bytes'], state=LockState.OK))
                    else:
                        locks_to_create.append(models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=file['scope'], name=file['name'], account=account, bytes=file['bytes'], state=LockState.REPLICATING))
                        transfers_to_create.append({'rse_id': rse_id, 'scope': file['scope'], 'name': file['name']})
    else:
        # ###########
        # # DATASET #
        # ###########
        for dataset in datasetfiles:
            bytes = sum([file['bytes'] for file in dataset['files']])
            rse_coverage = {}  # {'rse_id': coverage }
            for file in dataset['files']:
                for lock in file['locks']:
                    if lock['rse_id'] in rse_coverage:
                        rse_coverage[lock['rse_id']] += file['bytes']
                    else:
                        rse_coverage[lock['rse_id']] = file['bytes']
            if len(preferred_rse_ids) == 0:
                rse_ids = rseselector.select_rse(bytes, [x[0] for x in sorted(rse_coverage.items(), key=lambda tup: tup[1], reverse=True)])
            else:
                rse_ids = rseselector.select_rse(bytes, preferred_rse_ids)
            #TODO: Add some threshhold
            for rse_id in rse_ids:
                for file in dataset['files']:
                    if len([lock for lock in file['locks'] if lock['rule_id'] == rule_id]) == copies:
                        continue
                    if rse_id in [lock['rse_id'] for lock in file['locks']]:
                        if LockState.REPLICATING in [lock['state'] for lock in file['locks'] if lock['rse_id'] == rse_id]:
                            locks_to_create.append(models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=file['scope'], name=file['name'], account=account, bytes=file['bytes'], state=LockState.REPLICATING))
                        else:
                            locks_to_create.append(models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=file['scope'], name=file['name'], account=account, bytes=file['bytes'], state=LockState.OK))
                    else:
                        locks_to_create.append(models.ReplicaLock(rule_id=rule_id, rse_id=rse_id, scope=file['scope'], name=file['name'], account=account, bytes=file['bytes'], state=LockState.REPLICATING))
                        transfers_to_create.append({'rse_id': rse_id, 'scope': file['scope'], 'name': file['name']})

    # d) Put the locks to the DB, return the transfers
    session.add_all(locks_to_create)
    session.flush()
    return(transfers_to_create)


@read_session
def list_replication_rules(filters={}, session=None):
    """
    List replication rules.

    :param filters: dictionary of attributes by which the results should be filtered.
    :param session: The database session in use.
    """

    query = session.query(models.ReplicationRule)
    if filters:
        for (k, v) in filters.items():
            query = query.filter(getattr(models.ReplicationRule, k) == v)

    for rule in query.yield_per(5):
        d = {'id': rule.id,
             'subscription_id': rule.subscription_id,
             'account': rule.account,
             'scope': rule.scope,
             'name': rule.name,
             'state': rule.state,
             'rse_expression': rule.rse_expression,
             'copies': rule.copies,
             'expires_at': rule.expires_at,
             'weight': rule.weight,
             'locked': rule.locked,
             'grouping': rule.grouping,
             'created_at': rule.created_at,
             'updated_at': rule.updated_at}
        yield d


@transactional_session
def delete_expired_replication_rule(session=None):
    """
    Delete all expired replication rules.

    :param session:  The DB Session in use.
    :returns:        True if something expired, false otherwise.
    """

    # Get Rule which needs deletion
    # TODO This needs to skip locks
    rule = session.query(models.ReplicationRule).filter(models.ReplicationRule.expires_at < datetime.now()).with_lockmode('update_nowait').first()
    if rule is None:
        return False
    print 'rule_cleaner: deleting %s' % rule.id
    delete_replication_rule(rule_id=rule.id, session=session)
    return True


@transactional_session
def delete_replication_rule(rule_id, session=None):
    """
    Delete a replication rule.

    :param rule_id: The rule to delete.
    :param session: The database session in use.
    :raises:        RuleNotFound if no Rule can be found.
    """

    try:
        rule = session.query(models.ReplicationRule).with_lockmode('update').filter_by(id=rule_id).one()
        session.query(models.ReplicaLock).filter_by(rule_id=rule_id).with_lockmode('update').all()
    except NoResultFound:
        raise RuleNotFound('No rule with the id %s found' % (rule_id))
    if rule.state == RuleState.OK or rule.state == RuleState.SUSPENDED or rule.state == RuleState.STUCK:
        #Just delete the rule (and locks), no running transfers for this rule in this rule STATE
        rule.delete(session=session)
    elif rule.state == RuleState.REPLICATING:
        #There are running transfers for this rule, which possibly have to be deleted
        lock_alias = aliased(models.ReplicaLock)
        alllocks = session.query(models.ReplicaLock.scope,
                                 models.ReplicaLock.name,
                                 models.ReplicaLock.rse_id,
                                 models.ReplicaLock.state,
                                 lock_alias.state).outerjoin(lock_alias,
                                                             and_(models.ReplicaLock.scope == lock_alias.scope,
                                                                  models.ReplicaLock.name == lock_alias.name,
                                                                  models.ReplicaLock.rule_id != lock_alias.rule_id,
                                                                  models.ReplicaLock.rse_id == lock_alias.rse_id)).filter(
                                                                      models.ReplicaLock.rule_id == rule_id,
                                                                      models.ReplicaLock.state == LockState.REPLICATING).with_lockmode('update')

        transfers_to_delete = {}  # {(scope, name) : {'scope': , 'name':, 'rse_id':, 'delete' }}
        for scope, name, rse_id, self_state, other_state in alllocks:
            if other_state is None:
                # There are no other locks, the transfer has to be cancelled
                transfers_to_delete[(scope, name)] = {'scope':  scope,
                                                      'name':   name,
                                                      'rse_id': rse_id,
                                                      'delete': True}
            elif other_state == LockState.REPLICATING:
                if (scope, name) in transfers_to_delete:
                    transfers_to_delete[(scope, name)]['delete'] = False
                else:
                    transfers_to_delete[(scope, name)] = {'scope':  scope,
                                                          'name':   name,
                                                          'rse_id': rse_id,
                                                          'delete': False}
            else:
                # SUSPENDED, STUCK
                if (scope, name) not in transfers_to_delete:
                    transfers_to_delete[(scope, name)] = {'scope':  scope,
                                                          'name':   name,
                                                          'rse_id': rse_id,
                                                          'delete': True}
        for transfer in [transfer for transfer in transfers_to_delete.values() if transfer['delete']]:
            #TODO Cancel Transfer
            #cancel_request_did(scope=transfer['scope'], name=transfer['name'], dest_rse=transfer['rse_id'], req_type='transfer')
            continue
        rule.delete(session=session)


@read_session
def get_replication_rule(rule_id, session=None):
    """
    Get a specific replication rule.

    :param rule_id: The rule_id to select
    :param session: The database session in use.
    :raises:        RuleNotFound if no Rule can be found.
    """

    try:
        rule = session.query(models.ReplicationRule).filter_by(id=rule_id).one()
        d = {}
        for column in rule.__table__.columns:
            d[column.name] = getattr(rule, column.name)
        return d

    except NoResultFound:
        raise RuleNotFound('No rule with the id %s found' % (rule_id))


@transactional_session
def re_evaluate_did(session=None):
    """
    Fetches the next did to re-evaluate and re-evaluates it.

    :param session: The database session in use.
    :returns:       True if a rule was re-evaluated; False otherwise.
    """

    # Get DID which needs re-evaluation
    # TODO This needs to skip locks
    always_none = None
    did = session.query(models.DataIdentifier).filter(models.DataIdentifier.rule_evaluation != always_none).with_lockmode('update_nowait').first()
    if did is None:
        return False
    print 're_evaluator: evaluating %s:%s for %s' % (did.scope, did.name, did.rule_evaluation)
    if did.rule_evaluation == DIDReEvaluation.ATTACH:
        __evaluate_attach(did, session=session)
    elif did.rule_evaluation == DIDReEvaluation.DETACH:
        __evaluate_detach(did, session=session)
    else:
        __evaluate_detach(did, session=session)
        __evaluate_attach(did, session=session)
    return True


@transactional_session
def __evaluate_detach(eval_did, session=None):
    """
    Evaluate a parent did which has childs removed

    :param eval_did:  The did object in use.
    :param session:   The database session in use.
    """

    #Get all parent DID's and row-lock them
    parent_dids = list_parent_dids(scope=eval_did.scope, name=eval_did.name, lock=True, session=session)

    #Get all RR from parents and eval_did
    rules = session.query(models.ReplicationRule).filter_by(scope=eval_did.scope, name=eval_did.name).with_lockmode('update').all()
    for did in parent_dids:
        rules.extend(session.query(models.ReplicationRule).filter_by(scope=did['scope'], name=did['name']).with_lockmode('update').all())

    #Get all the files of eval_did
    files = {}
    for file in list_files(scope=eval_did.scope, name=eval_did.name, session=session):
        files[(file['scope'], file['name'])] = True

    #Iterate rules and delete locks
    for rule in rules:
        query = session.query(models.ReplicaLock).filter_by(rule_id=rule.id).with_lockmode("update")
        for lock in query:
            if (lock.scope, lock.name) not in files:
                session.delete(lock)

    if eval_did.rule_evaluation == DIDReEvaluation.BOTH:
        eval_did.rule_evaluation = DIDReEvaluation.ATTACH
    else:
        eval_did.rule_evaluation = None

    session.flush()


@transactional_session
def __evaluate_attach(eval_did, session=None):
    """
    Evaluate a parent did which has new childs

    :param eval_did:  The did object in use.
    :param session:   The database session in use.
    """

    #Get all parent DID's and row-lock them
    parent_dids = list_parent_dids(scope=eval_did.scope, name=eval_did.name, lock=True, session=session)

    #Get and row-lock immediate child DID's
    always_true = True
    new_child_dids = session.query(models.DataIdentifier).join(models.DataIdentifierAssociation, and_(
        models.DataIdentifierAssociation.child_scope == models.DataIdentifier.scope,
        models.DataIdentifierAssociation.child_name == models.DataIdentifier.name)).filter(
            models.DataIdentifierAssociation.scope == eval_did.scope,
            models.DataIdentifierAssociation.name == eval_did.name,
            models.DataIdentifierAssociation.rule_evaluation == always_true).with_lockmode('update').all()

    #Row-Lock all children of the evaluate_dids
    all_child_dscont = []
    if new_child_dids[0].type != models.DataIdType.FILE:
        for did in new_child_dids:
            all_child_dscont.extend(list_child_dids(scope=did.scope, name=did.name, lock=True, session=session))

    #Get all RR from parents and eval_did
    rules = session.query(models.ReplicationRule).filter_by(scope=eval_did.scope, name=eval_did.name).with_lockmode('update').all()
    for did in parent_dids:
        rules.extend(session.query(models.ReplicationRule).filter_by(scope=did['scope'], name=did['name']).with_lockmode('update').all())

    #Resolve the new_child_dids to its locks
    if new_child_dids[0].type == models.DataIdType.FILE:
        # All the evaluate_dids will be files!
        # Build the special files and datasetfiles object
        files = []
        for did in new_child_dids:
            files.append({'scope': did.scope, 'name': did.name, 'bytes': did.bytes, 'locks': get_replica_locks(scope=did.scope, name=did.name)})
        datasetfiles = [{'scope': None, 'name': None, 'files': files}]
    else:
        datasetfiles = {}
        for did in new_child_dids:
            datasetfiles.update(__resolve_dids_to_locks(did, session=session))

    for rule in rules:
        # 1. Resolve the rse_expression into a list of RSE-ids
        try:
            rse_ids = parse_expression(rule.rse_expression, session=session)
        except (InvalidRSEExpression, RSENotFound) as e:
            rule.state = RuleState.STUCK
            rule.error = str(e)
            rule.save(session=session)
            continue
        # 2. Create the RSE Selector
        try:
            selector = RSESelector(account=rule.account,
                                   rse_ids=rse_ids,
                                   weight=rule.weight,
                                   copies=rule.copies,
                                   session=session)
        except InvalidReplicationRule, e:
            rule.state = RuleState.STUCK
            rule.error = str(e)
            rule.save(session=session)
            continue
        # 3. Apply the Replication rule to the Files
        preferred_rse_ids = []
        # 3.1 Check if the dids in question are files added to a dataset with DATASET/ALL grouping
        if new_child_dids[0].type == models.DataIdType.FILE and rule.grouping != RuleGrouping.NONE:
            # Are there any existing did's in this dataset
            always_false = False
            brother_did = session.query(models.DataIdentifierAssociation).filter(
                models.DataIdentifierAssociation.scope == eval_did.scope,
                models.DataIdentifierAssociation.name == eval_did.name,
                models.DataIdentifierAssociation.scope.rule_evaluation == always_false).first()
            if brother_did is not None:
                # There are other files in the dataset
                locks = get_replica_locks(scope=brother_did.child_scope,
                                          name=brother_did.child_name,
                                          rule_id=rule.id,
                                          session=session)
                preferred_rse_ids = [lock['rse_id'] for lock in locks]
        transfers_to_create = []
        try:
            transfers_to_create.extend(__create_locks_for_rule(datasetfiles=datasetfiles,
                                                               rseselector=selector,
                                                               account=rule.account,
                                                               rule_id=rule.id,
                                                               copies=rule.copies,
                                                               grouping=rule.grouping,
                                                               preferred_rse_ids=preferred_rse_ids,
                                                               session=session))
        except InsufficientQuota, e:
            rule.state = RuleState.STUCK
            rule.error = str(e)
            rule.save(session=session)
            break
        # 4. Create Transfers
        if len(transfers_to_create) > 0:
            rule.state = RuleState.REPLICATING
            rule.save(session=session)
            for transfer in transfers_to_create:
                queue_request(scope=transfer['scope'], name=transfer['name'], dest_rse_id=transfer['rse_id'], req_type='TRANSFER')

    # Set the re_evaluation tag to done
    if eval_did.rule_evaluation == DIDReEvaluation.BOTH:
        eval_did.rule_evaluation = DIDReEvaluation.DETACH
    else:
        eval_did.rule_evaluation = None
    always_true = True
    new_child_dids = session.query(models.DataIdentifierAssociation).filter(
        models.DataIdentifierAssociation.scope == eval_did.scope,
        models.DataIdentifierAssociation.name == eval_did.name,
        models.DataIdentifierAssociation.rule_evaluation == always_true).update(
            {'rule_evaluation': None})

    session.flush()
