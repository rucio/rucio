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

from random import uniform

from sqlalchemy.exc import IntegrityError

from rucio.common.utils import generate_uuid
from rucio.core.did import list_files
from rucio.common.exception import InvalidReplicationRule, InsufficientQuota
from rucio.core.lock import get_replica_locks, add_replica_lock
from rucio.core.quota import list_account_limits, list_account_usage
from rucio.core.rse import list_rse_attributes
from rucio.core.rse_expression_parser import parse_expression
from rucio.db import models
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
    :raises:                 InvalidReplicationRule
    """

    # Resolve the rse_expression into a list of RSE-ids
    rse_ids = parse_expression(rse_expression, session=session)
    # Create the RSESelector
    selector = RSESelector(account=account, rse_ids=rse_ids, weight=weight, session=session)

    transfers_to_create = []
    rule_ids = []

    for did in dids:
        locks_to_create = []
        #One rule gets created per did specified by the user
        if grouping == 'NONE':
            #Random spread
            files = []  # [{scope, name, size, replica_locks=[]]
            files.extend(list_files(scope=did['scope'], name=did['name'], session=session))
            for file in files:
                file['replica_locks'] = get_replica_locks(scope=file['scope'], name=file['name'])
                rse_ids = selector.select_rse(file['size'], copies, [lock['rse_id'] for lock in file['replica_locks']])
                for rse_id in rse_ids:
                    if 'WAITING' in [lock['state'] for lock in file['replica_locks'] if lock['rse_id'] == rse_id]:
                        locks_to_create.append({'rse_id': rse_id, 'scope': file['scope'], 'name': file['name'], 'state': 'WAITING'})
                    else:
                        locks_to_create.append({'rse_id': rse_id, 'scope': file['scope'], 'name': file['name'], 'state': 'OK'})
                    if rse_id not in [lock['rse_id'] for lock in file['replica_locks']]:
                        transfers_to_create.append({'rse_id': rse_id, 'scope': file['scope'], 'name': file['name']})
        elif grouping == 'ALL':
            # Concentration
            raise NotImplemented
        else:
            # Dataset Grouping
            raise NotImplemented

        # Create the replication rule
        rule_id = generate_uuid()
        rule_ids.append(rule_id)
        new_rule = models.ReplicationRule(id=rule_id, account=account, name=did['name'], scope=did['scope'], copies=copies, rse_expression=rse_expression, locked=locked, grouping=grouping, expires_at=lifetime, weight=weight)
        try:
            new_rule.save(session=session)
        except IntegrityError, e:
            raise InvalidReplicationRule(e.args[0])

        # Insert the locks
        for lock in locks_to_create:
            add_replica_lock(rule_id=rule_id, scope=lock['scope'], name=lock['name'], rse_id=lock['rse_id'], account=account, state=lock['state'], session=session)

    #TODO Create transfers in transfers_to_create, depending on [RUCIO-154]

    return rule_ids


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

    for row in query:
        d = {}
        for column in row.__table__.columns:
            d[column.name] = getattr(row, column.name)
        yield d


class RSESelector():
    """
    Representation of the RSE selector
    """

    @read_session
    def __init__(self, account, rse_ids, weight, session=None):
        """
        Initialize the RSE Selector.

        :param account:  Account owning the rule.
        :param rse_ids:  List of rse_ids.
        :param weight:   Weighting to use.
        :param session:  DB Session in use.
        :raises:         InvalidReplicationRule
        """

        self.account = account
        self.rses = []
        if weight is not None:
            for rse_id in rse_ids:
                attributes = list_rse_attributes(rse=None, rse_id=rse_id, session=session)
                if weight not in attributes:
                    continue
                try:
                    self.rses.append({'rse_id': rse_id, 'weight': float(attributes['weight'])})
                except ValueError:
                    continue
        else:
            self.rses = [{'rse_id': rse_id, 'weight': 1} for rse_id in rse_ids]
        if not self.rses:
            raise InvalidReplicationRule

        for rse in self.rses:
            rse['quota_left'] = list_account_limits(account=account, rse_id=rse['rse_id'], session=session) - list_account_usage(account=account, rse_id=rse['rse_id'], session=session)

        self.rses = [rse for rse in self.rses if rse['quota_left'] > 0]

    def select_rse(self, size, copies, preferred_rse_ids):
        """
        Select n RSEs to replicate data to.

        :param size:               Size of the block being replicated.
        :param copies:             How many replicas to pick.
        :param preferred_rse_ids:  If possible, replicate to these RSEs.
        :returns:                  List of RSE ids.
        :raises:                   InvalidReplicationRule
        """

        result = []
        for copy in range(copies):
            #Only use RSEs which have enough quota
            rses = [rse for rse in self.rses if rse['quota_left'] > size and rse['rse_id'] not in result]
            if not rses:
                #No site has enough quota
                raise InsufficientQuota('There is insufficient quota on any of the RSE\'s to fullfill the operation')
            #Filter the preferred RSEs to those with enough quota
            preferred_rses = [x for x in rses if x['rse_id'] in preferred_rse_ids]

            if preferred_rses:
                rse_id = self.__choose_rse(preferred_rses)
            else:
                rse_id = self.__choose_rse(rses)
            result.append(rse_id)
            self.__update_quota(rse_id, size)
        return result

    def __update_quota(self, rse_id, size):
        """
        Update the internal quota value.

        :param rse_ids:   RSE-id to update.
        :param size:        Size to substract.
        """

        for element in self.rses:
            if element['rse_id'] == rse_id:
                element['quota_left'] -= size
                return

    def __choose_rse(self, rses):
        """
        Choose an RSE based on weighting.
        """
        pick = uniform(0, sum([rse['weight'] for rse in rses]))
        weight = 0
        for rse in rses:
            weight += rse['weight']
            if pick <= weight:
                return rse['rse_id']
