# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Martin Barisits, <martin.barisits@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2014
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014

import datetime
import re

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import aliased
from sqlalchemy.orm.exc import NoResultFound

from rucio.common.exception import SubscriptionNotFound, SubscriptionDuplicate, RucioException
from rucio.db.sqla import models
from rucio.db.sqla.constants import SubscriptionState
from rucio.db.sqla.session import transactional_session, stream_session, read_session


@transactional_session
def add_subscription(name, account, filter, replication_rules, comments, lifetime, retroactive, dry_run, priority=3, session=None):
    """
    Adds a new subscription which will be verified against every new added file and dataset

    :param account: Account identifier
    :type account:  String
    :param name: Name of the subscription
    :type:  String
    :param filter: Dictionary of attributes by which the input data should be filtered
                   **Example**: ``{'dsn': 'data11_hi*.express_express.*,data11_hi*physics_MinBiasOverlay*', 'account': 'tzero'}``
    :type filter:  Dict
    :param replication_rules: Replication rules to be set : Dictionary with keys copies, rse_expression, weight, rse_expression
    :type replication_rules:  Dict
    :param comments: Comments for the subscription
    :type comments:  String
    :param lifetime: Subscription's lifetime (days)
    :type lifetime:  Integer or None
    :param retroactive: Flag to know if the subscription should be applied on previous data
    :type retroactive:  Boolean
    :param dry_run: Just print the subscriptions actions without actually executing them (Useful if retroactive flag is set)
    :type dry_run:  Boolean
    :param priority: The priority of the subscription
    :type priority: Integer
    :param session: The database session in use.

    :returns: The subscriptionid
    """

    retroactive = bool(retroactive)  # Force boolean type, necessary for strict SQL
    state = SubscriptionState.ACTIVE
    lifetime = None
    if retroactive:
        state = SubscriptionState.NEW
    if lifetime:
        lifetime = datetime.datetime.utcnow() + datetime.timedelta(days=lifetime)
    new_subscription = models.Subscription(name=name, filter=filter, account=account, replication_rules=replication_rules, state=state, lifetime=lifetime,
                                           retroactive=retroactive, policyid=priority, comments=comments)
    try:
        new_subscription.save(session=session)
    except IntegrityError, e:
        if re.match('.*IntegrityError.*ORA-00001: unique constraint.*SUBSCRIPTIONS_PK.*violated.*', e.args[0])\
           or re.match(".*IntegrityError.*UNIQUE constraint failed: subscriptions.name, subscriptions.account.*", e.args[0])\
           or re.match(".*columns name, account are not unique.*", e.args[0])\
           or re.match('.*IntegrityError.*ORA-00001: unique constraint.*SUBSCRIPTIONS_NAME_ACCOUNT_UQ.*violated.*', e.args[0])\
           or re.match('.*IntegrityError.*1062.*Duplicate entry.*', e.args[0]) \
           or re.match('.*IntegrityError.*duplicate key value violates unique constraint.*', e.args[0]):
            raise SubscriptionDuplicate('Subscription \'%s\' owned by \'%s\' already exists!' % (name, account))
        raise RucioException(e.args)
    return new_subscription.id


@transactional_session
def update_subscription(name, account, filter=None, replication_rules=None, comments=None, lifetime=None, retroactive=None, dry_run=None, state=None, priority=None, session=None):
    """
    Updates a subscription

    :param name: Name of the subscription
    :type:  String
    :param account: Account identifier
    :type account:  String
    :param filter: Dictionary of attributes by which the input data should be filtered
                   **Example**: ``{'dsn': 'data11_hi*.express_express.*,data11_hi*physics_MinBiasOverlay*', 'account': 'tzero'}``
    :type filter:  Dict
    :param replication_rules: Replication rules to be set : Dictionary with keys copies, rse_expression, weight, rse_expression
    :type replication_rules:  Dict
    :param transfer_requests: Transfer requests to be issued. List of tuples holding count, RSE-tag, group; If the group flag is set to ``true``, this transfer_request will resolve to the same RSE for all files in the same dataset
                              **Example**: ``[(1, 'T1-DATADISKS', True), (2, 'T2-DATADISKS', False)]``
    :type transfer_requests:  List
    :param comments: Comments for the subscription
    :type comments:  String
    :param lifetime: Subscription's lifetime (days)
    :type lifetime:  Integer or None
    :param retroactive: Flag to know if the subscription should be applied on previous data
    :type retroactive:  Boolean
    :param dry_run: Just print the subscriptions actions without actually executing them (Useful if retroactive flag is set)
    :type dry_run:  Boolean
    :param state: The state of the subscription
    :param priority: The priority of the subscription
    :type priority: Integer
    :param session: The database session in use.
    :raises: exception.NotFound if subscription is not found
    """
    values = {'state': SubscriptionState.UPDATED}
    if filter:
        values['filter'] = filter
    if replication_rules:
        values['replication_rules'] = replication_rules
    if lifetime:
        values['lifetime'] = datetime.datetime.utcnow() + datetime.timedelta(days=lifetime)
    if retroactive:
        values['retroactive'] = retroactive
    if dry_run:
        values['dry_run'] = dry_run
    if comments:
        values['comments'] = comments
    if priority:
        values['policyid'] = priority
    if state and state == SubscriptionState.INACTIVE:
        values['state'] = SubscriptionState.INACTIVE
        values['expired_at'] = datetime.datetime.utcnow()

    try:
        rowcount = session.query(models.Subscription).filter_by(account=account, name=name).update(values)
        if rowcount == 0:
            raise SubscriptionNotFound("Subscription for account '%(account)s' named '%(name)s' not found" % locals())
    except IntegrityError, e:
        raise RucioException(e.args)


@stream_session
def list_subscriptions(name=None, account=None, state=None, session=None):
    """
    Returns a dictionary with the subscription information :
    Examples: ``{'status': 'INACTIVE/ACTIVE/BROKEN', 'last_modified_date': ...}``

    :param name: Name of the subscription
    :type:  String
    :param account: Account identifier
    :type account:  String
    :param session: The database session in use.
    :returns: Dictionary containing subscription parameter
    :rtype:   Dict
    :raises: exception.NotFound if subscription is not found
    """
    query = session.query(models.Subscription)
    try:
        if name:
            query = query.filter_by(name=name)
        if account:
            query = query.filter_by(account=account)
        if state:
            query = query.filter_by(state=state)
    except IntegrityError, e:
        print e
        raise
    d = {}
    for row in query:
        d = {}
        for column in row.__table__.columns:
            d[column.name] = getattr(row, column.name)
        yield d
    if d == {}:
        raise SubscriptionNotFound("Subscription for account '%(account)s' named '%(name)s' not found" % locals())


def delete_subscription(subscription_id):
    """
    Deletes a subscription

    :param subscription_id: Subscription identifier
    :type subscription_id:  String
    """

    raise NotImplementedError


@stream_session
def list_subscription_rule_states(name=None, account=None, session=None):
    """Returns a list of with the number of rules per state for a subscription.

    :param name: Name of the subscription
    :param account: Account identifier
    :param session: The database session in use.
    :returns: List with tuple (account, name, state, count)
    """
    s = aliased(models.Subscription)
    r = aliased(models.ReplicationRule)
    query = session.query(s.account, s.name, r.state, func.count()).join(r, s.id == r.subscription_id)

    try:
        if name:
            query = query.filter(s.name == name)
        if account:
            query = query.filter(s.account == account)
    except IntegrityError, e:
        print e
        raise

    query = query.group_by(s.account, s.name, r.state)

    for row in query:
        yield row


class SubscriptionPolicy():
    """
    Abstract class for advanced subscription policies; Each time a subscription with a set subscription policy is called the specifically designed process function is called to return the replication_rules and transfer_requests for the input dataset/file
    """

    def process(lfn, dsn, meta_data):
        """
        Specifically selects and returns the replication_rules and transfer_requests

        :param lfn: Logical file name
        :type lfn:  String
        :param dsn: Dataset name the file belongs to
        :type dsn:  String
        :param meta_data: Meta data dictionary of this file
        :type meta_data:  Dict
        :returns: Tuple holding the List of replication_rules and List of transfer_requests: (replication_rules, transfer_requests)
                  **Example**: ``([(1, 'T1-DATADISKS', True, True), (3, 'T2-DATADISKS', False, False)], [(1, 'T1-DATADISKS', True), (2, 'T2-DATADISKS', False)])``
        :rtype:   List
        """

        raise NotImplementedError


@read_session
def get_subscription_by_id(subscription_id, session=None):
    """
    Get a specific subscription by id.

    :param subscription_id: The subscription_id to select.
    :param session: The database session in use.
    :raises: SubscriptionNotFound if no Subscription can be found.
    """

    try:
        subscription = session.query(models.Subscription).filter_by(id=subscription_id).one()
        d = {}
        for column in subscription.__table__.columns:
            d[column.name] = getattr(subscription, column.name)
        return d

    except NoResultFound:
        raise SubscriptionNotFound('No subscription with the id %s found' % (subscription_id))
    except StatementError:
        raise RucioException('Badly formatted subscription id (%s)' % (subscription_id))
