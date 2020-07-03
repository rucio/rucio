# Copyright 2013-2020 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Martin Barisits, <martin.barisits@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012-2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013-2019
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2014
# - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister, <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
#
# PY3K COMPATIBLE

from __future__ import print_function

import datetime
import re

from json import dumps

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import aliased
from sqlalchemy.orm.exc import NoResultFound

from rucio.common.exception import SubscriptionNotFound, SubscriptionDuplicate, RucioException, ConfigNotFound
from rucio.core.config import get
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
    try:
        keep_history = get('subscriptions', 'keep_history')
    except ConfigNotFound:
        keep_history = False

    SubscriptionHistory = models.Subscription.__history_mapper__.class_
    retroactive = bool(retroactive)  # Force boolean type, necessary for strict SQL
    state = SubscriptionState.ACTIVE
    lifetime = None
    if retroactive:
        state = SubscriptionState.NEW
    if lifetime:
        lifetime = datetime.datetime.utcnow() + datetime.timedelta(days=lifetime)
    new_subscription = models.Subscription(name=name,
                                           filter=filter,
                                           account=account,
                                           replication_rules=replication_rules,
                                           state=state,
                                           lifetime=lifetime,
                                           retroactive=retroactive,
                                           policyid=priority, comments=comments)
    if keep_history:
        subscription_history = SubscriptionHistory(id=new_subscription.id,
                                                   name=new_subscription.name,
                                                   filter=new_subscription.filter,
                                                   account=new_subscription.account,
                                                   replication_rules=new_subscription.replication_rules,
                                                   state=new_subscription.state,
                                                   lifetime=new_subscription.lifetime,
                                                   retroactive=new_subscription.retroactive,
                                                   policyid=new_subscription.policyid,
                                                   comments=new_subscription.comments)
    try:
        new_subscription.save(session=session)
        if keep_history:
            subscription_history.save(session=session)
    except IntegrityError as error:
        if re.match('.*IntegrityError.*ORA-00001: unique constraint.*SUBSCRIPTIONS_PK.*violated.*', error.args[0])\
           or re.match(".*IntegrityError.*UNIQUE constraint failed: subscriptions.name, subscriptions.account.*", error.args[0])\
           or re.match('.*IntegrityError.*columns? name.*account.*not unique.*', error.args[0]) \
           or re.match('.*IntegrityError.*ORA-00001: unique constraint.*SUBSCRIPTIONS_NAME_ACCOUNT_UQ.*violated.*', error.args[0])\
           or re.match('.*IntegrityError.*1062.*Duplicate entry.*', error.args[0]) \
           or re.match('.*IntegrityError.*duplicate key value violates unique constraint.*', error.args[0]) \
           or re.match('.*UniqueViolation.*duplicate key value violates unique constraint.*', error.args[0]):
            raise SubscriptionDuplicate('Subscription \'%s\' owned by \'%s\' already exists!' % (name, account))
        raise RucioException(error.args)
    return new_subscription.id


@transactional_session
def update_subscription(name, account, metadata=None, session=None):
    """
    Updates a subscription

    :param name: Name of the subscription
    :type:  String
    :param account: Account identifier
    :type account:  String
    :param metadata: Dictionary of metadata to update. Supported keys : filter, replication_rules, comments, lifetime, retroactive, dry_run, priority, last_processed
    :type metadata:  Dict
    :param session: The database session in use.
    :raises: SubscriptionNotFound if subscription is not found
    """
    try:
        keep_history = get('subscriptions', 'keep_history')
    except ConfigNotFound:
        keep_history = False
    values = {'state': SubscriptionState.UPDATED}
    if 'filter' in metadata and metadata['filter']:
        values['filter'] = dumps(metadata['filter'])
    if 'replication_rules' in metadata and metadata['replication_rules']:
        values['replication_rules'] = dumps(metadata['replication_rules'])
    if 'lifetime' in metadata and metadata['lifetime']:
        values['lifetime'] = datetime.datetime.utcnow() + datetime.timedelta(days=float(metadata['lifetime']))
    if 'retroactive' in metadata and metadata['retroactive']:
        values['retroactive'] = metadata['retroactive']
    if 'dry_run' in metadata and metadata['dry_run']:
        values['dry_run'] = metadata['dry_run']
    if 'comments' in metadata and metadata['comments']:
        values['comments'] = metadata['comments']
    if 'priority' in metadata and metadata['priority']:
        values['policyid'] = metadata['priority']
    if 'last_processed' in metadata and metadata['last_processed']:
        values['last_processed'] = metadata['last_processed']
    if 'state' in metadata and metadata['state'] == SubscriptionState.INACTIVE:
        values['state'] = SubscriptionState.INACTIVE
        values['expired_at'] = datetime.datetime.utcnow()

    SubscriptionHistory = models.Subscription.__history_mapper__.class_
    try:
        subscription = session.query(models.Subscription).filter_by(account=account, name=name).one()
        subscription.update(values)
        if keep_history:
            subscription_history = SubscriptionHistory(id=subscription.id,
                                                       name=subscription.name,
                                                       filter=subscription.filter,
                                                       account=subscription.account,
                                                       replication_rules=subscription.replication_rules,
                                                       state=subscription.state,
                                                       lifetime=subscription.lifetime,
                                                       retroactive=subscription.retroactive,
                                                       policyid=subscription.policyid,
                                                       comments=subscription.comments,
                                                       last_processed=subscription.last_processed,
                                                       expired_at=subscription.expired_at,
                                                       updated_at=subscription.updated_at,
                                                       created_at=subscription.created_at)
            subscription_history.save(session=session)
    except NoResultFound:
        raise SubscriptionNotFound("Subscription for account '%(account)s' named '%(name)s' not found" % locals())


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
            if '*' in account.internal:
                account_str = account.internal.replace('*', '%')
                query = query.filter(models.Subscription.account.like(account_str))
            else:
                query = query.filter_by(account=account)
        if state:
            query = query.filter_by(state=state)
    except IntegrityError as error:
        print(error)
        raise
    result = {}
    for row in query:
        result = {}
        for column in row.__table__.columns:
            result[column.name] = getattr(row, column.name)
        yield result
    if result == {}:
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
    subscription = aliased(models.Subscription)
    rule = aliased(models.ReplicationRule)
    # count needs a label to allow conversion to dict (label name can be changed)
    query = session.query(subscription.account, subscription.name, rule.state, func.count().label('count')).join(rule, subscription.id == rule.subscription_id)

    try:
        if name:
            query = query.filter(subscription.name == name)

        if account:
            if '*' in account.internal:
                account_str = account.internal.replace('*', '%')
                query = query.filter(subscription.account.like(account_str))
            else:
                query = query.filter(subscription.account == account)

    except IntegrityError as error:
        print(error)
        raise

    query = query.group_by(subscription.account, subscription.name, rule.state)

    for row in query:
        yield row


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
        result = {}
        for column in subscription.__table__.columns:
            result[column.name] = getattr(subscription, column.name)
        return result

    except NoResultFound:
        raise SubscriptionNotFound('No subscription with the id %s found' % (subscription_id))
    except StatementError:
        raise RucioException('Badly formatted subscription id (%s)' % (subscription_id))
