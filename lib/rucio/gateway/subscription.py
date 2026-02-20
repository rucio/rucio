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

from collections import namedtuple
from json import dumps, loads
from typing import TYPE_CHECKING, Any, Literal, Optional, Union

from rucio.common.constants import DEFAULT_VO
from rucio.common.exception import AccessDenied, InvalidObject
from rucio.common.schema import validate_schema
from rucio.common.types import InternalAccount, InternalScope
from rucio.core import subscription
from rucio.db.sqla.constants import DatabaseOperationType, SubscriptionState
from rucio.db.sqla.session import db_session
from rucio.gateway.permission import has_permission

if TYPE_CHECKING:
    from collections.abc import Iterator


SubscriptionRuleState = namedtuple('SubscriptionRuleState', ['account', 'name', 'state', 'count'])


def add_subscription(
    name: str,
    account: str,
    filter_: dict[str, Any],
    replication_rules: list[dict[str, Any]],
    comments: str,
    lifetime: Union[int, Literal[False]],
    retroactive: bool,
    dry_run: bool,
    issuer: str,
    priority: Optional[int] = None,
    vo: str = DEFAULT_VO,
) -> str:
    """
    Adds a new subscription which will be verified against every new added file and dataset

    :param account: Account identifier
    :param name: Name of the subscription
    :param filter_: Dictionary of attributes by which the input data should be filtered
                   **Example**: ``{'dsn': 'data11_hi*.express_express.*,data11_hi*physics_MinBiasOverlay*', 'account': 'tzero'}``
    :param replication_rules: Replication rules to be set : Dictionary with keys copies, rse_expression, weight, rse_expression
    :param comments: Comments for the subscription
    :param lifetime: Subscription's lifetime (seconds); False if subscription has no lifetime
    :param retroactive: Flag to know if the subscription should be applied on previous data
    :param dry_run: Just print the subscriptions actions without actually executing them (Useful if retroactive flag is set)
    :param priority: The priority of the subscription
    :param issuer:  The account issuing this operation.
    :param vo: The VO to act on.
    :returns: subscription_id
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='add_subscription', kwargs={'account': account}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s can not add subscription. %s' % (issuer, auth_result.message))
        try:
            if filter_:
                if not isinstance(filter_, dict):
                    raise TypeError('filter should be a dict')
                validate_schema(name='subscription_filter', obj=filter_, vo=vo)
            if replication_rules:
                if not isinstance(replication_rules, list):
                    raise TypeError('replication_rules should be a list')
                else:
                    for rule in replication_rules:
                        validate_schema(name='activity', obj=rule.get('activity', 'default'), vo=vo)
            else:
                raise InvalidObject('You must specify a rule')
        except ValueError as error:
            raise TypeError(error)

        internal_account = InternalAccount(account, vo=vo)

        keys = ['scope', 'account']
        types = [InternalScope, InternalAccount]
        for _key, _type in zip(keys, types):
            if _key in filter_:
                if isinstance(filter_[_key], list):
                    filter_[_key] = [_type(val, vo=vo).internal for val in filter_[_key]]
                else:
                    filter_[_key] = _type(filter_[_key], vo=vo).internal

        return subscription.add_subscription(name=name, account=internal_account, filter_=dumps(filter_), replication_rules=dumps(replication_rules),
                                             comments=comments, lifetime=lifetime, retroactive=retroactive, dry_run=dry_run, priority=priority,
                                             session=session)


def update_subscription(
    name: str,
    account: str,
    issuer: str,
    metadata: Optional[dict[str, Any]] = None,
    vo: str = DEFAULT_VO,
) -> None:
    """
    Updates a subscription

    :param name: Name of the subscription
    :param account: Account identifier
    :param metadata: Dictionary of metadata to update. Supported keys : filter, replication_rules, comments, lifetime, retroactive, dry_run, priority, last_processed, state
    :param issuer: The account issuing this operation.
    :param vo: The VO to act on.
    :raises: SubscriptionNotFound if subscription is not found
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        auth_result = has_permission(issuer=issuer, vo=vo, action='update_subscription', kwargs={'account': account}, session=session)
        if not auth_result.allowed:
            raise AccessDenied('Account %s can not update subscription. %s' % (issuer, auth_result.message))
        try:
            if not isinstance(metadata, dict):
                raise TypeError('metadata should be a dict')
            if 'filter' in metadata and metadata['filter']:
                if not isinstance(metadata['filter'], dict):
                    raise TypeError('filter should be a dict')
                validate_schema(name='subscription_filter', obj=metadata['filter'], vo=vo)
            if 'replication_rules' in metadata and metadata['replication_rules']:
                if not isinstance(metadata['replication_rules'], list):
                    raise TypeError('replication_rules should be a list')
                else:
                    for rule in metadata['replication_rules']:
                        validate_schema(name='activity', obj=rule.get('activity', 'default'), vo=vo)
            if 'state' in metadata and metadata['state'] is not None:
                try:
                    metadata['state'] = SubscriptionState(metadata['state'])
                except ValueError as err:
                    raise InvalidObject(f"Invalid subscription state: {metadata['state']}") from err

        except ValueError as error:
            raise TypeError(error)

        internal_account = InternalAccount(account, vo=vo)

        if 'filter' in metadata and metadata['filter'] is not None:
            filter_ = metadata['filter']
            keys = ['scope', 'account']
            types = [InternalScope, InternalAccount]

            for _key, _type in zip(keys, types):
                if _key in filter_ and filter_[_key] is not None:
                    if isinstance(filter_[_key], list):
                        filter_[_key] = [_type(val, vo=vo).internal for val in filter_[_key]]
                    else:
                        filter_[_key] = _type(filter_[_key], vo=vo).internal
        return subscription.update_subscription(name=name, account=internal_account, metadata=metadata, session=session)


def list_subscriptions(
    name: Optional[str] = None,
    account: Optional[str] = None,
    state: Optional[str] = None,
    vo: str = DEFAULT_VO,
) -> 'Iterator[dict[str, Any]]':
    """
    Returns a dictionary with the subscription information :
    Examples: ``{'status': 'INACTIVE/ACTIVE/BROKEN', 'last_modified_date': ...}``

    :param name: Name of the subscription
    :param account: Account identifier
    :param state: Filter for subscription state
    :param vo: The VO to act on.
    :returns: Dictionary containing subscription parameter
    :raises: exception.NotFound if subscription is not found
    """

    if account:
        internal_account = InternalAccount(account, vo=vo)
    else:
        internal_account = InternalAccount('*', vo=vo)

    with db_session(DatabaseOperationType.READ) as session:
        subs = subscription.list_subscriptions(name, internal_account, state, session=session)

        for sub in subs:
            sub['account'] = sub['account'].external

            if 'filter' in sub:
                fil = loads(sub['filter'])
                if 'account' in fil:
                    fil['account'] = [InternalAccount(acc, from_external=False).external for acc in fil['account']]
                if 'scope' in fil:
                    fil['scope'] = [InternalScope(sco, from_external=False).external for sco in fil['scope']]
                sub['filter'] = dumps(fil)

            yield sub


def list_subscription_rule_states(
    name: Optional[str] = None,
    account: Optional[str] = None,
    vo: str = DEFAULT_VO,
) -> 'Iterator[SubscriptionRuleState]':
    """Returns a list of with the number of rules per state for a subscription.

    :param name: Name of the subscription
    :param account: Account identifier
    :param vo: The VO to act on.
    :returns: Sequence with SubscriptionRuleState named tuples (account, name, state, count)
    """
    if account is not None:
        internal_account = InternalAccount(account, vo=vo)
    else:
        internal_account = InternalAccount('*', vo=vo)

    with db_session(DatabaseOperationType.READ) as session:
        subs = subscription.list_subscription_rule_states(name, internal_account, session=session)

        for sub in subs:
            # sub is an immutable Row so return new named tuple with edited entries
            d = sub._asdict()
            d['account'] = d['account'].external
            yield SubscriptionRuleState(**d)


def delete_subscription(
    subscription_id: str,
    vo: str = DEFAULT_VO,
) -> None:
    """
    Deletes a subscription

    :param subscription_id: Subscription identifier
    :param vo: The VO of the user issuing command
    """

    raise NotImplementedError


def get_subscription_by_id(
    subscription_id: str,
    vo: str = DEFAULT_VO,
) -> dict[str, Any]:
    """
    Get a specific subscription by id.

    :param subscription_id: The subscription_id to select.
    :param vo: The VO of the user issuing command.

    :raises: SubscriptionNotFound if no Subscription can be found.
    """
    with db_session(DatabaseOperationType.READ) as session:
        sub = subscription.get_subscription_by_id(subscription_id, session=session)
    if sub['account'].vo != vo:
        raise AccessDenied('Unable to get subscription')

    sub['account'] = sub['account'].external

    if 'filter' in sub:
        fil = loads(sub['filter'])
        if 'account' in fil:
            fil['account'] = [InternalAccount(acc, from_external=False).external for acc in fil['account']]
        if 'scope' in fil:
            fil['scope'] = [InternalScope(sco, from_external=False).external for sco in fil['scope']]
        sub['filter'] = dumps(fil)

    return sub
