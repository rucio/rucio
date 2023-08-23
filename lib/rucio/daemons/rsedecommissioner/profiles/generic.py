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

"""Generic decommissioning profiles."""
import logging
from collections.abc import Callable, Iterable
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.exc import NoResultFound

from rucio.common.exception import (Duplicate, RequestNotFound, ReplicaNotFound, RucioException,
                                    RuleNotFound, RuleReplaceFailed, UnsupportedOperation)
from rucio.core.lock import get_replica_locks, get_replica_locks_for_rule_id
from rucio.core.replica import list_replicas_per_rse, set_tombstone, update_replica_state
from rucio.core.request import get_request_by_did
from rucio.core.rse import add_rse_attribute, update_rse
from rucio.core.rule import list_rules_for_rse_decommissioning, move_rule, update_rule
from rucio.db.sqla.constants import ReplicaState

from .types import DecommissioningProfile, HandlerOutcome


def generic_delete(rse: dict[str, Any], config: dict[str, Any]) -> DecommissioningProfile:
    """Return a profile for simply deleting rules.

    The "generic delete" profile lists out all rules that are locking replicas at the given RSE,
    and deletes them if either one of the following is true:

    - The RSE expression of the rule is trivial (the RSE name itself).
    - There are no replicas locked by the rule that reside on another RSE.

    :param rse: RSE to decommission.
    :param config: Decommissioning configuration dictionary.
    :returns: A decommissioning profile.
    """
    return DecommissioningProfile(
        rse=rse,
        initializer=_generic_initialize,
        discoverer=_generic_discover,
        handlers=[
            (_is_locked, _call_for_attention),
            (_is_being_deleted, _count_as_processed),
            (_has_trivial_rse_expression, _delete_rule),
            (_has_all_replicas_on_rse, _delete_rule),
        ],
        finalizer=_generic_finalize
    )


def generic_move(rse: dict[str, Any], config: dict[str, Any]) -> DecommissioningProfile:
    """Return a profile for moving rules that satisfy conditions to a specific destination.

    The "generic move" profile lists out all rules that are locking replicas at the given RSE,
    and moves them to the specified destination if either one of the following is true:

    - The RSE expression of the rule is trivial (the RSE name itself).
    - There are no replicas locked by the rule that reside on another RSE.

    :param rse: RSE to decommission.
    :param config: Decommissioning configuration dictionary.
    :returns: A decommissioning profile dictionary.
    """
    try:
        destination = config['destination']
    except KeyError as exc:
        raise RucioException('Configuration parameter "destination" not set') from exc

    move_to_destination = RuleMover(destination)
    return DecommissioningProfile(
        rse=rse,
        initializer=_generic_initialize,
        discoverer=_generic_discover,
        handlers=[
            (_is_locked, _call_for_attention),
            (_is_being_deleted, _count_as_processed),
            (_has_child_rule_id, _count_as_processed),
            (_has_trivial_rse_expression, move_to_destination),
            (_has_all_replicas_on_rse, move_to_destination),
        ],
        finalizer=_generic_finalize
    )


def _generic_initialize(
    rse: dict[str, Any],
    *,
    logger: Callable[..., None] = logging.log,
) -> None:
    """Initializer function that sets the RSE availability flags and the decommissioning status.

    When an RSE is initialized for decommissioning, the availability flags are set as follows:

    - `availability_read=True`
    - `availability_write=False`
    - `availability_delete=True`

    and the following attribute is set:

    - `greedyDeletion=True`

    :param rse: RSE table entry as a dictionary.
    :param logger: Logging function.
    """
    logger(logging.INFO,
           '(%s) Setting RSE availability flags of to read !write delete, greedyDeletion=true.',
           rse['rse'])

    parameters = {
        'availability_read': True,
        'availability_write': False,
        'availability_delete': True
    }
    update_rse(rse['id'], parameters)

    try:
        add_rse_attribute(rse['id'], 'greedyDeletion', True)
    except Duplicate:
        pass


def _generic_discover(
    rse: dict[str, Any],
    *,
    logger: Callable[..., None] = logging.log
) -> Iterable[dict[str, Any]]:
    """Discoverer function that calls the listing function from core.rule.

    :param rse: RSE table entry as a dictionary.
    :param logger: Logging function.
    :returns: An iterable of rule dictionaries.
    """
    return list_rules_for_rse_decommissioning(rse['id'])


def _generic_finalize(
    rse: dict[str, Any],
    *,
    logger: Callable[..., None] = logging.log
) -> bool:
    """Check for remaining replicas at the RSE and resolve where possible.

    If for some reason there are still a large number of replicas remaining at the RSE, this
    function cuts off automatic processing attempts at a hard-coded 100.

    :param rse: RSE table entry as a dictionary.
    :param logger: Logging function.
    :returns: A boolean flag indicating the completion status.
    """
    num_remaining_replicas = _process_replicas_with_no_locks(rse,
                                                             list_replicas_per_rse(rse['id']),
                                                             limit=100,
                                                             logger=logger)

    if num_remaining_replicas == 0:
        # The RSE is now really completely cleared.
        logger(logging.INFO,
               '(%s) Completed deleting the RSE contents. Updating the decommissioning status'
               ' to "done".',
               rse['rse'])
        return True

    logger(logging.WARNING,
           '(%s) %d replicas remain on the RSE even though there are no more rules creating'
           ' locks on them.',
           rse['rse'], num_remaining_replicas)

    # We now wait for reaper to pick the updated replicas (if there are any). Hopefully all
    # replicas will be deleted at the next cycle.
    return False


def _process_replicas_with_no_locks(
    rse: dict[str, Any],
    replicas: Iterable[dict[str, Any]],
    limit: int = 0,
    *,
    logger: Callable[..., None] = logging.log,
) -> int:
    """Process replicas that remain at the RSE after the decommissioning.

    Replicas that remain at the RSE at this point should be unlocked. While this is a situation
    that should not happen, it can due to various errors. This function checks each such replica
    and attempt to resolve the invalid state for known cases.

    :param rse: RSE table entry as a dictionary.
    :param replicas: Sequence or generator of replica objects.
    :param logger: Logging function.
    :returns: Number of processed replicas.
    """
    num_processed = 0
    num_updated = 0
    num_waiting_reap = 0

    # Check if each replica satisfies the condition in list_and_mark_unlocked_replicas() (in
    # core.replica).
    # For each of the conditions, in case of failure, handle cases that can be handled.
    for replica in replicas:
        num_processed += 1
        if limit > 0 and num_processed == limit:
            break

        updated = False

        # If the replica fails any of the following three conditions, reaper won't pick it up.
        reap_pending = True

        # 1. Condition on the replica state & update time
        in_stable_state = replica['state'] in [ReplicaState.AVAILABLE,
                                               ReplicaState.UNAVAILABLE,
                                               ReplicaState.BAD]

        ten_minutes_ago = datetime.utcnow() - timedelta(seconds=600)
        deleting_stuck = (replica['state'] == ReplicaState.BEING_DELETED
                          and replica['updated_at'] < ten_minutes_ago)

        if not (in_stable_state or deleting_stuck):
            # 1.1 If COPYING without a valid request
            # -> Update the state to UNAVAILABLE
            if replica['state'] == ReplicaState.COPYING:
                # Should we allow requests in certain states? Depends on the details of the
                # request state machine.
                try:
                    get_request_by_did(replica['scope'], replica['name'], rse['id'])
                except RequestNotFound:
                    logger(logging.INFO,
                           '(%s) Replica %s:%s is in COPYING state without a valid request.'
                           ' Changing state to UNAVAILABLE.',
                           rse['rse'], replica['scope'], replica['name'])

                    try:
                        update_replica_state(rse['id'], replica['scope'], replica['name'],
                                             ReplicaState.UNAVAILABLE)
                    except ReplicaNotFound:
                        logger(logging.WARNING,
                               '(%s) Replica %s:%s disappeared during cleanup',
                               rse['rse'], replica['scope'], replica['name'])
                    except UnsupportedOperation as error:
                        logger(logging.ERROR, '(%s) %s', rse['rse'], str(error))
                    else:
                        updated = True

            reap_pending = False

        # 2. Condition on the lock count
        if replica['lock_cnt'] != 0:
            # 2.1 No actual lock -> Reset the lock count
            try:
                locks = get_replica_locks(replica['scope'], replica['name'],
                                          restrict_rses=[rse['id']])
            except NoResultFound:
                logger(logging.WARNING,
                       '(%s) Replica %s:%s disappeared during cleanup',
                       rse['rse'], replica['scope'], replica['name'])
            else:
                if len(locks) == 0:
                    logger(logging.WARNING,
                           '(%s) Replica %s:%s has lock count %s but zero actual locks. Please'
                           ' fix the counts.',
                           rse['rse'], replica['scope'], replica['name'], replica['lock_cnt'])

            reap_pending = False

        # 3. Tombstone missing or in the future -> RIP now
        if replica['tombstone'] is None or replica['tombstone'] >= datetime.utcnow():
            logger(logging.INFO, '(%s) Marking tombstone of replica %s:%s as UTCNOW.',
                   rse['rse'], replica['scope'], replica['name'])

            try:
                set_tombstone(rse['id'], replica['scope'], replica['name'],
                              tombstone=datetime.utcnow())
            except ReplicaNotFound as error:
                logger(logging.WARNING, '(%s) %s', rse['rse'], str(error))
            else:
                updated = True

            reap_pending = False

        if updated:
            num_updated += 1

        if reap_pending:
            num_waiting_reap += 1

    logger(logging.INFO, '(%s) %s replicas have been updated. %s replicas are pending deletion.'
           ' >=%s replicas remain unhandled.',
           rse['rse'], num_updated, num_waiting_reap,
           num_processed - num_updated - num_waiting_reap)

    return num_processed


# Condition functions

def _is_locked(
    rule: dict[str, Any],
    rse: dict[str, Any],
    *,
    logger: Callable[..., None] = logging.log
) -> bool:
    logger(logging.INFO,
           '(%s) Rule %s for %s:%s is locked',
           rse['rse'], rule['id'], rule['scope'], rule['name'])
    return rule['locked']


def _is_being_deleted(
    rule: dict[str, Any],
    rse: dict[str, Any],
    *,
    logger: Callable[..., None] = logging.log
) -> bool:
    """Check if the rule is already set to be deleted."""
    if rule['expires_at'] is not None and rule['expires_at'] < datetime.utcnow():
        logger(logging.DEBUG,
               '(%s) Rule %s for %s:%s is bound for deletion',
               rse['rse'], rule['id'], rule['scope'], rule['name'])
        return True
    return False


def _has_trivial_rse_expression(
    rule: dict[str, Any],
    rse: dict[str, Any],
    *,
    logger: Callable[..., None] = logging.log
) -> bool:
    """Check for a trivial rse_expression."""
    return rule['rse_expression'] == rse['rse']


def _has_all_replicas_on_rse(
    rule: dict[str, Any],
    rse: dict[str, Any],
    *,
    logger: Callable[..., None] = logging.log
) -> bool:
    """Check if the all the replicas are on the RSE."""
    # Check the list of RSEs that the replicas locked by this rule reside on.
    try:
        locks = get_replica_locks_for_rule_id(rule['id'])
    except NoResultFound:
        # No replica is locked to begin with -> treat as having the last replica on this RSE
        return True

    replica_rse_ids = set(lock['rse_id'] for lock in locks)

    return len(replica_rse_ids) == 1 and list(replica_rse_ids)[0] == rse['id']


def _has_child_rule_id(
    rule: dict[str, Any],
    rse: dict[str, Any],
    *,
    logger: Callable[..., None] = logging.log
) -> bool:
    """Check for non-empty child_rule_id."""
    if rule['child_rule_id']:
        logger(logging.DEBUG, '(%s) Rule %s for %s:%s is being moved',
               rse['rse'], rule['id'], rule['scope'], rule['name'])
        return True
    return False


# Action functions

def _call_for_attention(
    rule: dict[str, Any],
    rse: dict[str, Any],
    *,
    logger: Callable[..., None] = logging.log
) -> HandlerOutcome:
    return HandlerOutcome.NEED_ATTENTION


def _count_as_processed(
    rule: dict[str, Any],
    rse: dict[str, Any],
    *,
    logger: Callable[..., None] = logging.log
) -> HandlerOutcome:
    """Do nothing but increment the limit checker."""
    return HandlerOutcome.UNTOUCHED


def _delete_rule(
    rule: dict[str, Any],
    rse: dict[str, Any],
    *,
    logger: Callable[..., None] = logging.log
) -> HandlerOutcome:
    """Delete the rule."""
    logger(logging.DEBUG, '(%s) Deleting rule %s for %s:%s',
           rse['rse'], rule['id'], rule['scope'], rule['name'])

    try:
        update_rule(rule['id'], {'lifetime': 0})
    except RuleNotFound:
        logger(logging.WARNING, '(%s) Rule %s for %s:%s disappeared before deleting',
               rse['rse'], rule['id'], rule['scope'], rule['name'])
        return HandlerOutcome.UNTOUCHED

    return HandlerOutcome.REMOVED


class RuleMover:
    """Callable object with a destination attribute."""
    def __init__(self, destination: str) -> None:
        self.destination = destination

    def __call__(
        self,
        rule: dict[str, Any],
        rse: dict[str, Any],
        *,
        logger: Callable[..., None] = logging.log
    ) -> HandlerOutcome:
        """Move the rule."""
        # Move the rule.
        logger(logging.DEBUG, '(%s) Moving rule %s for %s:%s to %s',
               rse['rse'], rule['id'], rule['scope'], rule['name'],
               self.destination)

        try:
            move_rule(rule['id'], self.destination,
                      override={'weight': None, 'source_replica_expression': None})
        except RuleNotFound:
            logger(logging.WARNING, '(%s) Rule %s for %s:%s disappeared before moving',
                   rse['rse'], rule['id'], rule['scope'], rule['name'])
            return HandlerOutcome.UNTOUCHED
        except RuleReplaceFailed:
            logger(logging.ERROR,
                   '(%s) Failed to move rule %s for %s:%s to %s',
                   rse['rse'], rule['id'], rule['scope'], rule['name'],
                   self.destination)
            return HandlerOutcome.NEED_ATTENTION
        return HandlerOutcome.REMOVED
