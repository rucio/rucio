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

"""
RSE-Decommissioner is a daemon that clears RSEs to be decommissioning. The
actual operations (e.g. just delete all replicas, move the replicas to specific
RSEs, etc.) that are performed on the RSEs depend on the "decommissioning
profile", which must be specified for each RSE upon triggering decommissioning.
"""

from collections.abc import Callable
import logging
import random
import socket
import threading
from types import FrameType
from typing import TYPE_CHECKING, Any, Optional, Union

from rucio.common.config import config_get_int
from rucio.common.logging import setup_logging
from rucio.common.exception import RucioException
from rucio.core.heartbeat import sanity_check
from rucio.core.rse import get_rses_with_attribute, get_rse_attribute
from rucio.daemons.common import run_daemon
from rucio.db.sqla.constants import RuleState

from .config import DecommissioningStatus, InvalidStatusName, attr_to_config, set_status
from .profiles import PROFILE_MAP
from .profiles.types import DecommissioningProfile, HandlerOutcome

if TYPE_CHECKING:
    from rucio.daemons.common import HeartbeatHandler

GRACEFUL_STOP = threading.Event()
DAEMON_NAME = 'rsedecommissioner'


def rse_decommissioner(
    once: bool,
    sleep_time: int
) -> None:
    """Daemon runner.

    :param once: Whether to execute once and exit.
    :param sleep_time: Number of seconds to sleep before restarting.
    """
    run_daemon(
        once=once,
        graceful_stop=GRACEFUL_STOP,
        executable=DAEMON_NAME,
        partition_wait_time=1,
        sleep_time=sleep_time,
        run_once_fnc=run_once
    )


def run_once(
    *,
    heartbeat_handler: 'HeartbeatHandler',
    activity: Union[str, None]
) -> bool:
    """Decommission an RSE.

    Identifies an RSE to decommission and sets its decommissioning status to
    PROCESSING. Once all replication rules are processed, tries to finalize
    the RSE by cleaning up the remaining replicas. Should be run in only one
    worker thread (worker_number == 0).

    :param heartbeat_handler: A HeartbeatHandler instance.
    :param activity: Activity to work on.
    :returns: A boolean flag indicating whether the daemon should go to sleep.
    """
    worker_number, _, logger = heartbeat_handler.live()

    if worker_number != 0:
        logger(logging.INFO, 'RSE decommissioner thread id is not 0, will sleep.'
               ' Only thread 0 will work')
        return True

    # Collect all RSEs with the 'decommission' attribute
    rses = get_rses_with_attribute('decommission')
    random.shuffle(rses)

    for rse in rses:
        # Get the decommission attribute (encodes the decommissioning config)
        attr = get_rse_attribute(rse['id'], 'decommission')
        try:
            config = attr_to_config(attr)
        except InvalidStatusName:
            logger(logging.ERROR, 'RSE %s has an invalid decommissioning status',
                   rse['rse'])
            continue

        if config['status'] != DecommissioningStatus.PROCESSING:
            logger(logging.INFO, 'Skipping RSE %s which has decommissioning status "%s"',
                   config['status'])
            continue

        try:
            profile_maker = PROFILE_MAP[config['profile']]
        except KeyError:
            logger(logging.ERROR, 'Invalid decommissioning profile name %s used for %s',
                   config['profile'], rse['rse'])
            continue

        try:
            profile = profile_maker(rse, config)
        except RucioException:
            logger(logging.ERROR, 'Invalid configuration for profile %s', config['profile'])
            raise

        logger(logging.INFO, 'Decommissioning %s: %s', rse['rse'], attr)
        try:
            decommission_rse(rse, profile, logger=logger)
        except Exception as error:  # pylint: disable=broad-exception-caught
            logger(logging.ERROR, 'Unexpected error while decommissioning %s: %s',
                   rse['rse'], str(error), exc_info=True)

    return True


def run(
    once: bool = False,
    sleep_time: int = 86400
) -> None:
    """
    Starts up the decommissioner threads.

    :param once: Whether to execute once and exit.
    :param sleep_time: Number of seconds to sleep before restarting.
    """
    setup_logging(process_name=DAEMON_NAME)
    hostname = socket.gethostname()
    sanity_check(executable='rucio-rsedecommissioner', hostname=hostname)

    logging.info('RSE-Decommissioner starting 1 thread')

    # Creating only one thread but putting it in a list to conform to how
    # other daemons are run.
    threads = [
        threading.Thread(
            target=rse_decommissioner,
            kwargs={
                'sleep_time': sleep_time,
                'once': once
            },
        )
    ]
    [thread.start() for thread in threads]
    # Interruptible joins require a timeout.
    while any(thread.is_alive() for thread in threads):
        [thread.join(timeout=3.14) for thread in threads]


def stop(
    signum: Optional[int] = None,
    frame: Optional[FrameType] = None
) -> None:
    """
    Graceful exit.
    """
    GRACEFUL_STOP.set()


def decommission_rse(
    rse: dict[str, Any],
    profile: DecommissioningProfile,
    *,
    logger: Callable[..., None] = logging.log
) -> None:
    """RSE decommissioning template function.

    RSE decommissioning proceeds in common steps of
    - Profile initialization
    - Discovery of rules to act (move / delete / etc.) on
    - Actual handling of the rules
    - Finalization
    This function takes the functions corresponding to the four steps as its arguments and
    executes them in order.

    The handlers are given as a list of pairs of functions. The two functions both have a
    signature
    (rule, rse, *, logger=logging.log) -> bool
    with the following actions:
    - The first function is the "condition" against which each rule is tested. The returned
      boolean indicates whether the rule satisfies it.
    - The second function is the "(in)action" taken against the rule if the first function
      returns True. The returned boolean indicates whether the limit checker should be
      incremented after executing the action.

    For each rule listed by the discoverer function, the conditions are applied in the order
    given in the handlers list until one evaluates to True, at which point the corresponding
    action function is executed. All remaining condition-action pairs are skipped for the rule.

    :param rse: RSE table entry as a dictionary.
    :param profile: Decommissioning profile.
    :param logger: Logging function.
    """
    remove_max = {
        'rules': config_get_int('rse-decommissioner', 'max_rules', default=-1),
        'locks': config_get_int('rse-decommissioner', 'max_locks', default=-1)
    }
    if any(lim < 0 for lim in remove_max.values()):
        raise RucioException('This daemon requires configuration parameters'
                             ' rse-decommissioner/max_rules and rse-decommissioner/max_locks'
                             ' set to non-negative integers.')

    # Initialize the RSE for decommissioning.
    profile.initialize(logger=logger)
    # Counters for throttling.
    num_untouched = 0
    num_need_attention = 0
    num_removed = {'rules': 0, 'locks': 0}

    # Iterate over rules locking datasets / replicas at the RSE.
    stop_reason = None
    for rule in profile.discover(logger=logger):
        outcome = profile.process(rule, logger=logger)

        if outcome == HandlerOutcome.UNTOUCHED:
            num_untouched += 1
        elif outcome == HandlerOutcome.REMOVED:
            # Rule removed; increment the counters and check the throttling conditions.
            num_removed['rules'] += 1

            if rule['state'] in [RuleState.SUSPENDED, RuleState.WAITING_APPROVAL,
                                 RuleState.INJECT]:
                logger(logging.WARNING,
                       'Rule %s is in state "%s"; cannot extract number of locks',
                       rule['id'], rule['state'])

            num_removed['locks'] += (rule['locks_ok_cnt'] + rule['locks_replicating_cnt']
                                     + rule['locks_stuck_cnt'])

            for counter in ['rules', 'locks']:
                if num_removed[counter] >= remove_max[counter]:
                    stop_reason = counter
                    break
            if stop_reason:
                break
        elif outcome == HandlerOutcome.NEED_ATTENTION:
            num_need_attention += 1

    if stop_reason:
        logger(logging.INFO,
               '(%s) Stopping decommissioning cycle because number of deleted %s reached the'
               ' limit=%d',
               rse['rse'], stop_reason, remove_max[stop_reason])

    if num_removed['rules'] != 0:
        logger(logging.INFO,
               '(%s) %s rules are being deleted. Decommissioning is not complete.',
               rse['rse'], num_removed['rules'])
    elif num_untouched != 0:
        logger(logging.INFO,
               '(%s) %s rules are acknowledged by the daemon and are expected to be removed'
               ' soon. Decommissioning is not complete.',
               rse['rse'], num_untouched)
    elif num_need_attention != 0:
        logger(logging.WARNING,
               '(%s) %s rules were not handled under the current profile. We need to move the'
               ' replicas manually and/or update the rules for decommissioning to proceed.',
               rse['rse'], num_need_attention)
        set_status(rse['id'], DecommissioningStatus.SUSPENDED)
    elif profile.finalize(logger=logger):
        # Finalizer returns True -> RSE is decommissioned
        set_status(rse['id'], DecommissioningStatus.DONE)
