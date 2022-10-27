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

import functools
import logging
import re
import threading
import time
from datetime import datetime
from json import loads, dumps
from typing import TYPE_CHECKING, List, Dict, Callable

import rucio.db.sqla.util
from rucio.db.sqla.constants import DIDType, SubscriptionState
from rucio.common.config import config_get
from rucio.common.exception import (
    DatabaseException,
    InvalidReplicationRule,
    DuplicateRule,
    InvalidRSEExpression,
    InsufficientTargetRSEs,
    InsufficientAccountLimit,
    RSEOverQuota,
    InvalidRuleWeight,
    StagingAreaRuleRequiresLifetime,
    SubscriptionWrongParameter,
    SubscriptionNotFound,
)
from rucio.common.logging import setup_logging
from rucio.common.types import InternalAccount
from rucio.common.utils import chunks
from rucio.core import monitor
from rucio.core.did import list_new_dids, set_new_dids, get_metadata
from rucio.core.rse import list_rses, rse_exists, get_rse_id, list_rse_attributes
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rse_selector import resolve_rse_expression
from rucio.core.rule import add_rule, list_rules, get_rule
from rucio.core.subscription import list_subscriptions, update_subscription
from rucio.daemons.common import run_daemon

if TYPE_CHECKING:
    from rucio.daemons.common import HeartbeatHandler
    from rucio.common.types import InternalScope

graceful_stop = threading.Event()

RULES_COMMENT_LENGTH = 255


def __get_rule_dict(rule_dict: dict, subscription: dict) -> dict:
    """
    Internal method to clean and enrich the rule_dict coming from the subscription.

    :param rule_dict: The rule dictionnary coming from a subscription.
    :param subscription: The subscription associated to the rule.
    :return: A dictionary that contains all the parameters associated to the rule.
    """
    source_replica_expression = rule_dict.get("source_replica_expression", None)
    rule_dict["source_replica_expression"] = source_replica_expression
    locked = rule_dict.get("locked", None)
    if locked == "True":
        locked = True
    else:
        locked = False
    rule_dict["locked"] = locked

    purge_replicas = rule_dict.get("purge_replicas", False)
    if purge_replicas == "True":
        purge_replicas = True
    else:
        purge_replicas = False
    rule_dict["purge_replicas"] = purge_replicas

    rule_dict["rse_expression"] = str(rule_dict["rse_expression"])
    comment = str(subscription["comments"])[:RULES_COMMENT_LENGTH]
    if "comments" in rule_dict:
        comment = str(rule_dict["comments"])
    rule_dict["comment"] = comment
    account = subscription["account"]
    if "account" in rule_dict:
        vo = account.vo
        account = InternalAccount(rule_dict["account"], vo=vo)
    rule_dict["account"] = account
    rule_dict["copies"] = int(rule_dict["copies"])
    default_activity = config_get("rules", "default_activity", default="default")
    activity = rule_dict.get("activity", default_activity)
    rule_dict["activity"] = activity
    lifetime = rule_dict.get("lifetime", None)
    if lifetime:
        rule_dict["lifetime"] = int(lifetime)
    chained_idx = rule_dict.get("chained_idx", None)
    if chained_idx:
        chained_idx = int(rule_dict["copies"])
    rule_dict["chained_idx"] = chained_idx
    delay_injection = rule_dict.get("delay_injection", None)
    if delay_injection:
        delay_injection = int(delay_injection)
    rule_dict["delay_injection"] = delay_injection
    return rule_dict


def __split_rule_select_rses(
    subscription_id: str,
    subscription_name: str,
    scope: "InternalScope",
    name: str,
    account: "InternalAccount",
    weight: int,
    rse_expression: str,
    copies: int,
    blocklisted_rse_id: list,
    logger: "Callable",
) -> List[Dict]:
    """
    Internal method to create a list of RSEs that match RSE expression for subscriptions with split_rule.

    :param subscription_id: The subscription id.
    :param subscription_name: The subscription name.
    :param scope: The internal DID scope.
    :param name: The DID name.
    :param account: The internal account.
    :param weight: The weight of the rule.
    :param rse_expression: The RSE expression of the rule.
    :param copies: The number of copies.
    :param blocklisted_rse_id: The list of blocklisted_rse_id.
    :param logger: The logger.
    :return: A tuple of list selected_rses, preferred_rses, preferred_unmatched.
    """
    preferred_rses = set()
    for rule in list_rules(
        filters={
            "subscription_id": subscription_id,
            "scope": scope,
            "name": name,
        }
    ):
        for rse_dict in parse_expression(
            rule["rse_expression"],
            filter_={"vo": account.vo},
        ):
            preferred_rses.add(rse_dict["rse"])
    preferred_rses = list(preferred_rses)

    try:
        (selected_rses, preferred_unmatched,) = resolve_rse_expression(
            rse_expression,
            account,
            weight=weight,
            copies=copies,
            size=0,
            preferred_rses=preferred_rses,
            blocklist=blocklisted_rse_id,
        )

    except (
        InsufficientTargetRSEs,
        InsufficientAccountLimit,
        InvalidRuleWeight,
        RSEOverQuota,
    ) as error:
        logger(
            logging.WARNING,
            'Problem getting RSEs for subscription "%s" for account %s : %s. Try including blocklisted sites'
            % (
                subscription_name,
                account,
                str(error),
            ),
        )
        # Now including the blocklisted sites
        (selected_rses, preferred_unmatched,) = resolve_rse_expression(
            rse_expression,
            account,
            weight=weight,
            copies=copies,
            size=0,
            preferred_rses=preferred_rses,
        )
    return selected_rses, preferred_rses, preferred_unmatched


def get_subscriptions(logger: "Callable" = logging.log) -> List[Dict]:
    """
    A method to extract the list of active subscriptions and exclued the one that have bad RSE expression.
    :param logger: The logger.
    :return: The list of active subscriptions.
    """
    subscriptions = []
    try:
        sub_dict = {3: []}
        #  Get the list of subscriptions. The default priority of the subscription is 3. 0 is the highest priority, 5 the lowest
        #  The priority is defined as 'policyid'
        logger(logging.DEBUG, "Listing active subscriptions")
        for sub in list_subscriptions(None, None):
            rse_expression = sub.get("rse_expression")
            skip_sub = False
            rules = loads(sub["replication_rules"])
            overwrite_rules = False
            for rule in rules:
                rse_expression = rule.get("rse_expression")
                try:
                    list_rses_from_expression = parse_expression(rse_expression)
                except InvalidRSEExpression:
                    logger(
                        logging.ERROR,
                        "Invalid RSE expression %s for subscription %s. Subscription removed from the list",
                        rse_expression,
                        sub["id"],
                    )
                    skip_sub = True
                    break
                if rule.get("copies") == "*":
                    rule["copies"] = len(list_rses_from_expression)
                    overwrite_rules = True
            if skip_sub:
                continue
            if overwrite_rules:
                sub["replication_rules"] = dumps(rules)
            if (
                sub["state"] != SubscriptionState.INACTIVE
                and sub["lifetime"]
                and (datetime.now() > sub["lifetime"])
            ):
                update_subscription(
                    name=sub["name"],
                    account=sub["account"],
                    metadata={"state": SubscriptionState.INACTIVE},
                )

            elif sub["state"] in [SubscriptionState.ACTIVE, SubscriptionState.UPDATED]:
                priority = 3
                if "policyid" in sub:
                    if int(sub["policyid"]) not in sub_dict:
                        sub_dict[int(sub["policyid"])] = []
                    priority = int(sub["policyid"])
                sub_dict[priority].append(sub)
        priorities = list(sub_dict.keys())
        priorities.sort()
        #  Order the subscriptions according to their priority
        for priority in priorities:
            subscriptions.extend(sub_dict[priority])
        logger(logging.INFO, "%i active subscriptions", len(subscriptions))
    except SubscriptionNotFound as error:
        logger(logging.WARNING, "No subscriptions defined: %s" % (str(error)))
        return []
    except TypeError as error:
        logger(
            logging.ERROR,
            "Failed to parse subscription: %s" % (str(error)),
        )
        raise error
    except Exception as error:
        logger(
            logging.ERROR,
            "Failed to get list of new DIDs or subscriptions: %s" % (str(error)),
        )
        raise error
    return subscriptions


def __is_matching_subscription(subscription, did, metadata):
    """
    Internal method to identify if a DID matches a subscription.

    :param subscription: The subscription dictionary.
    :param did: The DID dictionary
    :param metadata: The metadata dictionnary for the DID
    :return: True/False
    """
    if metadata["hidden"]:
        return False
    try:
        filter_string = loads(subscription["filter"])
    except ValueError as error:
        logging.error("%s : Subscription will be skipped" % error)
        return False
    # Loop over the keys of filter_string for subscription
    for key in filter_string:
        values = filter_string[key]
        if key == "pattern":
            if not re.match(values, did["name"]):
                return False
        elif key == "excluded_pattern":
            if re.match(values, did["name"]):
                return False
        elif key == "split_rule":
            pass
        elif key == "scope":
            match_scope = False
            for scope in values:
                if re.match(scope, did["scope"].internal):
                    match_scope = True
                    break
            if not match_scope:
                return False
        elif key == "account":
            match_account = False
            if not isinstance(values, list):
                values = [values]
            for account in values:
                if account == metadata["account"].internal:
                    match_account = True
                    break
            if not match_account:
                return False
        elif key == "did_type":
            match_did_type = False
            if not isinstance(values, list):
                values = [values]
            for did_type in values:
                if did_type == metadata["did_type"].name:
                    match_did_type = True
                    break
            if not match_did_type:
                return False
        elif key in ["min_avg_file_size", "max_avg_file_size"]:
            length = metadata["length"]
            size = metadata["bytes"]
            if length and size:
                avg_file_size = size / length
                if key == "min_avg_file_size" and avg_file_size < values:
                    return False
                if key == "max_avg_file_size" and avg_file_size > values:
                    return False
            else:
                # If the DID is evaluated at the creation, length and bytes are not set yet
                # In that case, just ignore min_avg_file_size and max_avg_file_size filter
                continue
        else:
            if not isinstance(values, list):
                values = [
                    values,
                ]
            has_metadata = False
            for meta in metadata:
                if str(meta) == str(key):
                    has_metadata = True
                    match_meta = False
                    for value in values:
                        if re.match(str(value), str(metadata[meta])):
                            match_meta = True
                            break
                    if not match_meta:
                        return False
            if not has_metadata:
                return False
    return True


def select_algorithm(algorithm: str, rule_ids: list, params: dict) -> dict:
    """
    Method used in case of chained subscriptions

    :param algorithm: Algorithm used for the chained rule. Now only associated_site
                      associated_site : Choose an associated endpoint according to the RSE attribute assoiciated_site
    :param rule_ids: List of parent rules
    :param params: Dictionary of rules parameters to be used by the algorithm
    """
    selected_rses = {}
    if algorithm == "associated_site":
        for rule_id in rule_ids:
            rule = get_rule(rule_id)
            logging.debug("In select_algorithm, %s", str(rule))
            rse = rule["rse_expression"]
            vo = rule["account"].vo
            if rse_exists(rse, vo=vo):
                rse_id = get_rse_id(rse, vo=vo)
                rse_attributes = list_rse_attributes(rse_id)
                associated_sites = rse_attributes.get("associated_sites", None)
                associated_site_idx = params.get("associated_site_idx", None)
                if not associated_site_idx:
                    raise SubscriptionWrongParameter(
                        "Missing parameter associated_site_idx"
                    )
                if associated_sites:
                    associated_sites = associated_sites.split(",")
                    if associated_site_idx > len(associated_sites) + 1:
                        raise SubscriptionWrongParameter(
                            "Parameter associated_site_idx is out of range"
                        )
                    associated_site = associated_sites[associated_site_idx - 1]
                    selected_rses[associated_site] = {
                        "source_replica_expression": rse,
                        "weight": None,
                    }
            else:
                raise SubscriptionWrongParameter(
                    "Algorithm associated_site only works with split_rule"
                )
            if rule["copies"] != 1:
                raise SubscriptionWrongParameter(
                    "Algorithm associated_site only works with split_rule"
                )
    return selected_rses


def transmogrifier(bulk: int = 5, once: bool = False, sleep_time: int = 60) -> None:
    """
    Creates a Transmogrifier Worker that gets a list of new DIDs for a given hash,
    identifies the subscriptions matching the DIDs and
    submit a replication rule for each DID matching a subscription.

    :param bulk: The number of requests to process.
    :param once: Run only once.
    :param sleep_time: Time between two cycles.
    """
    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable="transmogrifier",
        logger_prefix="transmogrifier",
        partition_wait_time=1,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            bulk=bulk,
        ),
    )


def run_once(heartbeat_handler: "HeartbeatHandler", bulk: int, **_kwargs) -> bool:

    worker_number, total_workers, logger = heartbeat_handler.live()
    timer = monitor.Timer()
    blocklisted_rse_id = [rse["id"] for rse in list_rses({"availability_write": False})]
    identifiers = []
    #  List all the active subscriptions
    subscriptions = get_subscriptions(logger=logger)

    #  Loop over all the new dids
    #  Get the new DIDs based on the is_new flag
    logger(logging.DEBUG, "Listing new dids")
    for did in list_new_dids(
        thread=worker_number,
        total_threads=total_workers,
        chunk_size=bulk,
        did_type=None,
    ):
        _, _, logger = heartbeat_handler.live()
        did_success = True
        if not (
            did["did_type"] == DIDType.DATASET or did["did_type"] == DIDType.CONTAINER
        ):
            identifiers.append(
                {
                    "scope": did["scope"],
                    "name": did["name"],
                    "did_type": did["did_type"],
                }
            )
            continue
        metadata = get_metadata(did["scope"], did["name"])

        #  Loop over all the subscriptions
        for subscription in subscriptions:
            #  Check if the DID match the subscription
            if __is_matching_subscription(subscription, did, metadata) is True:
                filter_string = loads(subscription["filter"])
                split_rule = filter_string.get("split_rule", False)
                stime = time.time()
                logger(
                    logging.INFO,
                    "%s:%s matches subscription %s"
                    % (did["scope"], did["name"], subscription["name"]),
                )
                rules = loads(subscription["replication_rules"])
                created_rules = {}
                for cnt, rule_dict in enumerate(rules):
                    created_rules[cnt + 1] = []
                    #  Get all the rule and subscription parameters
                    rule_dict = __get_rule_dict(rule_dict, subscription)
                    weight = rule_dict.get("weight", None)
                    source_replica_expression = rule_dict.get(
                        "source_replica_expression", None
                    )
                    copies = rule_dict["copies"]
                    success = False

                    chained_idx = rule_dict.get("chained_idx", None)
                    #  By default selected_rses contains only the rse_expression
                    #  It is overwritten in 2 cases : Chained subscription and split_rule
                    selected_rses = [rule_dict.get("rse_expression")]
                    if chained_idx:
                        #  In the case of chained subscription, don't use rseselector but use the rses returned by the algorithm
                        params = {}
                        if rule_dict.get("associated_site_idx", None):
                            params["associated_site_idx"] = rule_dict.get(
                                "associated_site_idx", None
                            )
                        logger(
                            logging.DEBUG,
                            "Chained subscription identified. Will use %s",
                            str(created_rules[chained_idx]),
                        )
                        algorithm = rule_dict.get("algorithm", None)
                        selected_rses = select_algorithm(
                            algorithm, created_rules[chained_idx], params
                        )
                        copies = 1
                    elif split_rule:
                        try:
                            (
                                selected_rses,
                                preferred_rses,
                                preferred_unmatched,
                            ) = __split_rule_select_rses(
                                subscription_id=subscription["id"],
                                subscription_name=subscription["name"],
                                scope=did["scope"],
                                name=did["name"],
                                account=rule_dict.get("account"),
                                weight=weight,
                                rse_expression=rule_dict.get("rse_expression"),
                                copies=copies,
                                blocklisted_rse_id=blocklisted_rse_id,
                                logger=logger,
                            )
                            copies = 1
                        except (
                            InsufficientTargetRSEs,
                            InsufficientAccountLimit,
                            InvalidRuleWeight,
                            RSEOverQuota,
                        ) as error:
                            logger(
                                logging.WARNING,
                                'Problem getting RSEs for subscription "%s" for account %s : %s. Skipping rule creation.'
                                % (
                                    subscription["name"],
                                    rule_dict.get("account"),
                                    str(error),
                                ),
                            )
                            monitor.record_counter(
                                name="transmogrifier.addnewrule.errortype.{exception}",
                                labels={"exception": str(error.__class__.__name__)},
                            )
                            # The DID won't be reevaluated at the next cycle
                            did_success = did_success and True
                            continue

                        if len(preferred_rses) - len(preferred_unmatched) >= copies:
                            continue

                    nb_rule = 0
                    #  Try to create the rule
                    try:
                        for rse in selected_rses:
                            if isinstance(selected_rses, dict):
                                #  selected_rses is a dictionary only when split_rule is True or for chained subscriptions
                                source_replica_expression = selected_rses[rse].get(
                                    "source_replica_expression",
                                    None,
                                )
                                weight = selected_rses[rse].get("weight", None)
                            logger(
                                logging.INFO,
                                "Will insert one rule for %s:%s on %s"
                                % (did["scope"], did["name"], rse),
                            )
                            rule_ids = add_rule(
                                dids=[
                                    {
                                        "scope": did["scope"],
                                        "name": did["name"],
                                    }
                                ],
                                account=rule_dict.get("account"),
                                copies=copies,
                                rse_expression=rse,
                                grouping=rule_dict.get("grouping", "DATASET"),
                                weight=weight,
                                lifetime=rule_dict.get("lifetime", None),
                                locked=rule_dict.get("locked", None),
                                subscription_id=subscription["id"],
                                source_replica_expression=source_replica_expression,
                                activity=rule_dict.get("activity"),
                                purge_replicas=rule_dict.get("purge_replicas", False),
                                ignore_availability=rule_dict.get(
                                    "ignore_availability", None
                                ),
                                comment=rule_dict.get("comment"),
                                delay_injection=rule_dict.get("delay_injection"),
                            )
                            created_rules[cnt + 1].append(rule_ids[0])
                            nb_rule += 1
                            if nb_rule == copies:
                                success = True
                            if split_rule:
                                success = True

                        monitor.record_counter(
                            name="transmogrifier.addnewrule.done",
                            delta=nb_rule,
                        )
                        monitor.record_counter(
                            name="transmogrifier.addnewrule.activity.{activity}",
                            delta=nb_rule,
                            labels={
                                "activity": "".join(rule_dict.get("activity").split())
                            },
                        )
                        success = True
                    except (
                        InvalidReplicationRule,
                        InvalidRuleWeight,
                        InvalidRSEExpression,
                        StagingAreaRuleRequiresLifetime,
                        DuplicateRule,
                    ) as error:
                        # Errors that won't be retried
                        success = True
                        logger(logging.ERROR, str(error))
                        monitor.record_counter(
                            name="transmogrifier.addnewrule.errortype.{exception}",
                            labels={"exception": str(error.__class__.__name__)},
                        )
                    except Exception:
                        # Errors that will be retried
                        monitor.record_counter(
                            name="transmogrifier.addnewrule.errortype.{exception}",
                            labels={"exception": "unknown"},
                        )
                        logger(logging.ERROR, "Unexpected error", exc_info=True)

                    did_success = did_success and success
                    if not success:
                        logger(
                            logging.ERROR,
                            "Rule for %s:%s on %s cannot be inserted"
                            % (
                                did["scope"],
                                did["name"],
                                rule_dict.get("rse_expression"),
                            ),
                        )
                    else:
                        logger(
                            logging.INFO,
                            "%s rule(s) inserted in %f seconds"
                            % (str(nb_rule), time.time() - stime),
                        )

        if did_success:
            if did["did_type"] == str(DIDType.FILE):
                monitor.record_counter(name="transmogrifier.did.file.processed")
            elif did["did_type"] == str(DIDType.DATASET):
                monitor.record_counter(name="transmogrifier.did.dataset.processed")
            elif did["did_type"] == str(DIDType.CONTAINER):
                monitor.record_counter(
                    name="transmogrifier.did.container.processed", delta=1
                )
            monitor.record_counter(name="transmogrifier.did.processed", delta=1)
            identifiers.append(
                {
                    "scope": did["scope"],
                    "name": did["name"],
                    "did_type": did["did_type"],
                }
            )

    #  Mark the DIDs as processed
    flag_timer = monitor.Timer()
    for identifier in chunks(identifiers, 100):
        set_new_dids(identifier, None)
    logger(logging.DEBUG, "Time to set the new flag : %f" % flag_timer.elapsed)

    timer.stop()

    for sub in subscriptions:
        update_subscription(
            name=sub["name"],
            account=sub["account"],
            metadata={"last_processed": datetime.now()},
        )
    logger(
        logging.INFO,
        "It took %f seconds to process %i DIDs" % (timer.elapsed, len(identifiers)),
    )
    logger(logging.DEBUG, "DIDs processed : %s" % (str(identifiers)))
    monitor.record_counter(name="transmogrifier.job.done", delta=1)
    timer.record("transmogrifier.job.duration")
    must_sleep = True
    return must_sleep


def run(
    threads: int = 1, bulk: int = 100, once: bool = False, sleep_time: int = 60
) -> None:
    """
    Starts up the transmogrifier threads.
    """
    setup_logging()

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException("Database was not updated, daemon won't start")

    if once:
        logging.info("Will run only one iteration in a single threaded mode")
        transmogrifier(bulk=bulk, once=once)
    else:
        logging.info("starting transmogrifier threads")
        thread_list = [
            threading.Thread(
                target=transmogrifier,
                kwargs={"once": once, "sleep_time": sleep_time, "bulk": bulk},
            )
            for _ in range(0, threads)
        ]
        [thread.start() for thread in thread_list]
        logging.info("waiting for interrupts")
        # Interruptible joins require a timeout.
        while thread_list:
            thread_list = [
                thread.join(timeout=3.14)
                for thread in thread_list
                if thread and thread.is_alive()
            ]


def stop(signum=None, frame=None):
    """
    Graceful exit.
    """
    graceful_stop.set()
