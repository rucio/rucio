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

import logging
import threading
import time
import datetime
from typing import TYPE_CHECKING

from sqlalchemy.exc import NoResultFound

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.logging import setup_logging
from rucio.common.types import InternalAccount, InternalScope
from rucio.core.load_injection import (
    add_injection_plans_history,
    delete_injection_plan,
    get_injection_plan_state,
    get_injection_plans,
    get_unique_rse_pair_datasets,
    update_injection_plan_state,
    validate_unique_rse_pair_dataset,
)
from rucio.core.rse import get_rse_name
from rucio.core.rule import add_rule, get_rule, update_rule
from rucio.db.sqla.constants import LoadInjectionState
from rucio.daemons.common import HeartbeatHandler, run_daemon

if TYPE_CHECKING:
    from types import FrameType
    from typing import Optional, Mapping, Any, Callable

graceful_stop = threading.Event()
DAEMON_NAME = "loadinjector-submitter"


def plan_submitter(
    plan: "Mapping[str, Any]",
    logger: "Callable",
) -> None:
    """
    Submit a plan. Work as a sub-thread in the run-once thread.
    """

    src_rse_id, dest_rse_id, mbps = (
        plan["src_rse_id"],
        plan["dest_rse_id"],
        plan["inject_rate"],
    )
    src_rse_name, dest_rse_name = get_rse_name(src_rse_id), get_rse_name(dest_rse_id)
    total_unfudged = int(125000 * mbps)  # 125000 B/s = 1 Mbps
    total_bytes = total_unfudged
    if plan["fudge"] > 0:
        total_bytes = total_unfudged * (1 + plan["fudge"])
    injection_bytes = int(total_bytes * plan["interval"])
    # HACK: Possibly not good to get unique datasets before looping, because it
    # still needs set 'injected_at' tag for each dataset.
    unique_datasets = get_unique_rse_pair_datasets(src_rse_id, dest_rse_id)
    unique_datasets.sort(key=lambda x: x["bytes"], reverse=plan["big_first"])

    # Update plan state to 'injecting'.
    update_injection_plan_state(
        src_rse_id=src_rse_id,
        dest_rse_id=dest_rse_id,
        new_state=LoadInjectionState.INJECTING,
    )

    # Start injection in each injection interval.
    rule_id = list()
    while True:
        # If plan is killed or daemon is gracefully stopped, we need to remove all rules before we stop the loop.
        if (
            get_injection_plan_state(src_rse_id, dest_rse_id)
            == LoadInjectionState.KILLED
            or graceful_stop.is_set()
        ):
            for rule in rule_id:
                try:
                    get_rule(rule_id=rule)
                except NoResultFound as exc:
                    logger(
                        logging.DEBUG,
                        f"Sub: {src_rse_name} -> {dest_rse_name}, {LoadInjectionState.KILLED} :: Rule {rule} has already expired and removed, skip.",
                    )
                    continue

                try:
                    update_rule(rule_id=rule, options={"lifetime": 0})
                    logger(
                        logging.INFO,
                        f"Sub: {src_rse_name} -> {dest_rse_name}, {LoadInjectionState.KILLED} :: Removing rule {rule} for plan {plan['id']}.",
                    )
                except Exception as e:
                    logger(
                        logging.ERROR,
                        f"Sub: {src_rse_name} -> {dest_rse_name}, {LoadInjectionState.KILLED} :: Failed to remove rule {rule} for plan {plan['id']}.",
                    )
            break

        # Get fresh unique datasets, which are not used after last loop.
        fresh_datasets = list()
        for dataset in unique_datasets:
            # HACK: This is a hack, I am not sure if this is the best way.
            if "injected_at" in dataset:
                if dataset[
                    "injected_at"
                ] < datetime.datetime.utcnow() - datetime.timedelta(
                    seconds=plan["rule_lifetime"]
                ) - datetime.timedelta(
                    seconds=plan["expiration_delay"]
                ):
                    fresh_datasets.append(dataset)
            else:
                fresh_datasets.append(dataset)

        length_total = len(unique_datasets)
        length_fresh = len(fresh_datasets)
        logger(
            logging.DEBUG,
            f"Sub: {src_rse_name} -> {dest_rse_name}, {LoadInjectionState.INJECTING} :: We have {length_fresh} fresh datasets out of {length_total}.",
        )

        # Select datasets to inject.
        selected_datasets = list()
        injected_bytes = 0
        for dataset in fresh_datasets:
            if injected_bytes + dataset["bytes"] > injection_bytes * (
                1 + plan["max_injection"]
            ):
                continue
            if not validate_unique_rse_pair_dataset:
                logger(
                    logging.DEBUG,
                    f"Sub: Skipping bad dataset {dataset['scope']}:{dataset['name']}.",
                )
                continue
            selected_datasets.append(dataset)
            injected_bytes += dataset["bytes"]

            if injected_bytes >= injection_bytes:
                break

        injection_gbytes = injection_bytes / (1000000000)
        injected_gbytes = injected_bytes / (1000000000)
        if injected_bytes == injection_bytes:
            logger(
                logging.INFO,
                f"Sub: {src_rse_name} -> {dest_rse_name}, {LoadInjectionState.INJECTING} :: Wanted {injection_gbytes}, injecting {injected_gbytes} Gbytes, -- HOLY CRAP, EQUAL!",
            )
        elif injected_bytes > injection_bytes:
            logger(
                logging.INFO,
                f"Sub: {src_rse_name} -> {dest_rse_name}, {LoadInjectionState.INJECTING} :: Wanted {injection_gbytes}, injecting {injected_gbytes} Gbytes, -- TOO MUCH, OH WELL IT IS A DATA CHALLENGE AFTER ALL.",
            )
        else:
            logger(
                logging.INFO,
                f"Sub: {src_rse_name} -> {dest_rse_name}, {LoadInjectionState.INJECTING} :: Wanted {injection_gbytes}, injecting {injected_gbytes} Gbytes, -- NOT ENOUGH, SAD ROBOT.",
            )

        length_selected = len(selected_datasets)
        logger(
            logging.INFO,
            f"Sub: {src_rse_name} -> {dest_rse_name}, {LoadInjectionState.INJECTING} :: Adding rules for {length_selected} datasets.",
        )

        dids = list()
        for dataset in selected_datasets:
            logger(
                logging.DEBUG,
                f"Sub: {src_rse_name} -> {dest_rse_name}, {LoadInjectionState.INJECTING} :: Adding rule for {dataset['scope']}:{dataset['name']}.",
            )
            scope, name = dataset["scope"], dataset["name"]
            new_rule_id = list()
            dids.append({"scope": InternalScope(scope), "name": name})
        try:
            if plan["dryrun"]:
                new_rule_id = ["dryrun-rule-id"]
            else:
                # TODO: I guess I use add_rule correctly, but I am not sure.
                new_rule_id = add_rule(
                    dids=dids,
                    copies=1,
                    rse_expression=dest_rse_name,
                    weight=None,
                    lifetime=plan["rule_lifetime"],
                    grouping="DATASET",
                    account=InternalAccount("root"),
                    locked=False,
                    subscrption_id=None,
                    source_replica_expression=src_rse_name,
                    activity="Load Injection",
                    notify="N",
                    purge_replicas=True,
                    comment=plan["comment"],
                )
                rule_id.extend(new_rule_id)
        except Exception as e:
            e = str(e).replace("\n", ";;;")
            logger(
                logging.ERROR,
                f"Sub: {src_rse_name} -> {dest_rse_name}, {LoadInjectionState.INJECTING} :: Injection messed up: {e} -- SKIPPING.",
            )
        # HACK: This is a hack, I am not sure if this is the best way.
        if new_rule_id:
            for dataset in selected_datasets:
                scope, name = dataset["scope"], dataset["name"]
                for d in unique_datasets:
                    if d["scope"] == scope and d["name"] == name:
                        d.update({"injected_id": datetime.datetime.utcnow()})

        # Check if it is finished.
        if datetime.datetime.utcnow() >= plan["end_time"]:
            logger(
                logging.INFO,
                f"Sub: {src_rse_name} -> {dest_rse_name}, {LoadInjectionState.FINISHED} :: Exceeded the end time, stopping looping.",
            )
            break

        # Sleep for next loop.
        logger(
            logging.INFO,
            f"Sub: {src_rse_name} -> {dest_rse_name}, {LoadInjectionState.INJECTING} :: Finished adding rules, sleeping for {plan['interval']} seconds.",
        )
        graceful_stop.wait(plan["interval"])

    # Update plan stat to finished.
    update_injection_plan_state(
        src_rse_id=src_rse_id,
        dest_rse_id=dest_rse_id,
        new_state=LoadInjectionState.FINISHED,
    )


def loadinjector_submitter(once: bool = False, sleep_time: int = 60) -> None:
    """
    Main loop for injecting plans.
    """
    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable=DAEMON_NAME,
        partition_wait_time=1,
        sleep_time=sleep_time,
        run_once_fnc=run_once,
    )


def run_once(heartbeat_handler: HeartbeatHandler, **_kwargs) -> None:
    """
    Run loadinjector submitter once.
    """
    work_number, total_workers, logger = heartbeat_handler.live()

    threads = list()
    while True:
        # Graceful stop by Ctrl + C.
        if graceful_stop.is_set():
            [thread.join() for thread in threads]
            break

        # Get the plans to submit.
        plans = get_injection_plans()
        if not plans:
            logger(
                logging.INFO,
                "Main: No more plans to deal with, go sleep and wait for next loop.",
            )
        else:
            for plan in plans:
                if plan["state"] == LoadInjectionState.WAITING:
                    if plans["start_time"] <= datetime.datetime.utcnow():
                        logger(
                            logging.INFO,
                            f"Main: Submitting plan {plan['plan_id']} with comment \"{plan['comments']}\".",
                        )
                        threads.append(
                            threading.Thread(target=plan_submitter, args=(plan, logger))
                        )
                    else:
                        logger(
                            logging.DEBUG,
                            f"Main: It's not time yet for plan {plan['plan_id']} with comment \"{plan['comments']}\", skip it.",
                        )
                elif plan["state"] == LoadInjectionState.FINISHED:
                    logger(
                        logging.INFO,
                        f"Main: Plan {plan['plan_id']} with comment \"{plan['comments']}\" is already finished, move it to history.",
                    )
                    delete_injection_plan(plan["src_rse_id"], plan["dest_rse_id"])
                    add_injection_plans_history([plan])
                elif plan["state"] == LoadInjectionState.INJECTING:
                    logger(
                        logging.INFO,
                        f"Main: Plan {plan['plan_id']} with comment \"{plan['comments']}\" is already running, skip it.",
                    )
                elif plan["state"] == LoadInjectionState.KILLED:
                    logger(
                        logging.DEBUG,
                        f"Main: Plan {plan['plan_id']} with comment \"{plan['comments']}\" need to be killed.",
                    )

        # Start waiting threads.
        for thread in threads:
            if not thread.is_alive() and not thread.ident:
                thread.start()

        # Remove finished threads.
        threads = [t for t in threads if t.is_alive()]

        # If threads still exist, main thread's long journey continues until all threads are finished.
        if threads:
            time.sleep(60)
        else:
            # If no thread exists, main thread's long journey ends.
            break


def stop(signum: "Optional[int]" = None, frame: "Optional[FrameType]" = None) -> None:
    """
    Graceful exit.
    """
    graceful_stop.set()


def run(once: bool = False, sleep_time: int = 60) -> None:
    """
    Start up the loadinjector submitter threads.
    """
    setup_logging(process_name=DAEMON_NAME)

    if rucio.db.sqla.util.is_old_db():
        raise exception.DatabaseException(
            "Database was not upgraded, daemon won't start."
        )

    if once:
        logging.info("Main: Excuting on iteration only")
        loadinjector_submitter(once)
    else:
        logging.info("Main: Executing in a loop")
        loadinjector_submitter(sleep_time=sleep_time)
