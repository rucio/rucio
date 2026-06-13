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
from typing import TYPE_CHECKING, Any

from sqlalchemy.exc import NoResultFound

import rucio.db.sqla.util
from rucio.common import exception
from rucio.common.logging import setup_logging
from rucio.common.types import InternalAccount, InternalScope
from rucio.core.load_injection import (
    add_injection_plans_history,
    delete_injection_plan,
    finish_injecting_plan,
    get_injection_plan_state,
    get_injection_plans,
    get_unique_rse_pair_datasets,
    heartbeat_injecting_plan,
    try_claim_plan,
    try_recover_zombie_plan,
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
    Submit a load injection plan. Runs as a sub-thread spawned by run_once.

    For each injection interval, selects unique datasets that exist on the source
    RSE but not the destination, and creates replication rules to generate the
    target transfer rate (in Mbps). Datasets are reused only after their previous
    rules have expired (rule_lifetime + expiration_delay).

    The cached unique datasets are refreshed from the DB periodically so that
    newly scanned datasets become available mid-plan.
    """

    src_rse_id = plan["src_rse_id"]
    dest_rse_id = plan["dest_rse_id"]
    mbps = plan["inject_rate"]
    src_rse_name = get_rse_name(src_rse_id)
    dest_rse_name = get_rse_name(dest_rse_id)

    # Convert Mbps to bytes: 125000 B/s = 1 Mbps
    total_unfudged = int(125000 * mbps)
    total_bytes = total_unfudged
    if plan["fudge"] > 0:
        total_bytes = total_unfudged * (1 + plan["fudge"])
    injection_bytes = int(total_bytes * plan["interval"])

    # Track injection timestamps per dataset to implement cooldown/reuse logic.
    # Key: (scope, name) -> datetime when the dataset was last injected.
    injected_at: dict[tuple[str, str], datetime.datetime] = {}

    # Cooldown period before a dataset can be reused (rule_lifetime + expiration_delay).
    cooldown = datetime.timedelta(
        seconds=plan["rule_lifetime"] + plan["expiration_delay"]
    )

    def load_unique_datasets() -> list[dict[str, Any]]:
        """Load and sort cached unique datasets from the DB."""
        datasets = get_unique_rse_pair_datasets(src_rse_id, dest_rse_id)
        datasets.sort(key=lambda x: x["bytes"], reverse=plan["big_first"])
        return datasets

    def get_fresh_datasets(datasets: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Filter datasets to only those whose cooldown has expired."""
        now = datetime.datetime.utcnow()
        fresh = []
        for ds in datasets:
            key = (ds["scope"], ds["name"])
            last_injected = injected_at.get(key)
            if last_injected is None or now - last_injected > cooldown:
                fresh.append(ds)
        return fresh

    # Load cached unique datasets from DB. They are refreshed periodically
    # (every REFRESH_EVERY_N_LOOPS iterations) to pick up newly scanned datasets.
    REFRESH_EVERY_N_LOOPS = 10
    # Plan was already claimed (WAITING → INJECTING) atomically by run_once.
    unique_datasets = load_unique_datasets()
    rule_ids: list[str] = []
    loop_count = 0

    logger(
        logging.INFO,
        f"Sub: {src_rse_name} -> {dest_rse_name} :: "
        f"plan={plan['plan_id'][:8]}...  rate={mbps} Mbps  "
        f"target={injection_bytes/1e9:.2f} GB/interval  "
        f"interval={plan['interval']}s  end={plan['end_time'].strftime('%H:%M:%S')}  "
        f"cached={len(unique_datasets)} datasets  "
        f"mode={'DRY-RUN' if plan['dry_run'] else 'LIVE'}",
    )

    while True:
        # Heartbeat at the top of every loop so the updated_at timestamp
        # is fresh before any work—including long rule-creation batches.
        # Also re-checks for kill that may have arrived during sleep.
        current_state = get_injection_plan_state(src_rse_id, dest_rse_id)
        if current_state == LoadInjectionState.KILLED:
            # Let the kill guard below handle cleanup next iteration.
            pass
        elif current_state == LoadInjectionState.INJECTING:
            heartbeat_injecting_plan(
                src_rse_id=src_rse_id,
                dest_rse_id=dest_rse_id,
            )

        # Check for explicit operator kill — expire all rules immediately.
        if (
            get_injection_plan_state(src_rse_id, dest_rse_id)
            == LoadInjectionState.KILLED
        ):
            logger(
                logging.INFO,
                f"Sub: {src_rse_name} -> {dest_rse_name}, {LoadInjectionState.KILLED} :: "
                f"Removing {len(rule_ids)} active rules for plan {plan['plan_id']}.",
            )
            for rule_id in rule_ids:
                try:
                    update_rule(rule_id=rule_id, options={"lifetime": 0})
                except Exception:
                    logger(
                        logging.DEBUG,
                        f"Sub: {src_rse_name} -> {dest_rse_name} :: "
                        f"Rule {rule_id} already expired or removed, skip.",
                    )
            break

        # Graceful daemon shutdown — exit loop without expiring rules
        # (they will run to completion with their lifetime) and without
        # changing state (zombie recovery handles stale plans on restart).
        if graceful_stop.is_set():
            logger(
                logging.INFO,
                f"Sub: {src_rse_name} -> {dest_rse_name} :: "
                f"Graceful stop — exiting with {len(rule_ids)} active rules, "
                f"plan remains INJECTING.",
            )
            break

        # Check end_time BEFORE creating rules — if the window expired
        # during sleep, exit immediately without injecting another batch.
        if datetime.datetime.utcnow() >= plan["end_time"]:
            logger(
                logging.INFO,
                f"Sub: {src_rse_name} -> {dest_rse_name}, {LoadInjectionState.FINISHED} :: "
                f"Plan {plan['plan_id']} reached end time, stopping.",
            )
            break

        # Periodically refresh the unique dataset cache from DB so that
        # datasets added by the scanner mid-plan become available.
        if loop_count > 0 and loop_count % REFRESH_EVERY_N_LOOPS == 0:
            prev_count = len(unique_datasets)
            unique_datasets = load_unique_datasets()
            logger(
                logging.DEBUG,
                f"Sub: {src_rse_name} -> {dest_rse_name} :: "
                f"cache refreshed: {prev_count} -> {len(unique_datasets)} datasets "
                f"(loop #{loop_count})",
            )

        fresh_datasets = get_fresh_datasets(unique_datasets)
        logger(
            logging.DEBUG,
            f"Sub: {src_rse_name} -> {dest_rse_name}, {LoadInjectionState.INJECTING} :: "
            f"{len(fresh_datasets)} fresh datasets out of {len(unique_datasets)} total.",
        )

        # Refresh heartbeat before potentially long per-dataset rule creation.
        # Without this, a second worker could consider us stale during a large
        # batch and incorrectly trigger zombie recovery.
        if not heartbeat_injecting_plan(src_rse_id, dest_rse_id):
            # State was changed (likely KILLED) — exit loop
            break

        # Select datasets until we reach the target byte count for this interval.
        selected_datasets = []
        injected_bytes = 0
        max_bytes = int(injection_bytes * (1 + plan["max_injection"]))
        for dataset in fresh_datasets:
            if injected_bytes + dataset["bytes"] > max_bytes:
                continue
            if not validate_unique_rse_pair_dataset(
                scope=dataset["scope"],
                name=dataset["name"],
                src_rse_id=src_rse_id,
                dest_rse_id=dest_rse_id,
            ):
                logger(
                    logging.DEBUG,
                    f"Sub: Skipping bad dataset {dataset['scope']}:{dataset['name']}.",
                )
                continue
            selected_datasets.append(dataset)
            injected_bytes += dataset["bytes"]
            if injected_bytes >= injection_bytes:
                break

        injection_gbytes = injection_bytes / 1e9
        injected_gbytes = injected_bytes / 1e9
        logger(
            logging.INFO,
            f"Sub: {src_rse_name} -> {dest_rse_name}, {LoadInjectionState.INJECTING} :: "
            f"Target {injection_gbytes:.2f} GB, injecting {injected_gbytes:.2f} GB "
            f"({len(selected_datasets)} datasets).",
        )

        if not selected_datasets:
            logger(
                logging.WARNING,
                f"Sub: {src_rse_name} -> {dest_rse_name} :: "
                f"No fresh datasets available. Waiting for cooldown or scanner refresh.",
            )

        new_rule_ids = []
        now = datetime.datetime.utcnow()
        if selected_datasets:
            for i, ds in enumerate(selected_datasets):
                # Guard: stop creating rules if end_time has passed.
                # This is a free check (no DB call) that prevents
                # over-injection past the plan window boundary.
                if datetime.datetime.utcnow() >= plan["end_time"]:
                    logger(
                        logging.INFO,
                        f"Sub: {src_rse_name} -> {dest_rse_name} :: "
                        f"end_time reached mid-batch, stopping after "
                        f"{i}/{len(selected_datasets)} datasets.",
                    )
                    break

                # Guard: check for KILLED before every add_rule call.
                # The DB lookup is a simple indexed SELECT — cheap
                # enough to run per-dataset so no rule is ever created
                # after an operator kill signal.
                if (
                    get_injection_plan_state(src_rse_id, dest_rse_id)
                    == LoadInjectionState.KILLED
                ):
                    # Expire the rules we just created so they
                    # don't outlive the kill signal.
                    for rule_id in new_rule_ids:
                        try:
                            update_rule(
                                rule_id=rule_id, options={"lifetime": 0}
                            )
                        except Exception:
                            pass
                    rule_ids.extend(new_rule_ids)
                    new_rule_ids = []
                    logger(
                        logging.INFO,
                        f"Sub: {src_rse_name} -> {dest_rse_name} :: "
                        f"KILLED mid-batch, expired "
                        f"{len(rule_ids)} rules total.",
                    )
                    break

                # Create one rule per dataset for fault isolation —
                # a single bad dataset won't block the entire batch.
                try:
                    if plan["dry_run"]:
                        new_rule_ids.append("dryrun-rule-id")
                    else:
                        plan_vo = plan.get("vo") or "def"
                        # Normalize scope to a plain string — ds["scope"] may
                        # already be an InternalScope from the DB column type.
                        scope_str = str(ds["scope"])
                        new_rule_ids += add_rule(
                            dids=[{"scope": InternalScope(scope_str, vo=plan_vo), "name": ds["name"]}],
                            account=InternalAccount("root", vo=plan_vo),
                            copies=1,
                            rse_expression=dest_rse_name,
                            grouping="DATASET",
                            weight=None,
                            lifetime=plan["rule_lifetime"],
                            locked=False,
                            subscription_id=None,
                            source_replica_expression=src_rse_name,
                            activity="Load Injection",
                            notify="N",
                            purge_replicas=True,
                            comment=plan.get("comments", ""),
                        )
                    # Record injection timestamp for cooldown tracking.
                    injected_at[(ds["scope"], ds["name"])] = now
                except Exception as e:
                    err = str(e).replace("\n", ";;;")
                    logger(
                        logging.ERROR,
                        f"Sub: {src_rse_name} -> {dest_rse_name} :: "
                        f"Failed to create rule for {ds['scope']}:{ds['name']}: {err} -- SKIPPING.",
                    )
            rule_ids.extend(new_rule_ids)

        # Fast-path: if the plan was killed (including mid-batch), skip
        # the sleep loop and restart the main while-loop immediately so
        # the top-level KILLED handler at line ~130 expires all rules.
        if (
            get_injection_plan_state(src_rse_id, dest_rse_id)
            == LoadInjectionState.KILLED
        ):
            continue

        # Check if plan has reached its end time.
        if datetime.datetime.utcnow() >= plan["end_time"]:
            logger(
                logging.INFO,
                f"Sub: {src_rse_name} -> {dest_rse_name}, {LoadInjectionState.FINISHED} :: "
                f"Plan {plan['plan_id']} reached end time, stopping.",
            )
            break

        logger(
            logging.INFO,
            f"Sub: {src_rse_name} -> {dest_rse_name}, {LoadInjectionState.INJECTING} :: "
            f"Sleeping for {plan['interval']}s.",
        )
        # Sleep for the full interval, but check for kill every 10s.
        # Cap sleep to remaining time before end_time so we don't
        # sleep past the window boundary.
        remaining = min(
            plan["interval"],
            max(0, (plan["end_time"] - datetime.datetime.utcnow()).total_seconds()),
        )
        while remaining > 0 and not graceful_stop.is_set():
            snooze = min(remaining, 10)
            graceful_stop.wait(snooze)
            remaining -= snooze
            if get_injection_plan_state(src_rse_id, dest_rse_id) == LoadInjectionState.KILLED:
                break
        loop_count += 1

    # Determine the correct terminal state based on why the loop exited.
    # The DB already holds the authoritative state (KILLED was written by the
    # gateway, INJECTING by try_claim_plan). We read it back and combine it
    # with graceful_stop to decide the outcome.
    current_state = get_injection_plan_state(src_rse_id, dest_rse_id)

    current_state = get_injection_plan_state(src_rse_id, dest_rse_id)

    if current_state == LoadInjectionState.KILLED:
        # Operator sent kill signal — preserve KILLED state.
        logger(
            logging.INFO,
            f"Sub: {src_rse_name} -> {dest_rse_name} :: Plan killed, state remains KILLED.",
        )
    elif graceful_stop.is_set():
        # Daemon is shutting down — leave as INJECTING. Existing rules
        # have their lifetime and will run to completion. On restart,
        # zombie recovery handles stale plans via the updated_at heartbeat.
        logger(
            logging.INFO,
            f"Sub: {src_rse_name} -> {dest_rse_name} :: "
            f"Graceful stop — plan stays INJECTING, {len(rule_ids)} rules active.",
        )
    elif rule_ids:
        # Normal completion with rules created. Conditional transition
        # so a concurrent kill is never overwritten.
        finish_injecting_plan(src_rse_id, dest_rse_id)
        logger(
            logging.INFO,
            f"Sub: {src_rse_name} -> {dest_rse_name} :: "
            f"Plan completed with {len(rule_ids)} rules created.",
        )
    else:
        # Zero rules — normal completion with no output.
        # finish_injecting_plan is conditional (INJECTING→FINISHED);
        # if the plan was concurrently killed the transition is a no-op.
        finished = finish_injecting_plan(src_rse_id, dest_rse_id)
        logger(
            logging.WARNING,
            f"Sub: {src_rse_name} -> {dest_rse_name} :: "
            f"Plan ended with ZERO rules created. "
            f"State={'FINISHED' if finished else 'KILLED (concurrent)'}.",
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

    threads: list[tuple[str, threading.Thread]] = []  # (plan_id, thread)
    started_plans: set[str] = set()
    while True:
        # Graceful stop by Ctrl + C.
        if graceful_stop.is_set():
            [thread.join() for _, thread in threads]
            break

        # Get the plans to submit.
        plans = get_injection_plans()
        if not plans:
            logger(
                logging.INFO,
                "Main: No plans found. Sleeping.",
            )
        else:
            # Summarize plan states
            by_state: dict[str, int] = {}
            for p in plans:
                s = str(p.get("state", "?"))
                by_state[s] = by_state.get(s, 0) + 1
            state_summary = " ".join(f"{s}={c}" for s, c in sorted(by_state.items()))
            logger(
                logging.INFO,
                f"Main: {len(plans)} plans found  [{state_summary}]",
            )
            for plan in plans:
                if plan["state"] == LoadInjectionState.WAITING:
                    now = datetime.datetime.utcnow()
                    # Skip plans whose entire time window has already passed.
                    if plan["end_time"] <= now:
                        logger(
                            logging.INFO,
                            f"Main: Plan {plan['plan_id']} window already expired, "
                            f"moving to FINISHED.",
                        )
                        update_injection_plan_state(
                            plan["src_rse_id"],
                            plan["dest_rse_id"],
                            LoadInjectionState.FINISHED,
                        )
                        continue
                    if plan["start_time"] <= now:
                        if plan["plan_id"] not in started_plans:
                            # Atomically claim the plan to prevent duplicate execution
                            # when multiple submitter workers compete for the same plan.
                            if not try_claim_plan(plan["src_rse_id"], plan["dest_rse_id"]):
                                logger(
                                    logging.DEBUG,
                                    f"Main: Plan {plan['plan_id']} was already claimed by another worker, skip.",
                                )
                                continue
                            logger(
                                logging.INFO,
                                f"Main: Claimed + starting plan {plan['plan_id']}  "
                                f"{get_rse_name(plan['src_rse_id'])} -> {get_rse_name(plan['dest_rse_id'])}  "
                                f"\"{plan.get('comments', '')}\"",
                            )
                            thread = threading.Thread(target=plan_submitter, args=(plan, logger))
                            thread.start()
                            threads.append((plan["plan_id"], thread))
                            started_plans.add(plan["plan_id"])
                    else:
                        logger(
                            logging.INFO,
                            f"Main: Plan {plan['plan_id']} start_time not yet reached, skip.",
                        )
                elif plan["state"] == LoadInjectionState.FINISHED:
                    logger(
                        logging.INFO,
                        f"Main: Plan {plan['plan_id']} with comment \"{plan['comments']}\" is already finished, move it to history.",
                    )
                    # delete_injection_plan already archives to history internally
                    delete_injection_plan(plan["src_rse_id"], plan["dest_rse_id"])
                elif plan["state"] == LoadInjectionState.INJECTING:
                    # Detect zombie plans: a plan stuck in INJECTING with no
                    # heartbeat for > 20 * interval is considered dead.
                    updated_at = plan.get("updated_at")
                    if updated_at is not None:
                        stall_timeout = datetime.timedelta(
                            seconds=plan.get("interval", 900) * 20
                        )
                        deadline = datetime.datetime.utcnow() - stall_timeout
                        if updated_at < deadline:
                            if try_recover_zombie_plan(
                                plan["src_rse_id"],
                                plan["dest_rse_id"],
                                deadline,
                            ):
                                logger(
                                    logging.WARNING,
                                    f"Main: Recovered zombie plan {plan['plan_id']} "
                                    f"(stale since {updated_at}).",
                                )
                                continue
                    logger(
                        logging.INFO,
                        f"Main: Plan {plan['plan_id']} is already running "
                        f"(heartbeat {updated_at.strftime('%H:%M:%S') if updated_at else 'unknown'}), skip.",
                    )
                elif plan["state"] == LoadInjectionState.KILLED:
                    logger(
                        logging.INFO,
                        f"Main: Plan {plan['plan_id']} is KILLED, waiting for cleanup.",
                    )

        # Remove finished threads.
        threads = [(pid, t) for pid, t in threads if t.is_alive()]

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
    try:
        setup_logging(process_name=DAEMON_NAME)
    except Exception:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s\t%(name)s\t%(process)d\t%(levelname)s\t%(message)s',
        )

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
