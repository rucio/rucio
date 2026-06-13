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
import math
from datetime import datetime
from typing import TYPE_CHECKING, Any

import rucio.gateway.permission
from rucio.common.exception import (
    AccessDenied,
    DuplicateLoadInjectionPlan,
    InvalidObject,
    NoLoadInjectionPlanFound,
)
from rucio.common.utils import generate_uuid
from rucio.core import load_injection
from rucio.core.rse import get_rse_id, get_rse_name
from rucio.db.sqla.session import transactional_session, read_session
from rucio.db.sqla.constants import LoadInjectionState

if TYPE_CHECKING:
    from collections.abc import Sequence
    from sqlalchemy.orm import Session


@transactional_session
def add_load_injection_plans(
    injection_plans: "Sequence[dict[str, Any]]",
    issuer: str,
    vo: str,
    *,
    session: "Session"
) -> None:
    """
    Bulk add load injection plans.

    :param injection_plans: List of injection plans.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """
    kwargs = {"issuer": issuer}
    auth_result = rucio.gateway.permission.has_permission(
        issuer=issuer,
        vo=vo,
        action="add_load_injection_plans",
        kwargs=kwargs,
        session=session,
    )
    if not auth_result.allowed:
        raise AccessDenied(
            "Account %s can not bulk add load injection plans. %s"
            % (issuer, auth_result.message)
        )

    for plan in injection_plans:
        src_rse_id = get_rse_id(plan["src_rse"], vo=vo, session=session)
        dest_rse_id = get_rse_id(plan["dest_rse"], vo=vo, session=session)
        plan["src_rse_id"] = src_rse_id
        plan["dest_rse_id"] = dest_rse_id
        plan["state"] = LoadInjectionState.WAITING
        plan["plan_id"] = generate_uuid()
        plan["vo"] = vo
        plan["start_time"] = _parse_datetime(plan.get("start_time"), "start_time")
        plan["end_time"] = _parse_datetime(plan.get("end_time"), "end_time")
        _validate_plan_params(plan)

    present_plans = load_injection.get_injection_plans(vo=vo, session=session)
    for new_plan in injection_plans:
        logging.debug("Adding load injection plan %s to database.", str(new_plan))
        # Reuse src_rse_id/dest_rse_id already resolved in the first loop above
        exist = any(
            plan.get("src_rse_id") == new_plan["src_rse_id"]
            and plan.get("dest_rse_id") == new_plan["dest_rse_id"]
            for plan in present_plans
        )
        if exist:
            raise DuplicateLoadInjectionPlan(
                "Load injection plan from %s to %s already exists."
                % (new_plan["src_rse"], new_plan["dest_rse"])
            )

    try:
        load_injection.add_injection_plans(injection_plans)
    except DuplicateLoadInjectionPlan:
        raise


@read_session
def get_load_injection_plans(
    issuer: str, vo: str, *, session: "Session"
) -> list[dict[str, Any]]:
    """
    Get load injection plans.

    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param state: The state of the plan.
    :param session: The database session in use.
    """
    kwargs = {"issuer": issuer}
    auth_result = rucio.gateway.permission.has_permission(
        issuer=issuer,
        vo=vo,
        action="get_load_injection_plans",
        kwargs=kwargs,
        session=session,
    )
    if not auth_result.allowed:
        raise AccessDenied(
            "Account %s can not get load injection plans. %s"
            % (issuer, auth_result.message)
        )

    try:
        result = load_injection.get_injection_plans(vo=vo, session=session)
    except NoLoadInjectionPlanFound:
        raise
    logging.debug("Getting load injection plans %s", _format_plans(result))
    return _format_plans(result)


@read_session
def get_load_injection_plan(
    src_rse: str, dest_rse: str, issuer: str, vo: str, *, session: "Session"
) -> dict[str, Any]:
    """
    Get load injection plan.

    :param src_rse: The source RSE.
    :param dest_rse: The destination RSE.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """
    kwargs = {"issuer": issuer}
    auth_result = rucio.gateway.permission.has_permission(
        issuer=issuer,
        vo=vo,
        action="get_load_injection_plans",
        kwargs=kwargs,
        session=session,
    )
    if not auth_result.allowed:
        raise AccessDenied(
            "Account %s can not get load injection plan. %s"
            % (issuer, auth_result.message)
        )

    try:
        src_rse_id = get_rse_id(src_rse, vo=vo, session=session)
        dest_rse_id = get_rse_id(dest_rse, vo=vo, session=session)
        result = load_injection.get_injection_plan(
            src_rse_id, dest_rse_id, vo=vo, session=session
        )
    except NoLoadInjectionPlanFound:
        raise
    logging.debug("Getting load injection plan %s", _format_plans([result]))
    return _format_plans([result])[0]


@transactional_session
def delete_load_injection_plan(
    src_rse: str, dest_rse: str, issuer: str, vo: str, *, session: "Session"
) -> None:
    """
    Delete load injection plans.

    :param src_rse: The source RSE.
    :param dest_rse: The destination RSE.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """
    kwargs = {"issuer": issuer}
    auth_result = rucio.gateway.permission.has_permission(
        issuer=issuer,
        vo=vo,
        action="delete_load_injection_plans",
        kwargs=kwargs,
        session=session,
    )
    if not auth_result.allowed:
        raise AccessDenied(
            "Account %s can not delete load injection plans. %s"
            % (issuer, auth_result.message)
        )

    src_rse_id = get_rse_id(src_rse, vo=vo, session=session)
    dest_rse_id = get_rse_id(dest_rse, vo=vo, session=session)
    try:
        load_injection.delete_injection_plan(src_rse_id, dest_rse_id, vo=vo, session=session)
    except NoLoadInjectionPlanFound:
        raise


@transactional_session
def delete_load_injection_plans(
    injection_plans: "Sequence[dict[str, Any]]",
    issuer: str,
    vo: str,
    *,
    session: "Session"
) -> None:
    """
    Bulk delete load injection plans.

    :param injection_plans: List of plans with src_rse and dest_rse keys.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """
    kwargs = {"issuer": issuer}
    auth_result = rucio.gateway.permission.has_permission(
        issuer=issuer,
        vo=vo,
        action="delete_load_injection_plans",
        kwargs=kwargs,
        session=session,
    )
    if not auth_result.allowed:
        raise AccessDenied(
            "Account %s can not delete load injection plans. %s"
            % (issuer, auth_result.message)
        )

    plans = []
    for plan in injection_plans:
        plans.append({
            "src_rse_id": get_rse_id(plan["src_rse"], vo=vo, session=session),
            "dest_rse_id": get_rse_id(plan["dest_rse"], vo=vo, session=session),
        })
    try:
        load_injection.delete_injection_plans(plans, vo=vo, session=session)
    except NoLoadInjectionPlanFound:
        raise


@transactional_session
def update_load_injection_plan(
    src_rse: str,
    dest_rse: str,
    updates: dict[str, Any],
    issuer: str,
    vo: str,
    *,
    session: "Session"
) -> None:
    """
    Update an existing load injection plan. Removes the old plan and creates
    a new one with updated parameters.

    :param src_rse: The source RSE.
    :param dest_rse: The destination RSE.
    :param updates: Dictionary of plan parameters to update.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """
    kwargs = {"issuer": issuer}
    auth_result = rucio.gateway.permission.has_permission(
        issuer=issuer,
        vo=vo,
        action="add_load_injection_plans",
        kwargs=kwargs,
        session=session,
    )
    if not auth_result.allowed:
        raise AccessDenied(
            "Account %s can not update load injection plans. %s"
            % (issuer, auth_result.message)
        )

    src_rse_id = get_rse_id(src_rse, vo=vo, session=session)
    dest_rse_id = get_rse_id(dest_rse, vo=vo, session=session)

    # Fetch and lock the existing plan within this transaction.
    # FOR UPDATE prevents a TOCTOU race where the daemon claims and
    # finishes the plan between our state check and the delete+add below.
    try:
        existing = load_injection.get_injection_plan(
            src_rse_id, dest_rse_id, vo=vo, for_update=True, session=session
        )
    except NoLoadInjectionPlanFound:
        raise

    # Only allow updates while the plan is WAITING — terminal states
    # (FINISHED, KILLED) and active state (INJECTING) must not be
    # silently re-queued.
    if existing.get("state") != LoadInjectionState.WAITING:
        raise InvalidObject(
            "Cannot update plan from %s to %s while it is %s. "
            "Only WAITING plans can be updated."
            % (src_rse, dest_rse, existing.get("state", "UNKNOWN"))
        )

    # Build updated plan by merging existing values with updates
    field_map = {
        "inject_rate": "inject_rate",
        "interval": "interval",
        "start_time": "start_time",
        "end_time": "end_time",
        "fudge": "fudge",
        "max_injection": "max_injection",
        "expiration_delay": "expiration_delay",
        "big_first": "big_first",
        "rule_lifetime": "rule_lifetime",
        "comments": "comments",
        "dry_run": "dry_run",
        "src_rse": "src_rse",
        "dest_rse": "dest_rse",
    }
    # Generate a new plan_id so the archived old plan (from the delete
    # below) and the replacement plan never share a history primary key.
    updated_plan = {
        "plan_id": generate_uuid(),
        "src_rse_id": src_rse_id,
        "dest_rse_id": dest_rse_id,
        "vo": existing.get("vo"),
        "state": LoadInjectionState.WAITING,
    }
    for api_key, plan_key in field_map.items():
        if api_key in updates:
            updated_plan[plan_key] = updates[api_key]
        elif plan_key in existing:
            updated_plan[plan_key] = existing[plan_key]
    # Ensure required fields have defaults
    updated_plan.setdefault("fudge", 0.0)
    updated_plan.setdefault("max_injection", 0.2)
    updated_plan.setdefault("expiration_delay", 1800)
    updated_plan.setdefault("big_first", False)
    updated_plan.setdefault("rule_lifetime", 3600)
    updated_plan.setdefault("comments", "")
    updated_plan.setdefault("dry_run", False)

    # Parse datetime strings so the core always receives datetime objects,
    # mirroring the normalization in add_load_injection_plans.
    if "start_time" in updated_plan:
        updated_plan["start_time"] = _parse_datetime(updated_plan["start_time"], "start_time")
    if "end_time" in updated_plan:
        updated_plan["end_time"] = _parse_datetime(updated_plan["end_time"], "end_time")

    _validate_plan_params(updated_plan)

    # Replace old plan with updated plan in the outer transaction so both
    # operations commit or roll back together.
    try:
        load_injection.delete_injection_plan(src_rse_id, dest_rse_id, session=session)
        load_injection.add_injection_plans([updated_plan], session=session)
    except (NoLoadInjectionPlanFound, DuplicateLoadInjectionPlan):
        raise


@transactional_session
def kill_load_injection_plan(
    src_rse: str, dest_rse: str, issuer: str, vo: str, *, session: "Session"
) -> None:
    """
    Kill a running load injection plan by transitioning it to KILLED state.

    :param src_rse: The source RSE.
    :param dest_rse: The destination RSE.
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """
    kwargs = {"issuer": issuer}
    auth_result = rucio.gateway.permission.has_permission(
        issuer=issuer,
        vo=vo,
        action="delete_load_injection_plans",
        kwargs=kwargs,
        session=session,
    )
    if not auth_result.allowed:
        raise AccessDenied(
            "Account %s can not kill load injection plans. %s"
            % (issuer, auth_result.message)
        )

    src_rse_id = get_rse_id(src_rse, vo=vo, session=session)
    dest_rse_id = get_rse_id(dest_rse, vo=vo, session=session)
    try:
        # Conditional transition — only INJECTING → KILLED.
        # Prevents overwriting terminal states (FINISHED, KILLED)
        # or requeueing WAITING plans.
        if not load_injection.kill_injection_plan(
            src_rse_id, dest_rse_id, session=session
        ):
            raise InvalidObject(
                "Plan is not in INJECTING state and cannot be killed."
            )
    except NoLoadInjectionPlanFound:
        raise


DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def _validate_plan_params(plan: dict[str, Any]) -> None:
    """
    Validate plan parameters at the gateway boundary so the daemon never
    receives impossible values (zero intervals, inverted times, NaN, etc.).

    :raises InvalidObject: If any parameter is out of range.
    """
    inject_rate = plan.get("inject_rate", 0)
    if isinstance(inject_rate, bool) or not isinstance(inject_rate, int) or inject_rate <= 0:
        raise InvalidObject("inject_rate must be a positive integer, got %s." % inject_rate)
    if inject_rate > 1000000:
        raise InvalidObject("inject_rate must be <= 1,000,000 Mbps, got %s." % inject_rate)

    interval = plan.get("interval", 0)
    if isinstance(interval, bool) or not isinstance(interval, int) or interval < 1:
        raise InvalidObject("interval must be a positive integer (>= 1 second), got %s." % interval)
    if interval > 86400:
        raise InvalidObject("interval must be <= 86400 seconds (24h), got %s." % interval)

    rule_lifetime = plan.get("rule_lifetime", 0)
    if isinstance(rule_lifetime, bool) or not isinstance(rule_lifetime, int) or rule_lifetime < 1:
        raise InvalidObject("rule_lifetime must be a positive integer (>= 1 second), got %s." % rule_lifetime)
    if rule_lifetime > 604800:
        raise InvalidObject("rule_lifetime must be <= 604800 seconds (7 days), got %s." % rule_lifetime)

    expiration_delay = plan.get("expiration_delay", 0)
    if isinstance(expiration_delay, bool) or not isinstance(expiration_delay, int) or expiration_delay < 0:
        raise InvalidObject("expiration_delay must be a non-negative integer, got %s." % expiration_delay)
    if expiration_delay > 604800:
        raise InvalidObject("expiration_delay must be <= 604800 seconds (7 days), got %s." % expiration_delay)

    fudge = plan.get("fudge", 0)
    if isinstance(fudge, bool) or not isinstance(fudge, (int, float)) or not math.isfinite(fudge):
        raise InvalidObject("fudge must be a finite number, got %s." % fudge)
    if fudge < 0 or fudge > 1:
        raise InvalidObject("fudge must be between 0 and 1, got %s." % fudge)

    max_injection = plan.get("max_injection", 0)
    if isinstance(max_injection, bool) or not isinstance(max_injection, (int, float)) or not math.isfinite(max_injection):
        raise InvalidObject("max_injection must be a finite number, got %s." % max_injection)
    if max_injection < 0 or max_injection > 1:
        raise InvalidObject("max_injection must be between 0 and 1, got %s." % max_injection)

    start_time = plan.get("start_time")
    end_time = plan.get("end_time")
    if isinstance(start_time, datetime) and isinstance(end_time, datetime):
        if start_time >= end_time:
            raise InvalidObject(
                "start_time (%s) must be before end_time (%s)."
                % (start_time.strftime(DATETIME_FORMAT), end_time.strftime(DATETIME_FORMAT))
            )


def _parse_datetime(value: Any, field_name: str) -> datetime:
    """
    Parse a datetime value from string or pass through a datetime object.
    Validates format at the gateway boundary so the core/daemon layers
    always receive proper datetime objects.

    :param value: A datetime object or a string in "YYYY-MM-DD HH:MM:SS" format.
    :param field_name: Field name for error messages.
    :returns: A datetime object.
    :raises InvalidObject: If the value is neither a datetime nor a valid string.
    """
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.strptime(value, DATETIME_FORMAT)
        except ValueError:
            raise InvalidObject(
                f"Invalid {field_name} format: '{value}'. Expected YYYY-MM-DD HH:MM:SS."
            )
    raise InvalidObject(
        f"Invalid {field_name} type: {type(value).__name__}. Expected datetime or string."
    )


def _format_plans(plans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Format load injection plans to user readable format.
    Batches RSE name lookups to avoid N+1 queries.

    :param plans: List of plans.
    :return: List of formatted plans.
    """
    # Collect all unique RSE IDs and batch-resolve names
    rse_ids = set()
    for plan in plans:
        rse_ids.add(plan.get("src_rse_id"))
        rse_ids.add(plan.get("dest_rse_id"))
    rse_id_to_name = {rse_id: get_rse_name(rse_id) for rse_id in rse_ids}

    formatted_plans = []
    for plan in plans:
        formatted_plan = plan.copy()
        formatted_plan["src_rse"] = rse_id_to_name[formatted_plan.pop("src_rse_id")]
        formatted_plan["dest_rse"] = rse_id_to_name[formatted_plan.pop("dest_rse_id")]
        formatted_plan.pop("created_at", None)
        formatted_plan.pop("updated_at", None)
        formatted_plans.append(formatted_plan)
    return formatted_plans
