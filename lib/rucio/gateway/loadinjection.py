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
from typing import TYPE_CHECKING, Any

import rucio.gateway.permission
from rucio.common.exception import (
    AccessDenied,
    DuplicateLoadInjectionPlan,
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
    for plan in injection_plans:
        src_rse_id = get_rse_id(plan["src_rse"], vo=vo, session=session)
        dest_rse_id = get_rse_id(plan["dest_rse"], vo=vo, session=session)
        # Change RSE name to RSE ID.
        plan["src_rse_id"] = src_rse_id
        plan["dest_rse_id"] = dest_rse_id
        # Internal ID and state.
        plan["state"] = LoadInjectionState.WAITING
        plan["plan_id"] = generate_uuid()

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

    present_plans = load_injection.get_injection_plans()
    for new_plan in injection_plans:
        logging.debug("Adding load injection plan %s to database.", str(new_plan))
        new_src_id = get_rse_id(new_plan["src_rse"])
        new_dest_id = get_rse_id(new_plan["dest_rse"])
        exist = any(
            plan.get("src_rse_id") == new_src_id
            and plan.get("dest_rse_id") == new_dest_id
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
        result = load_injection.get_injection_plans()
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
        src_rse_id = get_rse_id(src_rse)
        dest_rse_id = get_rse_id(dest_rse)
        result = load_injection.get_injection_plan(src_rse_id, dest_rse_id)
    except NoLoadInjectionPlanFound:
        raise
    logging.debug("Getting load injection plan %s", _format_plans([result]))
    return _format_plans(result)[0]


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

    src_rse_id = get_rse_id(src_rse)
    dest_rse_id = get_rse_id(dest_rse)
    try:
        load_injection.delete_injection_plan(src_rse_id, dest_rse_id)
    except NoLoadInjectionPlanFound:
        raise


def _format_plans(plans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Format load injection plans to user readable format.

    :param plans: List of plans.

    :return: List of formatted plans.
    """
    formatted_plans = list()
    for plan in plans:
        formatted_plan = plan.copy()
        formatted_plan["src_rse"] = get_rse_name(formatted_plan.pop("src_rse_id"))
        formatted_plan["dest_rse"] = get_rse_name(formatted_plan.pop("dest_rse_id"))
        formatted_plan.pop("created_at", None)
        formatted_plan.pop("updated_at", None)
        formatted_plans.append(formatted_plan)
    return formatted_plans
