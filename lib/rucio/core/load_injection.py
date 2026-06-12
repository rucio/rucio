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

import datetime
from typing import TYPE_CHECKING, Any, Optional

from sqlalchemy.orm import aliased
from sqlalchemy.sql.expression import select, and_, not_, exists, delete, update
from sqlalchemy.exc import IntegrityError, NoResultFound, MultipleResultsFound

from rucio.common import exception
from rucio.common.exception import InvalidObject
from rucio.db.sqla import models, constants
from rucio.db.sqla.session import read_session, transactional_session

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from sqlalchemy.orm import Session


@read_session
def scan_unique_rse_pair_datasets(
    src_rse_id: str, dest_rse_id: str, *, session: "Session"
) -> "Sequence[Mapping[str, Any]]":
    """
    Scan the unique datasets for a given RSE pair from dataset_locks table.

    :param src_rse_id: The src RSE id.
    :param des_rse_id: The des RSE id.
    :param session: The database session in use.
    :returns: A list of unique datasets for the given RSE pair.
    """

    from sqlalchemy import func

    datasetlock_alias = aliased(models.DatasetLock)
    stmt = select(
        models.DatasetLock.scope,
        models.DatasetLock.name,
        func.min(models.DatasetLock.bytes).label("bytes"),
        func.min(models.DatasetLock.length).label("length"),
    ).where(
        and_(
            models.DatasetLock.state == constants.LockState.OK,
            models.DatasetLock.bytes > 0,
            models.DatasetLock.length.between(1, 1000),
            models.DatasetLock.bytes / models.DatasetLock.length > 100000000,
            models.DatasetLock.rse_id == src_rse_id,
            not_(
                exists().where(
                    and_(
                        datasetlock_alias.scope == models.DatasetLock.scope,
                        datasetlock_alias.name == models.DatasetLock.name,
                        datasetlock_alias.rse_id == dest_rse_id,
                    )
                )
            ),
        )
    ).group_by(
        models.DatasetLock.scope,
        models.DatasetLock.name,
    )
    query_result = session.execute(stmt).all()

    return [
        {
            "scope": row.scope,
            "name": row.name,
            "bytes": row.bytes,
            "length": row.length,
            "src_rse_id": src_rse_id,
            "dest_rse_id": dest_rse_id,
        }
        for row in query_result
    ]


@read_session
def get_unique_rse_pair_dataset(
    src_rse_id: str, dest_rse_id: str, scope: str, name: str, *, session: "Session"
) -> "Mapping[str, Any]":
    """
    Read the cached unique dataset for a given RSE pair from unique_datasets table.

    :param src_rse_id: The src RSE id.
    :param dest_rse_id: The dest RSE id.
    :param scope: The dataset scope.
    :param name: The dataset name.
    :param session: The database session in use.
    :returns: A dictionary with the unique dataset for the given RSE pair.
    """

    try:
        stmt = select(models.LoadInjectionDatasets).where(
            and_(
                models.LoadInjectionDatasets.scope == scope,
                models.LoadInjectionDatasets.name == name,
                models.LoadInjectionDatasets.src_rse_id == src_rse_id,
                models.LoadInjectionDatasets.dest_rse_id == dest_rse_id,
            )
        )
        query_result = session.execute(stmt).scalar_one()
        return query_result.to_dict()
    except MultipleResultsFound as error:
        raise exception.DuplicateUniqueDatasetFound(error.args)
    except NoResultFound as error:
        raise exception.NoUniqueDatasetFound(error.args)


@read_session
def get_unique_rse_pair_datasets(
    src_rse_id: str, dest_rse_id: str, *, session: "Session"
) -> "Sequence[Mapping[str, Any]]":
    """
    Read the cached unique datasets for a given RSE pair from unique_datasets table.

    :param src_rse_id: The src RSE id.
    :param dest_rse_id: The dest RSE id.
    :param session: The database session in use.
    :returns: A list of unique datasets for the given RSE pair.
    """

    stmt = select(models.LoadInjectionDatasets).where(
        and_(
            models.LoadInjectionDatasets.src_rse_id == src_rse_id,
            models.LoadInjectionDatasets.dest_rse_id == dest_rse_id,
        )
    )
    query_result = session.execute(stmt).scalars().all()
    return [dataset.to_dict() for dataset in query_result]


@transactional_session
def add_unique_rse_pair_dataset(
    src_rse_id: str,
    dest_rse_id: str,
    scope: str,
    name: str,
    bytes: int,
    length: int,
    *,
    session: "Session"
) -> None:
    """
    Add a unique dataset for a given RSE pair to unique_datasets table.

    :param src_rse_id: The src RSE id.
    :param dest_rse_id: The dest RSE id.
    :param scope: The dataset scope.
    :param name: The dataset name.
    :param bytes: The dataset size.
    :param length: The dataset length.
    :param session: The database session in use.
    """
    add_unique_rse_pair_datasets(
        [
            {
                "scope": scope,
                "name": name,
                "bytes": bytes,
                "length": length,
                "src_rse_id": src_rse_id,
                "dest_rse_id": dest_rse_id,
            }
        ],
        session=session,
    )


@transactional_session
def add_unique_rse_pair_datasets(
    datasets: "Sequence[Mapping[str, Any]]", *, session: "Session"
) -> None:
    """
    Add a list of unique datasets for a given RSE pair to unique_datasets table.

    :param datasets: The list of unique datasets for the given RSE pair.
    :param session: The database session in use.
    """
    try:
        for dataset in datasets:
            new_dataset = models.LoadInjectionDatasets(
                scope=dataset["scope"],
                name=dataset["name"],
                src_rse_id=dataset["src_rse_id"],
                dest_rse_id=dataset["dest_rse_id"],
                bytes=dataset["bytes"],
                length=dataset["length"],
            )
            new_dataset.save(session=session, flush=False)
        session.flush()
    except IntegrityError as error:
        raise exception.DuplicateContent(error.args)


@transactional_session
def delete_unique_rse_pair_dataset(
    src_rse_id: str, dest_rse_id: str, scope: str, name: str, *, session: "Session"
) -> None:
    """
    Delete a unique dataset for a given RSE pair from unique_datasets table.

    :param src_rse_id: The src RSE id.
    :param dest_rse_id: The dest RSE id.
    :param scope: The dataset scope.
    :param name: The dataset name.
    :param session: The database session in use.
    """
    delete_unique_rse_pair_datasets(
        [
            {
                "scope": scope,
                "name": name,
                "src_rse_id": src_rse_id,
                "dest_rse_id": dest_rse_id,
            }
        ],
        session=session,
    )


@transactional_session
def delete_unique_rse_pair_datasets(
    datasets: "Sequence[Mapping[str, Any]]", *, session: "Session"
) -> None:
    """
    Delete a list of unique datasets for a given RSE pair from unique_datasets table.

    :param datasets: The list of unique datasets for the given RSE pair.
    :param session: The database session in use.
    """
    try:
        for dataset in datasets:
            stmt = delete(models.LoadInjectionDatasets).where(
                and_(
                    models.LoadInjectionDatasets.src_rse_id == dataset["src_rse_id"],
                    models.LoadInjectionDatasets.dest_rse_id == dataset["dest_rse_id"],
                    models.LoadInjectionDatasets.scope == dataset["scope"],
                    models.LoadInjectionDatasets.name == dataset["name"],
                )
            )
            session.execute(stmt)
    except NoResultFound as error:
        raise exception.NoUniqueDatasetFound(error.args)


@read_session
def validate_unique_rse_pair_dataset(
    scope: str, name: str, src_rse_id: str, dest_rse_id: str, *, session: "Session"
) -> bool:
    """
    Varify that the unique rse pair dataset exactly exist in the src and does NOT exist in the dest.

    :param scope: The dataset scope.
    :param name: The dataset name.
    :param src_rse_id: The src RSE id.
    :param dest_rse_id: The dest RSE id.
    :param session: The database session in use.
    :returns: True if the dataset is unique, False otherwise.
    """
    datasetlock_alias = aliased(models.DatasetLock)
    stmt = select(models.DatasetLock).where(
        and_(
            models.DatasetLock.state == constants.LockState.OK,
            models.DatasetLock.scope == scope,
            models.DatasetLock.name == name,
            models.DatasetLock.rse_id == src_rse_id,
            not_(
                exists().where(
                    and_(
                        datasetlock_alias.scope == scope,
                        datasetlock_alias.name == name,
                        datasetlock_alias.rse_id == dest_rse_id,
                    )
                )
            ),
        )
    ).limit(1)
    # Use limit(1) instead of scalar_one_or_none to tolerate
    # multiple source locks: the same dataset can have several OK
    # locks on the same RSE under different rules.
    query_result = session.execute(stmt).scalar_one_or_none()
    return query_result is not None


def _apply_vo_filter(stmt, vo: "Optional[str]"):
    """
    When a VO is provided, JOIN with rses on both src and dest
    to restrict results to plans whose RSEs belong to that VO.
    Daemon paths pass vo=None to skip filtering and see all plans.
    """
    if vo is None:
        return stmt
    src_rse = aliased(models.RSE, name="src_rse_vo")
    dest_rse = aliased(models.RSE, name="dest_rse_vo")
    return (
        stmt
        .join(src_rse, models.LoadInjectionPlans.src_rse_id == src_rse.id)
        .join(dest_rse, models.LoadInjectionPlans.dest_rse_id == dest_rse.id)
        .where(and_(src_rse.vo == vo, dest_rse.vo == vo))
    )


@read_session
def get_injection_plan(
    src_rse_id: str,
    dest_rse_id: str,
    *,
    vo: "Optional[str]" = None,
    session: "Session",
) -> "Mapping[str, Any]":
    """
    Get an injection plan from the database.

    :param src_rse_id: The source RSE ID.
    :param dest_rse_id: The destination RSE ID.
    :param vo: Optional VO scope filter. When provided, the plan is only
        returned if both RSEs belong to this VO.
    :param session: The database session in use.
    :returns: An injection plan.
    """
    try:
        stmt = _apply_vo_filter(
            select(models.LoadInjectionPlans).where(
                and_(
                    models.LoadInjectionPlans.src_rse_id == src_rse_id,
                    models.LoadInjectionPlans.dest_rse_id == dest_rse_id,
                )
            ),
            vo,
        )
        query_result = session.execute(stmt).scalar_one()
        return query_result.to_dict()
    except NoResultFound as error:
        raise exception.NoLoadInjectionPlanFound(error.args)


@read_session
def get_injection_plans(
    *,
    vo: "Optional[str]" = None,
    session: "Session",
) -> "Sequence[Mapping[str, Any]]":
    """
    Get injection plans from the database, optionally scoped to a VO.

    :param vo: Optional VO scope filter. When provided, only plans whose
        src and dest RSEs belong to this VO are returned. When None
        (daemon paths), returns all plans.
    :param session: The database session in use.
    :returns: A list of injection plans.
    """
    stmt = _apply_vo_filter(select(models.LoadInjectionPlans), vo)
    query_result = session.execute(stmt).scalars().all()
    return [plan.to_dict() for plan in query_result]


@transactional_session
def add_injection_plan(
    plan_id: str,
    src_rse_id: str,
    dest_rse_id: str,
    inject_rate: int,
    interval: int,
    start_time: datetime.datetime,
    end_time: datetime.datetime,
    fudge: float = 0.0,
    max_injection: float = 0.2,
    expiration_delay: int = 1800,
    big_first: bool = False,
    rule_lifetime: int = 3600,
    comments: Optional[str] = None,
    dry_run: bool = False,
    state: constants.LoadInjectionState = constants.LoadInjectionState.WAITING,
    vo: Optional[str] = None,
    *,
    session: "Session"
) -> None:
    """
    Add an injection plan in the database.

    :param plan_id: The plan id.
    :param src_rse_id: The src RSE id.
    :param dest_rse_id: The dest RSE id.
    :param inject_rate: The injection rate.
    :param interval: The time interval between eche time injection.
    :param start_time: The start time of the injection plan.
    :param end_time: The end time of the injection plan.
    :param fudge: The fudge factor for the injection plan.
    :param max_injection: The maximum injection rate.
    :param expiration_delay: The expiration delay for the injection plan.
    :param big_first: The big first flag for the injection plan.
    :param rule_lifetime: The rule lifetime for the injection plan.
    :param comments: The comments for the injection plan.
    :param dry_run: The dry_run flag for the injection plan.
    :param state: The state of the injection plan.
    :param session: The database session in use.
    """
    add_injection_plans(
        [
            {
                "plan_id": plan_id,
                "src_rse_id": src_rse_id,
                "dest_rse_id": dest_rse_id,
                "inject_rate": inject_rate,
                "state": state,
                "interval": interval,
                "start_time": start_time,
                "end_time": end_time,
                "fudge": fudge,
                "max_injection": max_injection,
                "expiration_delay": expiration_delay,
                "big_first": big_first,
                "rule_lifetime": rule_lifetime,
                "comments": comments,
                "dry_run": dry_run,
                "vo": vo,
            }
        ],
        session=session,
    )


@transactional_session
def add_injection_plans(
    plans: "Sequence[Mapping[str, Any]]", *, session: "Session"
) -> None:
    """
    Bulk add injection plans in the database.

    :param plans: The list of injection plans to add.
    :param session: The database session in use.
    """
    try:
        new_plans = [
            models.LoadInjectionPlans(
                plan_id=plan["plan_id"],
                src_rse_id=plan["src_rse_id"],
                dest_rse_id=plan["dest_rse_id"],
                vo=plan.get("vo"),
                inject_rate=plan["inject_rate"],
                state=plan["state"],
                interval=plan["interval"],
                start_time=plan["start_time"],
                end_time=plan["end_time"],
                fudge=plan["fudge"],
                max_injection=plan["max_injection"],
                expiration_delay=plan["expiration_delay"],
                big_first=plan["big_first"],
                rule_lifetime=plan["rule_lifetime"],
                comments=plan["comments"],
                dry_run=plan["dry_run"],
            )
            for plan in plans
        ]
        session.add_all(new_plans)
        session.flush()
    except IntegrityError as error:
        raise exception.DuplicateLoadInjectionPlan(error.args)


@transactional_session
def add_injection_plan_history(
    plan_id: str,
    src_rse_id: str,
    dest_rse_id: str,
    inject_rate: int,
    start_time: datetime.datetime,
    end_time: datetime.datetime,
    comments: Optional[str],
    interval: int,
    fudge: float,
    max_injection: float,
    expiration_delay: int,
    rule_lifetime: int,
    big_first: bool,
    dry_run: bool,
    state: constants.LoadInjectionState,
    vo: Optional[str] = None,
    *,
    session: "Session"
) -> None:
    """
    Add a history injection plan in the database.

    :param src_rse_id: The src RSE id.
    :param dest_rse_id: The dest RSE id.
    :param inject_rate: The injection rate.
    :param interval: The time interval between eche time injection.
    :param start_time: The start time of the injection plan.
    :param end_time: The end time of the injection plan.
    :param fudge: The fudge factor for the injection plan.
    :param max_injection: The maximum injection rate.
    :param expiration_delay: The expiration delay for the injection plan.
    :param big_first: The big first flag for the injection plan.
    :param rule_lifetime: The rule lifetime for the injection plan.
    :param comments: The comments for the injection plan.
    :param dry_run: The dry_run flag for the injection plan.
    :param session: The database session in use.
    """
    add_injection_plans_history(
        [
            {
                "plan_id": plan_id,
                "src_rse_id": src_rse_id,
                "dest_rse_id": dest_rse_id,
                "inject_rate": inject_rate,
                "state": state,
                "interval": interval,
                "start_time": start_time,
                "end_time": end_time,
                "fudge": fudge,
                "max_injection": max_injection,
                "expiration_delay": expiration_delay,
                "big_first": big_first,
                "rule_lifetime": rule_lifetime,
                "comments": comments,
                "dry_run": dry_run,
                "vo": vo,
            }
        ],
        session=session,
    )


@transactional_session
def add_injection_plans_history(
    plans: "Sequence[Mapping[str, Any]]", *, session: "Session"
) -> None:
    """
    Bulk add history injection plans in the database.

    :param _plans: The list of injection plans to add.
    :param session: The database session in use.
    """
    try:
        new_plans = [
            models.LoadInjectionPlansHistory(
                plan_id=plan["plan_id"],
                src_rse_id=plan["src_rse_id"],
                dest_rse_id=plan["dest_rse_id"],
                vo=plan.get("vo"),
                inject_rate=plan["inject_rate"],
                state=plan["state"],
                interval=plan["interval"],
                start_time=plan["start_time"],
                end_time=plan["end_time"],
                fudge=plan["fudge"],
                max_injection=plan["max_injection"],
                expiration_delay=plan["expiration_delay"],
                big_first=plan["big_first"],
                rule_lifetime=plan["rule_lifetime"],
                comments=plan["comments"],
                dry_run=plan["dry_run"],
            )
            for plan in plans
        ]
        session.add_all(new_plans)
        session.flush()
    except IntegrityError as error:
        raise exception.DuplicateLoadInjectionPlan(error.args)


@read_session
def get_injection_plan_history(
    src_rse_id: str, dest_rse_id: str, *, session: "Session"
) -> "Mapping[str,Any]":
    """
    Get one injection plan history from the database.

    :param src_rse_id: The source RSE ID.
    :param dest_rse_id: The destination RSE ID.
    :param session: The database session in use.
    :returns: A injection history plan.
    """
    try:
        stmt = select(models.LoadInjectionPlansHistory).where(
            and_(
                models.LoadInjectionPlansHistory.src_rse_id == src_rse_id,
                models.LoadInjectionPlansHistory.dest_rse_id == dest_rse_id,
            )
        )
        query_result = session.execute(stmt).scalar_one()
        return query_result.to_dict()
    except NoResultFound as error:
        raise exception.NoLoadInjectionPlanFound(error.args)


@read_session
def get_injection_plans_history(*, session: "Session") -> "Sequence[Mapping[str, Any]]":
    """
    Get injection history plans from the database.

    :param session: The database session in use.
    :returns: A list of injection history plans.
    """
    stmt = select(models.LoadInjectionPlansHistory)
    query_result = session.execute(stmt).scalars().all()
    return [plan.to_dict() for plan in query_result]


@transactional_session
def delete_injection_plan(
    src_rse_id: str,
    dest_rse_id: str,
    *,
    vo: "Optional[str]" = None,
    session: "Session",
) -> None:
    """
    Delete an injection plan from the database.

    :param src_rse_id: The source RSE ID.
    :param dest_rse_id: The destination RSE ID.
    :param vo: Optional VO scope. When provided, only deletes plans in this VO.
    :param session: The database session in use.
    """
    delete_injection_plans(
        [{"src_rse_id": src_rse_id, "dest_rse_id": dest_rse_id}],
        vo=vo,
        session=session,
    )


@transactional_session
def delete_injection_plans(
    plans: list[dict[str, Any]],
    *,
    vo: "Optional[str]" = None,
    session: "Session",
) -> None:
    """
    Bulk delete injection plans from the database.
    Archives to history first via a single bulk SELECT + INSERT.
    Rejects deletion of INJECTING plans — they must be killed first.

    :param plans: The list of injection plans to delete.
    :param vo: Optional VO scope. When provided, only deletes plans in this VO.
    :param session: The database session in use.
    """
    if not plans:
        return

    from sqlalchemy import or_

    pair_filters = [
        and_(
            models.LoadInjectionPlans.src_rse_id == p["src_rse_id"],
            models.LoadInjectionPlans.dest_rse_id == p["dest_rse_id"],
        )
        for p in plans
    ]
    if vo is not None:
        pair_filters = [
            and_(f, models.LoadInjectionPlans.vo == vo) for f in pair_filters
        ]

    # Bulk fetch all plans to archive
    stmt = select(models.LoadInjectionPlans).where(or_(*pair_filters))
    results = session.execute(stmt).scalars().all()

    if not results:
        raise exception.NoLoadInjectionPlanFound(
            "No load injection plans found for the given RSE pairs."
        )

    # Reject deletion of INJECTING plans — they have active submitter threads.
    injecting = [r for r in results if r.state == constants.LoadInjectionState.INJECTING]
    if injecting:
        src_rse_ids = {r.src_rse_id for r in injecting}
        dest_rse_ids = {r.dest_rse_id for r in injecting}
        raise exception.InvalidObject(
            "Cannot delete plans in INJECTING state. Kill them first. "
            "Affected src RSEs: %s, dest RSEs: %s"
            % (src_rse_ids, dest_rse_ids)
        )

    if results:
        history_entries = [r.to_dict() for r in results]
        add_injection_plans_history(history_entries, session=session)

    delete_stmt = delete(models.LoadInjectionPlans).where(or_(*pair_filters))
    session.execute(delete_stmt)


@transactional_session
def update_injection_plan_state(
    src_rse_id: str, dest_rse_id: str, new_state: str, *, session: "Session"
) -> None:
    """
    Update the state of an injection plan.

    :param src_rse_id: The source RSE ID.
    :param dest_rse_id: The destination RSE ID.
    :param new_state: The new state of the injection plan.
    :param session: The database session in use.
    """
    stmt = (
        update(models.LoadInjectionPlans)
        .where(
            and_(
                models.LoadInjectionPlans.dest_rse_id == dest_rse_id,
                models.LoadInjectionPlans.src_rse_id == src_rse_id,
            )
        )
        .values(state=new_state)
    )
    result = session.execute(stmt)
    if result.rowcount == 0:
        raise exception.NoLoadInjectionPlanFound(
            "No load injection plan found for src_rse_id=%s dest_rse_id=%s"
            % (src_rse_id, dest_rse_id)
        )


@read_session
def get_injection_plan_state(
    src_rse_id: str, dest_rse_id: str, *, session: "Session"
) -> "Optional[str]":
    """
    Get the state of an injection plan.

    :param src_rse_id: The source RSE ID.
    :param dest_rse_id: The destination RSE ID.
    :param session: The database session in use.
    :returns: The state of the injection plan.
    """
    try:
        stmt = select(models.LoadInjectionPlans).where(
            and_(
                models.LoadInjectionPlans.dest_rse_id == dest_rse_id,
                models.LoadInjectionPlans.src_rse_id == src_rse_id,
            )
        )
        query_result = session.execute(stmt).scalar_one_or_none()
    except NoResultFound as error:
        raise exception.NoLoadInjectionPlanFound(error.args)

    return query_result.to_dict()["state"] if query_result else None


@transactional_session
def try_claim_plan(
    src_rse_id: str, dest_rse_id: str, *, session: "Session"
) -> bool:
    """
    Atomically claim a WAITING plan by transitioning it to INJECTING.
    Uses a conditional UPDATE with a rowcount check to ensure only one
    worker wins the race when multiple submitter instances compete.

    :param src_rse_id: The source RSE ID.
    :param dest_rse_id: The destination RSE ID.
    :param session: The database session in use.
    :returns: True if the plan was successfully claimed, False otherwise.
    """
    stmt = (
        update(models.LoadInjectionPlans)
        .where(
            and_(
                models.LoadInjectionPlans.src_rse_id == src_rse_id,
                models.LoadInjectionPlans.dest_rse_id == dest_rse_id,
                models.LoadInjectionPlans.state == constants.LoadInjectionState.WAITING,
            )
        )
        .values(state=constants.LoadInjectionState.INJECTING)
    )
    result = session.execute(stmt)
    return result.rowcount == 1


@transactional_session
def heartbeat_injecting_plan(
    src_rse_id: str, dest_rse_id: str, *, session: "Session"
) -> bool:
    """
    Refresh updated_at on an INJECTING plan. Uses a conditional UPDATE
    so a KILL signal written by the gateway is never overwritten.

    :returns: True if the heartbeat succeeded (plan still INJECTING),
              False if the plan was KILLED or otherwise changed.
    """
    stmt = (
        update(models.LoadInjectionPlans)
        .where(
            and_(
                models.LoadInjectionPlans.src_rse_id == src_rse_id,
                models.LoadInjectionPlans.dest_rse_id == dest_rse_id,
                models.LoadInjectionPlans.state == constants.LoadInjectionState.INJECTING,
            )
        )
        .values(state=constants.LoadInjectionState.INJECTING)
    )
    result = session.execute(stmt)
    return result.rowcount == 1


@transactional_session
def try_recover_zombie_plan(
    src_rse_id: str, dest_rse_id: str, deadline: datetime.datetime, *, session: "Session"
) -> bool:
    """
    Atomically reset a stale INJECTING plan back to WAITING.
    Only succeeds if the plan is still INJECTING AND its updated_at
    is older than the deadline — preventing TOCTOU races.

    :param src_rse_id: The source RSE ID.
    :param dest_rse_id: The destination RSE ID.
    :param deadline: Timestamp threshold. Plans updated before this are stale.
    :param session: The database session in use.
    :returns: True if the plan was recovered, False otherwise.
    """
    stmt = (
        update(models.LoadInjectionPlans)
        .where(
            and_(
                models.LoadInjectionPlans.src_rse_id == src_rse_id,
                models.LoadInjectionPlans.dest_rse_id == dest_rse_id,
                models.LoadInjectionPlans.state == constants.LoadInjectionState.INJECTING,
                models.LoadInjectionPlans.updated_at < deadline,
            )
        )
        .values(state=constants.LoadInjectionState.WAITING)
    )
    result = session.execute(stmt)
    return result.rowcount == 1
