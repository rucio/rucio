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

from typing import TYPE_CHECKING, Optional, Union

from sqlalchemy.exc import NoResultFound
from sqlalchemy.sql import func, literal, select
from sqlalchemy.sql.expression import and_, or_

from rucio.core.account import get_all_rse_usages_per_account
from rucio.core.rse import get_rse_name
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.sqla import models
from rucio.db.sqla.session import read_session, transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from rucio.common.types import InternalAccount, RSEAccountUsageDict, RSEGlobalAccountUsageDict, RSELocalAccountUsageDict, RSEResolvedGlobalAccountLimitDict


@read_session
def get_rse_account_usage(rse_id: str, *, session: "Session") -> list["RSEAccountUsageDict"]:
    """
    Returns the account limit and usage for all accounts on a RSE.

    :param rse_id:   The id of the RSE.
    :param session:  Database session in use.
    :return:         List of dictionaries.
    """
    result = []
    stmt = select(
        models.RSE.id.label('rse_id'),
        models.RSE.vo.label('rse_vo'),
        models.RSE.rse.label('rse_name'),
        models.Account.account,
        models.AccountUsage.files.label('used_files'),
        models.AccountUsage.bytes.label('used_bytes'),
        models.AccountLimit.bytes.label('quota_bytes'),
    ).where(
        models.RSE.id == rse_id
    ).join_from(
        models.RSE,
        models.Account,
        or_(
            and_(
                models.RSE.vo == 'def',
                models.Account.account.notlike('%@%')
            ),
            and_(
                models.RSE.vo != 'def',
                models.Account.account.like(literal('%@') + models.RSE.vo)
            )
        )
    ).outerjoin(
        models.AccountUsage,
        and_(
            models.AccountUsage.account == models.Account.account,
            models.AccountUsage.rse_id == models.RSE.id
        )
    ).outerjoin(
        models.AccountLimit,
        and_(
            models.AccountLimit.account == models.Account.account,
            models.AccountLimit.rse_id == models.RSE.id
        )
    )
    for row in session.execute(stmt):
        if row.rse_vo != row.account.vo:
            continue
        result.append({
            'rse_id': row.rse_id,
            'rse': row.rse_name,
            'account': row.account,
            'used_files': row.used_files if row.used_files is not None else 0,
            'used_bytes': row.used_bytes if row.used_bytes is not None else 0,
            'quota_bytes': row.quota_bytes
        })
    return result


@read_session
def get_global_account_limit(account: Optional["InternalAccount"] = None, rse_expression: Optional[str] = None, *,
                             session: "Session") -> Union[int, float, dict[str, "RSEResolvedGlobalAccountLimitDict"], None]:
    """
    Returns the global account limit for the given account and RSE expression, or all limits if no specific expression is provided.

    :param account:         Account to check the limit for (optional for fetching all accounts).
    :param rse_expression:  Specific RSE expression to check the limit for (optional for fetching all limits).
    :param session:         Database session in use.
    :return:                Limit in Bytes for a single RSE expression, or a dictionary of all limits {'MOCK': {'resolved_rses': ['MOCK'], 'limit': 10, 'resolved_rse_ids': [123]}}.
    """
    if rse_expression:
        # Fetch limit for a single RSE expression
        try:
            stmt = select(models.AccountGlobalLimit).where(
                and_(models.AccountGlobalLimit.account == account,
                     models.AccountGlobalLimit.rse_expression == rse_expression)
            )
            global_account_limit = session.execute(stmt).scalar_one()
            return float("inf") if global_account_limit.bytes == -1 else global_account_limit.bytes
        except NoResultFound:
            return None

    # Fetch all global limits for the account (or all accounts if no account specified)
    stmt = select(models.AccountGlobalLimit)
    if account:
        stmt = stmt.where(models.AccountGlobalLimit.account == account)
    global_account_limits = session.execute(stmt).scalars().all()

    resolved_global_account_limits = {}
    for limit in global_account_limits:
        if account:
            resolved_rses = parse_expression(limit['rse_expression'], filter_={'vo': account.vo}, session=session)
        else:
            resolved_rses = parse_expression(limit['rse_expression'], session=session)
        limit_in_bytes = float('inf') if limit['bytes'] == -1 else limit['bytes']
        resolved_global_account_limits[limit['rse_expression']] = {
            'resolved_rses': [resolved_rse['rse'] for resolved_rse in resolved_rses],
            'resolved_rse_ids': [resolved_rse['id'] for resolved_rse in resolved_rses],
            'limit': limit_in_bytes
        }
    return resolved_global_account_limits


@read_session
def get_local_account_limit(account: "InternalAccount", rse_ids: Union[str, list[str], None] = None, *, session: "Session") -> Union[int, float, dict[str, int], None]:
    """
    Returns the local account limit for a given RSE or list of RSEs.

    :param account:  Account to check the limit for.
    :param rse_ids:  Single RSE id or a list of RSE ids to check the limit for.
    :param session:  Database session in use.
    :return:         Limit in Bytes (int/float) for a single RSE or
                     Dictionary {'rse_id': bytes, ...} for multiple RSEs.
    """
    if isinstance(rse_ids, str):  # Single RSE case
        try:
            stmt = select(models.AccountLimit).where(
                and_(models.AccountLimit.account == account, models.AccountLimit.rse_id == rse_ids)
            )
            account_limit = session.execute(stmt).scalar_one()
            return float("inf") if account_limit.bytes == -1 else account_limit.bytes
        except NoResultFound:
            return None

    # Multiple RSE case or no RSE specified
    account_limits = {}

    # If rse_ids is a list of RSEs
    if isinstance(rse_ids, list) and rse_ids:
        rse_id_clauses = []
        for rse_id in rse_ids:
            rse_id_clauses.append(and_(models.AccountLimit.rse_id == rse_id,
                                       models.AccountLimit.account == account))
        rse_id_clause_chunks = [rse_id_clauses[x:x + 10] for x in range(0, len(rse_id_clauses), 10)]
        for rse_id_chunk in rse_id_clause_chunks:
            stmt = select(
                models.AccountLimit
            ).where(
                or_(*rse_id_chunk)
            )
            tmp_limits = session.execute(stmt).scalars().all()
            for limit in tmp_limits:
                if limit.bytes == -1:
                    account_limits[limit.rse_id] = float("inf")
                else:
                    account_limits[limit.rse_id] = limit.bytes
    else:
        stmt = select(
            models.AccountLimit
        ).where(
            models.AccountLimit.account == account
        )
        account_limits_tmp = session.execute(stmt).scalars().all()
        for limit in account_limits_tmp:
            if limit.bytes == -1:
                account_limits[limit.rse_id] = float("inf")
            else:
                account_limits[limit.rse_id] = limit.bytes
    return account_limits


@transactional_session
def set_local_account_limit(account: "InternalAccount", rse_id: str, bytes_: int, *, session: "Session") -> None:
    """
    Returns the limits for the account on the rse.

    :param account:  Account to check the limit for.
    :param rse_id:   RSE id to check the limit for.
    :param bytes_:    The limit value, in bytes, to set.
    :param session:  Database session in use.
    """
    try:
        stmt = select(
            models.AccountLimit
        ).where(
            and_(models.AccountLimit.account == account,
                 models.AccountLimit.rse_id == rse_id)
        )
        account_limit = session.execute(stmt).scalar_one()
        account_limit.bytes = bytes_
    except NoResultFound:
        models.AccountLimit(account=account, rse_id=rse_id, bytes=bytes_).save(session=session)


@transactional_session
def set_global_account_limit(account: "InternalAccount", rse_expression: str, bytes_: int, *, session: "Session") -> None:
    """
    Sets the global limit for the account on a RSE expression.

    :param account:         Account to check the limit for.
    :param rse_expression:  RSE expression to check the limit for.
    :param bytes_:           The limit value, in bytes, to set.
    :param session:         Database session in use.
    """
    try:
        stmt = select(
            models.AccountGlobalLimit
        ).where(
            and_(models.AccountGlobalLimit.account == account,
                 models.AccountGlobalLimit.rse_expression == rse_expression)
        )
        account_limit = session.execute(stmt).scalar_one()
        account_limit.bytes = bytes_
    except NoResultFound:
        models.AccountGlobalLimit(account=account, rse_expression=rse_expression, bytes=bytes_).save(session=session)


@transactional_session
def delete_local_account_limit(account: "InternalAccount", rse_id: str, *, session: "Session") -> bool:
    """
    Deletes a local account limit.

    :param account:  Account to delete the limit for.
    :param rse_id:   RSE id to delete the limit for.
    :param session:  Database session in use.
    :returns:        True if something was deleted; False otherwise.
    """
    try:
        stmt = select(
            models.AccountLimit
        ).where(
            and_(models.AccountLimit.account == account,
                 models.AccountLimit.rse_id == rse_id)
        )
        result = session.execute(stmt).scalar_one()
        result.delete(session=session)
        return True
    except NoResultFound:
        return False


@transactional_session
def delete_global_account_limit(account: "InternalAccount", rse_expression: str, *, session: "Session") -> bool:
    """
    Deletes a global account limit.

    :param account:         Account to delete the limit for.
    :param rse_expression:  RSE expression to delete the limit for.
    :param session:         Database session in use.
    :returns:               True if something was deleted; False otherwise.
    """
    try:
        stmt = select(
            models.AccountGlobalLimit
        ).where(
            and_(models.AccountGlobalLimit.account == account,
                 models.AccountGlobalLimit.rse_expression == rse_expression)
        )
        result = session.execute(stmt).scalar_one()
        result.delete(session=session)
        return True
    except NoResultFound:
        return False


@transactional_session
def get_local_account_usage(account: "InternalAccount", rse_id: Optional[str] = None, *, session: "Session") -> list["RSELocalAccountUsageDict"]:
    """
    Read the account usage and connect it with (if available) the account limits of the account.

    :param account:  The account to read.
    :param rse_id:   The rse_id to read (If none, get all).
    :param session:  Database session in use.

    :returns:        List of dicts {'rse_id', 'rse', 'bytes', 'files', 'bytes_limit', 'bytes_remaining'}
    """

    stmt = select(
        models.AccountUsage
    ).where(
        models.AccountUsage.account == account
    )
    if not rse_id:
        # All RSESs
        limits = get_local_account_limit(account=account, rse_ids=None, session=session)
        counters = {c.rse_id: c for c in session.execute(stmt).scalars().all()}
    else:
        # One RSE
        stmt.where(
            models.AccountUsage.rse_id == rse_id
        )
        limits = get_local_account_limit(account=account, rse_ids=[rse_id], session=session)
        counters = {c.rse_id: c for c in session.execute(stmt).scalars().all()}
    result_list = []

    for rse_id in set(limits).union(counters):
        counter = counters.get(rse_id)
        if counter:
            counter_files = counter.files
            counter_bytes = counter.bytes
        else:
            counter_files = 0
            counter_bytes = 0

        if counter_bytes > 0 or counter_files > 0 or rse_id in limits.keys():
            result_list.append({
                'rse_id': rse_id,
                'rse': get_rse_name(rse_id=rse_id, session=session),
                'bytes': counter_bytes,
                'files': counter_files,
                'bytes_limit': limits.get(rse_id, 0),
                'bytes_remaining': limits.get(rse_id, 0) - counter_bytes,
            })
    return result_list


@transactional_session
def get_global_account_usage(account: "InternalAccount", rse_expression: Optional[str] = None, *, session: "Session") -> list["RSEGlobalAccountUsageDict"]:
    """
    Read the account usage and connect it with the global account limits of the account.

    :param account:          The account to read.
    :param rse_expression:   The RSE expression (If none, get all).
    :param session:          Database session in use.

    :returns:                List of dicts {'rse_expression', 'bytes', 'files' 'bytes_limit', 'bytes_remaining'}
    """
    result_list = []
    if not rse_expression:
        # All RSE Expressions
        limits = get_global_account_limit(account=account, session=session)
        all_rse_usages = {usage['rse_id']: (usage['bytes'], usage['files']) for usage in get_all_rse_usages_per_account(account=account, session=session)}
        for rse_expression, limit in limits.items():
            usage = 0
            files = 0
            for rse in limit['resolved_rse_ids']:
                usage += all_rse_usages.get(rse, [0])[0]
                files += all_rse_usages.get(rse, [0, 0])[1]
            result_list.append({'rse_expression': rse_expression,
                                'bytes': usage, 'files': files,
                                'bytes_limit': limit['limit'],
                                'bytes_remaining': limit['limit'] - usage})
    else:
        # One RSE Expression
        limit = get_global_account_limit(account=account, rse_expression=rse_expression, session=session)
        vo = account.vo
        resolved_rses = [resolved_rse['id'] for resolved_rse in parse_expression(rse_expression, filter_={'vo': vo}, session=session)]
        stmt = select(
            func.sum(models.AccountUsage.bytes),
            func.sum(models.AccountUsage.files)
        ).where(
            and_(models.AccountUsage.account == account,
                 models.AccountUsage.rse_id.in_(resolved_rses))
        ).group_by(
            models.AccountUsage.account
        )
        usage = session.execute(stmt).first()
        if limit is None:
            limit = 0
        if usage is None:
            usage = 0, 0
        result_list.append({
            'rse_expression': rse_expression,
            'bytes': usage[0], 'files': usage[1],
            'bytes_limit': limit,
            'bytes_remaining': limit - usage[0]
        })
    return result_list
