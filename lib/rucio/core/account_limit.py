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

from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.sql import func
from sqlalchemy.sql.expression import and_, or_

from rucio.core.account import get_all_rse_usages_per_account
from rucio.core.rse import get_rse_name
from rucio.core.rse_expression_parser import parse_expression
from rucio.db.sqla import models
from rucio.db.sqla.session import read_session, transactional_session


@read_session
def get_rse_account_usage(rse_id, session=None):
    """
    Returns the account limit and usage for all for all accounts on a RSE.

    :param rse_id:   The id of the RSE.
    :param session:  Database session in use.
    :return:         List of dictionaries.
    """
    result = []
    query = session.query(models.AccountUsage.account, models.AccountUsage.files, models.AccountUsage.bytes, models.AccountLimit.bytes, models.RSE.rse)
    query = query.filter(models.RSE.id == models.AccountUsage.rse_id)
    query = query.outerjoin(models.AccountLimit, and_(models.AccountUsage.account == models.AccountLimit.account, models.AccountUsage.rse_id == models.AccountLimit.rse_id)).filter(models.AccountUsage.rse_id == rse_id)
    account_limits_tmp = query.all()
    for row in account_limits_tmp:
        result.append({'rse_id': rse_id, 'rse': row[4], 'account': row[0], 'used_files': row[1], 'used_bytes': row[2], 'quota_bytes': row[3]})
    return result


@read_session
def get_global_account_limits(account=None, session=None):
    """
    Returns the global account limits for the account.

    :param account:  Account to check the limit for.
    :param session:  Database session in use.
    :return:         Dict {'MOCK': {'resolved_rses': ['MOCK'], 'limit': 10, 'resolved_rse_ids': [123]}}.
    """
    if account:
        global_account_limits = session.query(models.AccountGlobalLimit).filter_by(account=account).all()
    else:
        global_account_limits = session.query(models.AccountGlobalLimit).all()

    resolved_global_account_limits = {}
    for limit in global_account_limits:
        if account:
            resolved_rses = parse_expression(limit['rse_expression'], filter_={'vo': account.vo}, session=session)
        else:
            resolved_rses = parse_expression(limit['rse_expression'], session=session)
        limit_in_bytes = limit['bytes']
        if limit_in_bytes == -1:
            limit_in_bytes = float('inf')
        resolved_global_account_limits[limit['rse_expression']] = {
            'resolved_rses': [resolved_rse['rse'] for resolved_rse in resolved_rses],
            'resolved_rse_ids': [resolved_rse['id'] for resolved_rse in resolved_rses],
            'limit': limit_in_bytes
        }
    return resolved_global_account_limits


@read_session
def get_global_account_limit(account, rse_expression, session=None):
    """
    Returns the global account limit for the account on the rse expression.

    :param account:         Account to check the limit for.
    :param rse_expression:  RSE expression to check the limit for.
    :param session:         Database session in use.
    :return:                Limit in Bytes.
    """
    try:
        global_account_limit = session.query(models.AccountGlobalLimit).filter_by(account=account, rse_expression=rse_expression).one()
        if global_account_limit.bytes == -1:
            return float("inf")
        else:
            return global_account_limit.bytes
    except NoResultFound:
        return None


@read_session
def get_local_account_limit(account, rse_id, session=None):
    """
    Returns the account limit for the account on the rse.

    :param account:  Account to check the limit for.
    :param rse_id:   RSE id to check the limit for.
    :param session:  Database session in use.
    :return:         Limit in Bytes.
    """
    try:
        account_limit = session.query(models.AccountLimit).filter(models.AccountLimit.account == account,
                                                                  models.AccountLimit.rse_id == rse_id).one()
        if account_limit.bytes == -1:
            return float("inf")
        else:
            return account_limit.bytes
    except NoResultFound:
        return None


@read_session
def get_local_account_limits(account, rse_ids=None, session=None):
    """
    Returns the account limits for the account on the list of rses.

    :param account:  Account to check the limit for.
    :param rse_ids:  List of RSE ids to check the limit for.
    :param session:  Database session in use.
    :return:         Dictionary {'rse_id': bytes, ...}.
    """

    account_limits = {}
    if rse_ids:
        rse_id_clauses = []
        for rse_id in rse_ids:
            rse_id_clauses.append(and_(models.AccountLimit.rse_id == rse_id, models.AccountLimit.account == account))
        rse_id_clause_chunks = [rse_id_clauses[x:x + 10] for x in range(0, len(rse_id_clauses), 10)]
        for rse_id_chunk in rse_id_clause_chunks:
            tmp_limits = session.query(models.AccountLimit).filter(or_(*rse_id_chunk)).all()
            for limit in tmp_limits:
                if limit.bytes == -1:
                    account_limits[limit.rse_id] = float("inf")
                else:
                    account_limits[limit.rse_id] = limit.bytes
    else:
        account_limits_tmp = session.query(models.AccountLimit).filter(models.AccountLimit.account == account).all()
        for limit in account_limits_tmp:
            if limit.bytes == -1:
                account_limits[limit.rse_id] = float("inf")
            else:
                account_limits[limit.rse_id] = limit.bytes
    return account_limits


@transactional_session
def set_local_account_limit(account, rse_id, bytes_, session=None):
    """
    Returns the limits for the account on the rse.

    :param account:  Account to check the limit for.
    :param rse_id:   RSE id to check the limit for.
    :param bytes_:    The limit value, in bytes, to set.
    :param session:  Database session in use.
    """
    try:
        account_limit = session.query(models.AccountLimit).filter(models.AccountLimit.account == account,
                                                                  models.AccountLimit.rse_id == rse_id).one()
        account_limit.bytes = bytes_
    except NoResultFound:
        models.AccountLimit(account=account, rse_id=rse_id, bytes=bytes_).save(session=session)


@transactional_session
def set_global_account_limit(account, rse_expression, bytes_, session=None):
    """
    Sets the global limit for the account on a RSE expression.

    :param account:         Account to check the limit for.
    :param rse_expression:  RSE expression to check the limit for.
    :param bytes_:           The limit value, in bytes, to set.
    :param session:         Database session in use.
    """
    try:
        account_limit = session.query(models.AccountGlobalLimit).filter(models.AccountGlobalLimit.account == account,
                                                                        models.AccountGlobalLimit.rse_expression == rse_expression).one()
        account_limit.bytes = bytes_
    except NoResultFound:
        models.AccountGlobalLimit(account=account, rse_expression=rse_expression, bytes=bytes_).save(session=session)


@transactional_session
def delete_local_account_limit(account, rse_id, session=None):
    """
    Deletes a local account limit.

    :param account:  Account to delete the limit for.
    :param rse_id:   RSE id to delete the limit for.
    :param session:  Database session in use.
    :returns:        True if something was deleted; False otherwise.
    """
    try:
        session.query(models.AccountLimit).filter(models.AccountLimit.account == account,
                                                  models.AccountLimit.rse_id == rse_id).one().delete(session=session)
        return True
    except NoResultFound:
        return False


@transactional_session
def delete_global_account_limit(account, rse_expression, session=None):
    """
    Deletes a global account limit.

    :param account:         Account to delete the limit for.
    :param rse_expression:  RSE expression to delete the limit for.
    :param session:         Database session in use.
    :returns:               True if something was deleted; False otherwise.
    """
    try:
        session.query(models.AccountGlobalLimit).filter(models.AccountGlobalLimit.account == account,
                                                        models.AccountGlobalLimit.rse_expression == rse_expression).one().delete(session=session)
        return True
    except NoResultFound:
        return False


@transactional_session
def get_local_account_usage(account, rse_id=None, session=None):
    """
    Read the account usage and connect it with (if available) the account limits of the account.

    :param account:  The account to read.
    :param rse_id:   The rse_id to read (If none, get all).
    :param session:  Database session in use.

    :returns:        List of dicts {'rse_id', 'rse', 'bytes', 'files', 'bytes_limit', 'bytes_remaining'}
    """

    if not rse_id:
        # All RSESs
        limits = get_local_account_limits(account=account, session=session)
        counters = session.query(models.AccountUsage).filter_by(account=account).all()
    else:
        # One RSE
        limits = get_local_account_limits(account=account, rse_ids=[rse_id], session=session)
        counters = session.query(models.AccountUsage).filter_by(account=account, rse_id=rse_id).all()
    result_list = []

    for counter in counters:
        if counter.bytes > 0 or counter.files > 0 or rse_id in limits.keys():
            result_list.append({'rse_id': counter.rse_id, 'rse': get_rse_name(rse_id=counter.rse_id, session=session),
                                'bytes': counter.bytes, 'files': counter.files,
                                'bytes_limit': limits.get(counter.rse_id, 0),
                                'bytes_remaining': limits.get(counter.rse_id, 0) - counter.bytes})
    return result_list


@transactional_session
def get_global_account_usage(account, rse_expression=None, session=None):
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
        limits = get_global_account_limits(account=account, session=session)
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
        usage = session.query(func.sum(models.AccountUsage.bytes), func.sum(models.AccountUsage.files))\
                       .filter(models.AccountUsage.account == account, models.AccountUsage.rse_id.in_(resolved_rses))\
                       .group_by(models.AccountUsage.account).first()
        result_list.append({'rse_expression': rse_expression,
                            'bytes': usage[0], 'files': usage[1],
                            'bytes_limit': limit,
                            'bytes_remaining': limit - usage[0]})
    return result_list
