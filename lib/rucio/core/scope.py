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

from re import match
from traceback import format_exc
from typing import TYPE_CHECKING

from sqlalchemy.exc import IntegrityError

from rucio.common.exception import AccountNotFound, Duplicate, RucioException, VONotFound
from rucio.core.vo import vo_exists
from rucio.db.sqla import models
from rucio.db.sqla.constants import AccountStatus, ScopeStatus
from rucio.db.sqla.session import read_session, transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


@transactional_session
def add_scope(scope, account, *, session: "Session"):
    """ add a scope for the given account name.

    :param scope: the name for the new scope.
    :param account: the account to add the scope to.
    :param session: The database session in use.
    """

    if not vo_exists(vo=scope.vo, session=session):
        raise VONotFound('VO {} not found'.format(scope.vo))

    result = session.query(models.Account).filter_by(account=account, status=AccountStatus.ACTIVE).first()
    if result is None:
        raise AccountNotFound('Account ID \'%s\' does not exist' % account)

    new_scope = models.Scope(scope=scope, account=account, status=ScopeStatus.OPEN)
    try:
        new_scope.save(session=session)
    except IntegrityError as e:
        if match('.*IntegrityError.*ORA-00001: unique constraint.*SCOPES_PK.*violated.*', e.args[0]) \
                or match('.*IntegrityError.*Duplicate entry.*for key.*', e.args[0]) \
                or match('.*IntegrityError.*UNIQUE constraint failed: scopes.scope.*', e.args[0]) \
                or match('.*IntegrityError.*duplicate key value violates unique constraint.*', e.args[0]) \
                or match('.*UniqueViolation.*duplicate key value violates unique constraint.*', e.args[0]) \
                or match('.*IntegrityError.*columns? .*not unique.*', e.args[0]):
            raise Duplicate('Scope \'%s\' already exists!' % scope)
        else:
            raise RucioException(e)
    except:
        raise RucioException(str(format_exc()))


@read_session
def bulk_add_scopes(scopes, account, skipExisting=False, *, session: "Session"):
    """ add a group of scopes, this call should not be exposed to users.

    :param scopes: a list of scopes to be added.
    :param account: the account associated to the scopes.
    :param session: The database session in use.
    """

    for scope in scopes:
        try:
            add_scope(scope, account, session=session)
        except Duplicate:
            if not skipExisting:
                raise


@read_session
def list_scopes(filter_={}, *, session: "Session"):
    """
    Lists all scopes.
    :param filter_: Dictionary of attributes by which the input data should be filtered
    :param session: The database session in use.

    :returns: A list containing all scopes.
    """
    scope_list = []
    query = session.query(models.Scope).filter(models.Scope.status != ScopeStatus.DELETED)
    for filter_type in filter_:
        if filter_type == 'scope':
            if '*' in filter_['scope'].internal:
                scope_str = filter_['scope'].internal.replace('*', '%')
                query = query.filter(models.Scope.scope.like(scope_str))
            else:
                query = query.filter_by(scope=filter_['scope'])

    for s in query:
        scope_list.append(s.scope)
    return scope_list


@read_session
def get_scopes(account, *, session: "Session"):
    """ get all scopes defined for an account.

    :param account: the account name to list the scopes of.
    :param session: The database session in use.

    :returns: a list of all scope names for this account.
    """

    result = session.query(models.Account).filter_by(account=account).first()

    if result is None:
        raise AccountNotFound('Account ID \'%s\' does not exist' % account)

    scope_list = []

    for s in session.query(models.Scope).filter_by(account=account).filter(models.Scope.status != ScopeStatus.DELETED):
        scope_list.append(s.scope)

    return scope_list


@read_session
def check_scope(scope_to_check, *, session: "Session"):
    """ check to see if scope exists.

    :param scope: the scope to check.
    :param session: The database session in use.

    :returns: True or false
    """

    return True if session.query(models.Scope).filter_by(scope=scope_to_check).first() else False


@read_session
def is_scope_owner(scope, account, *, session: "Session"):
    """ check to see if account owns the scope.

    :param scope: the scope to check.
    :param account: the account to check.
    :param session: The database session in use.

    :returns: True or false
    """
    return True if session.query(models.Scope).filter_by(scope=scope, account=account).first() else False
