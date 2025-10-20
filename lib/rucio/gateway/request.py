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
Interface for the requests abstraction layer
"""

from typing import TYPE_CHECKING, Any, Optional

from rucio.common import exception
from rucio.common.constants import DEFAULT_VO, TransferLimitDirection
from rucio.common.types import InternalScope
from rucio.common.utils import gateway_update_return_dict
from rucio.core import request
from rucio.core.rse import get_rse_id
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session
from rucio.gateway import permission

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence

    from rucio.db.sqla.constants import RequestState


def get_request_by_did(
    scope: str,
    name: str,
    rse: str,
    issuer: str,
    vo: str = DEFAULT_VO,
) -> dict[str, Any]:
    """
    Retrieve a request by its DID for a destination RSE.

    :param scope: The scope of the data identifier as a string.
    :param name: The name of the data identifier as a string.
    :param rse: The destination RSE of the request as a string.
    :param issuer: Issuing account as a string.
    :param vo: The VO to act on.
    :returns: Request as a dictionary.
    """
    with db_session(DatabaseOperationType.READ) as session:
        rse_id = get_rse_id(rse=rse, vo=vo, session=session)

        kwargs = {'scope': scope, 'name': name, 'rse': rse, 'rse_id': rse_id, 'issuer': issuer}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='get_request_by_did', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied(f'{issuer} cannot retrieve the request DID {scope}:{name} to RSE {rse}. {auth_result.message}')

        internal_scope = InternalScope(scope, vo=vo)
        req = request.get_request_by_did(internal_scope, name, rse_id, session=session)

        return gateway_update_return_dict(req, session=session)


def get_request_history_by_did(
    scope: str,
    name: str,
    rse: str,
    issuer: str,
    vo: str = DEFAULT_VO,
) -> dict[str, Any]:
    """
    Retrieve a historical request by its DID for a destination RSE.

    :param scope: The scope of the data identifier as a string.
    :param name: The name of the data identifier as a string.
    :param rse: The destination RSE of the request as a string.
    :param issuer: Issuing account as a string.
    :param vo: The VO to act on.
    :returns: Request as a dictionary.
    """
    with db_session(DatabaseOperationType.READ) as session:
        rse_id = get_rse_id(rse=rse, vo=vo, session=session)

        kwargs = {'scope': scope, 'name': name, 'rse': rse, 'rse_id': rse_id, 'issuer': issuer}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='get_request_history_by_did', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied(f'{issuer} cannot retrieve the request DID {scope}:{name} to RSE {rse}. {auth_result.message}')

        internal_scope = InternalScope(scope, vo=vo)
        req = request.get_request_history_by_did(internal_scope, name, rse_id, session=session)

        return gateway_update_return_dict(req, session=session)


def list_requests(
    src_rses: "Iterable[str]",
    dst_rses: "Iterable[str]",
    states: "Sequence[RequestState]",
    issuer: str,
    vo: str = DEFAULT_VO,
) -> "Iterator[dict[str, Any]]":
    """
    List all requests in a specific state from a source RSE to a destination RSE.

    :param src_rses: source RSEs.
    :param dst_rses: destination RSEs.
    :param states: list of request states.
    :param issuer: Issuing account as a string.
    """
    with db_session(DatabaseOperationType.READ) as session:
        src_rse_ids = [get_rse_id(rse=rse, vo=vo, session=session) for rse in src_rses]
        dst_rse_ids = [get_rse_id(rse=rse, vo=vo, session=session) for rse in dst_rses]

        kwargs = {'src_rse_id': src_rse_ids, 'dst_rse_id': dst_rse_ids, 'issuer': issuer}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='list_requests', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied(f'{issuer} cannot list requests from RSEs {src_rses} to RSEs {dst_rses}. {auth_result.message}')

        for req in request.list_requests(src_rse_ids, dst_rse_ids, states, session=session):
            req = req.to_dict()
            yield gateway_update_return_dict(req, session=session)


def list_requests_history(
    src_rses: "Iterable[str]",
    dst_rses: "Iterable[str]",
    states: "Sequence[RequestState]",
    issuer: str,
    vo: str = DEFAULT_VO,
    offset: Optional[int] = None,
    limit: Optional[int] = None,
) -> "Iterator[dict[str, Any]]":
    """
    List all historical requests in a specific state from a source RSE to a destination RSE.
    :param src_rses: source RSEs.
    :param dst_rses: destination RSEs.
    :param states: list of request states.
    :param issuer: Issuing account as a string.
    :param offset: offset (for paging).
    :param limit: limit number of results.
    """
    with db_session(DatabaseOperationType.READ) as session:
        src_rse_ids = [get_rse_id(rse=rse, vo=vo, session=session) for rse in src_rses]
        dst_rse_ids = [get_rse_id(rse=rse, vo=vo, session=session) for rse in dst_rses]

        kwargs = {'src_rse_id': src_rse_ids, 'dst_rse_id': dst_rse_ids, 'issuer': issuer}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='list_requests_history', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied(f'{issuer} cannot list requests from RSEs {src_rses} to RSEs {dst_rses}. {auth_result.message}')

        for req in request.list_requests_history(src_rse_ids, dst_rse_ids, states, offset, limit, session=session):
            req = req.to_dict()
            yield gateway_update_return_dict(req, session=session)


def get_request_metrics(
    src_rse: Optional[str],
    dst_rse: Optional[str],
    activity: Optional[str],
    group_by_rse_attribute: Optional[str],
    issuer: str,
    vo: str = DEFAULT_VO,
) -> dict[str, Any]:
    """
    Get statistics of requests in a specific state grouped by source RSE, destination RSE, and activity.

    :param src_rse: source RSE.
    :param dst_rse: destination RSE.
    :param activity: activity
    :param group_by_rse_attribute: The parameter to group the RSEs by.
    :param issuer: Issuing account as a string.
    """
    src_rse_id = None
    dst_rse_id = None
    kwargs = {'issuer': issuer}

    with db_session(DatabaseOperationType.READ) as session:
        if src_rse:
            src_rse_id = get_rse_id(rse=src_rse, vo=vo, session=session)

        if dst_rse:
            dst_rse_id = get_rse_id(rse=dst_rse, vo=vo, session=session)

        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='get_request_metrics', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied(f'{issuer} cannot get request statistics. {auth_result.message}')

        return request.get_request_metrics(dest_rse_id=dst_rse_id, src_rse_id=src_rse_id, activity=activity, group_by_rse_attribute=group_by_rse_attribute, session=session)


def list_transfer_limits(
    issuer: str,
    vo: str = 'def'
) -> "Iterator[dict[str, Any]]":
    """
    List all the transfer limits.

    :param issuer: Issuing account as a string.
    :param session: The database session in use.

    :returns: The list of transfer limits
    """
    with db_session(DatabaseOperationType.READ) as session:
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='list_transfer_limits', kwargs={}, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied(f'{issuer} cannot list transfer limits. {auth_result.message}')

        return request.list_transfer_limits(session=session)


def set_transfer_limit(
    issuer: str,
    rse_expression: str,
    activity: Optional[str] = None,
    direction: TransferLimitDirection = TransferLimitDirection.DESTINATION,
    max_transfers: Optional[int] = None,
    volume: Optional[int] = None,
    deadline: Optional[int] = None,
    strategy: Optional[str] = None,
    transfers: Optional[int] = None,
    waitings: Optional[int] = None,
    vo: str = 'def'
) -> None:
    """
    Create or update a transfer limit

    :param issuer: Issuing account as a string.
    :param vo: The VO to act on.
    :param rse_expression: RSE expression for which the transfer limit applies.
    :param activity: The activity for which the transfer limit applies.
    :param direction: The direction in which this limit applies (source/destination)
    :param max_transfers: Maximum transfers.
    :param volume: Maximum transfer volume in bytes.
    :param deadline: Maximum waiting time in hours until a datasets gets released.
    :param strategy: defines how to handle datasets: `fifo` (each file released separately) or `grouped_fifo` (wait for the entire dataset to fit)
    :param transfers: Current number of active transfers
    :param waitings: Current number of waiting transfers
    :param session: The database session in use.

    :returns: None
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        kwargs = {'rse_expression': rse_expression, 'activity': activity, 'max_transfers': max_transfers}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='set_transfer_limit', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied(f'{issuer} cannot set transfer limits. {auth_result.message}')

        request.set_transfer_limit(rse_expression=rse_expression,
                                   activity=activity,
                                   direction=direction,
                                   max_transfers=max_transfers,
                                   volume=volume,
                                   deadline=deadline,
                                   strategy=strategy,
                                   transfers=transfers,
                                   waitings=waitings)


def delete_transfer_limit(
    issuer: str,
    rse_expression: str,
    activity: Optional[str] = None,
    direction: TransferLimitDirection = TransferLimitDirection.DESTINATION,
    vo: str = 'def'
) -> None:
    """
    Delete a transfer limit

    :param issuer: Issuing account as a string.
    :param vo: The VO to act on.
    :param rse_expression: RSE expression for which the transfer limit applies.
    :param activity: The activity for which the transfer limit applies.
    :param direction: The direction in which this limit applies (source/destination)
    :param session: The database session in use.
    """
    with db_session(DatabaseOperationType.WRITE) as session:
        kwargs = {'rse_expression': rse_expression, 'activity': activity}
        auth_result = permission.has_permission(issuer=issuer, vo=vo, action='delete_transfer_limit', kwargs=kwargs, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied(f'{issuer} cannot delete transfer limits. {auth_result.message}')

        request.delete_transfer_limit(rse_expression=rse_expression,
                                      activity=activity,
                                      direction=direction,
                                      session=session)
