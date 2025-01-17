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

from rucio.core.common import exception
from rucio.core.common.types import InternalAccount, InternalScope, RequestGatewayDict
from rucio.core.common.utils import gateway_update_return_dict
from rucio.core import request
from rucio.core.rse import get_rse_id
from rucio.core.db.sqla.session import read_session, stream_session, transactional_session
from rucio.gateway import permission

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence

    from sqlalchemy.orm import Session

    from rucio.core.db.sqla.constants import RequestState, RequestType


@transactional_session
def queue_requests(
    requests: "Iterable[RequestGatewayDict]",
    issuer: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> list[dict[str, Any]]:
    """
    Submit transfer or deletion requests on destination RSEs for data identifiers.

    :param requests: List of dictionaries containing 'scope', 'name', 'dest_rse_id', 'request_type', 'attributes'
    :param issuer: Issuing account as a string.
    :param vo: The VO to act on.
    :param session: The database session in use.
    :returns: List of Request-IDs as 32 character hex strings
    """

    kwargs = {'requests': requests, 'issuer': issuer}
    auth_result = permission.has_permission(issuer=issuer, vo=vo, action='queue_requests', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise exception.AccessDenied(f'{issuer} can not queue request. {auth_result.message}')

    for req in requests:
        req['scope'] = InternalScope(req['scope'], vo=vo)  # type: ignore (type reassignment)
        if 'account' in req:
            req['account'] = InternalAccount(req['account'], vo=vo)  # type: ignore (type reassignment)

    new_requests = request.queue_requests(requests, session=session)
    return [gateway_update_return_dict(r, session=session) for r in new_requests]


@transactional_session
def cancel_request(
    request_id: str,
    issuer: str,
    account: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> None:
    """
    Cancel a request.

    :param request_id: Request Identifier as a 32 character hex string.
    :param issuer: Issuing account as a string.
    :param account: Account identifier as a string.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """

    kwargs = {'account': account, 'issuer': issuer, 'request_id': request_id}
    auth_result = permission.has_permission(issuer=issuer, vo=vo, action='cancel_request_', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise exception.AccessDenied('%s cannot cancel request %s. %s' % (account, request_id, auth_result.message))

    raise NotImplementedError


@transactional_session
def cancel_request_did(
    scope: str,
    name: str,
    dest_rse: str,
    request_type: str,
    issuer: str,
    account: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> dict[str, Any]:
    """
    Cancel a request based on a DID and request type.

    :param scope: Data identifier scope as a string.
    :param name: Data identifier name as a string.
    :param dest_rse: RSE name as a string.
    :param request_type: Type of the request as a string.
    :param issuer: Issuing account as a string.
    :param account: Account identifier as a string.
    :param vo: The VO to act on.
    :param session: The database session in use.
    """

    dest_rse_id = get_rse_id(rse=dest_rse, vo=vo, session=session)

    kwargs = {'account': account, 'issuer': issuer}
    auth_result = permission.has_permission(issuer=issuer, vo=vo, action='cancel_request_did', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise exception.AccessDenied(f'{account} cannot cancel {request_type} request for {scope}:{name}. {auth_result.message}')

    internal_scope = InternalScope(scope, vo=vo)
    return request.cancel_request_did(internal_scope, name, dest_rse_id, request_type, session=session)


@transactional_session
def get_next(
    request_type: "RequestType",
    state: "RequestState",
    issuer: str,
    account: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> list[dict[str, Any]]:
    """
    Retrieve the next request matching the request type and state.

    :param request_type: Type of the request as a string.
    :param state: State of the request as a string.
    :param issuer: Issuing account as a string.
    :param account: Account identifier as a string.
    :param vo: The VO to act on.
    :param session: The database session in use.
    :returns: Request as a dictionary.
    """

    kwargs = {'account': account, 'issuer': issuer, 'request_type': request_type, 'state': state}
    auth_result = permission.has_permission(issuer=issuer, vo=vo, action='get_next', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise exception.AccessDenied(f'{account} cannot get the next request of type {request_type} in state {state}. {auth_result.message}')

    reqs = request.get_and_mark_next(request_type, state, session=session)
    return [gateway_update_return_dict(r, session=session) for r in reqs]


@read_session
def get_request_by_did(
    scope: str,
    name: str,
    rse: str,
    issuer: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> dict[str, Any]:
    """
    Retrieve a request by its DID for a destination RSE.

    :param scope: The scope of the data identifier as a string.
    :param name: The name of the data identifier as a string.
    :param rse: The destination RSE of the request as a string.
    :param issuer: Issuing account as a string.
    :param vo: The VO to act on.
    :param session: The database session in use.
    :returns: Request as a dictionary.
    """
    rse_id = get_rse_id(rse=rse, vo=vo, session=session)

    kwargs = {'scope': scope, 'name': name, 'rse': rse, 'rse_id': rse_id, 'issuer': issuer}
    auth_result = permission.has_permission(issuer=issuer, vo=vo, action='get_request_by_did', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise exception.AccessDenied(f'{issuer} cannot retrieve the request DID {scope}:{name} to RSE {rse}. {auth_result.message}')

    internal_scope = InternalScope(scope, vo=vo)
    req = request.get_request_by_did(internal_scope, name, rse_id, session=session)

    return gateway_update_return_dict(req, session=session)


@read_session
def get_request_history_by_did(
    scope: str,
    name: str,
    rse: str,
    issuer: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> dict[str, Any]:
    """
    Retrieve a historical request by its DID for a destination RSE.

    :param scope: The scope of the data identifier as a string.
    :param name: The name of the data identifier as a string.
    :param rse: The destination RSE of the request as a string.
    :param issuer: Issuing account as a string.
    :param vo: The VO to act on.
    :param session: The database session in use.
    :returns: Request as a dictionary.
    """
    rse_id = get_rse_id(rse=rse, vo=vo, session=session)

    kwargs = {'scope': scope, 'name': name, 'rse': rse, 'rse_id': rse_id, 'issuer': issuer}
    auth_result = permission.has_permission(issuer=issuer, vo=vo, action='get_request_history_by_did', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise exception.AccessDenied(f'{issuer} cannot retrieve the request DID {scope}:{name} to RSE {rse}. {auth_result.message}')

    internal_scope = InternalScope(scope, vo=vo)
    req = request.get_request_history_by_did(internal_scope, name, rse_id, session=session)

    return gateway_update_return_dict(req, session=session)


@stream_session
def list_requests(
    src_rses: "Iterable[str]",
    dst_rses: "Iterable[str]",
    states: "Sequence[RequestState]",
    issuer: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> "Iterator[dict[str, Any]]":
    """
    List all requests in a specific state from a source RSE to a destination RSE.

    :param src_rses: source RSEs.
    :param dst_rses: destination RSEs.
    :param states: list of request states.
    :param issuer: Issuing account as a string.
    :param session: The database session in use.
    """
    src_rse_ids = [get_rse_id(rse=rse, vo=vo, session=session) for rse in src_rses]
    dst_rse_ids = [get_rse_id(rse=rse, vo=vo, session=session) for rse in dst_rses]

    kwargs = {'src_rse_id': src_rse_ids, 'dst_rse_id': dst_rse_ids, 'issuer': issuer}
    auth_result = permission.has_permission(issuer=issuer, vo=vo, action='list_requests', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise exception.AccessDenied(f'{issuer} cannot list requests from RSEs {src_rses} to RSEs {dst_rses}. {auth_result.message}')

    for req in request.list_requests(src_rse_ids, dst_rse_ids, states, session=session):
        req = req.to_dict()
        yield gateway_update_return_dict(req, session=session)


@stream_session
def list_requests_history(
    src_rses: "Iterable[str]",
    dst_rses: "Iterable[str]",
    states: "Sequence[RequestState]",
    issuer: str,
    vo: str = 'def',
    offset: Optional[int] = None,
    limit: Optional[int] = None,
    *,
    session: "Session"
) -> "Iterator[dict[str, Any]]":
    """
    List all historical requests in a specific state from a source RSE to a destination RSE.
    :param src_rses: source RSEs.
    :param dst_rses: destination RSEs.
    :param states: list of request states.
    :param issuer: Issuing account as a string.
    :param offset: offset (for paging).
    :param limit: limit number of results.
    :param session: The database session in use.
    """
    src_rse_ids = [get_rse_id(rse=rse, vo=vo, session=session) for rse in src_rses]
    dst_rse_ids = [get_rse_id(rse=rse, vo=vo, session=session) for rse in dst_rses]

    kwargs = {'src_rse_id': src_rse_ids, 'dst_rse_id': dst_rse_ids, 'issuer': issuer}
    auth_result = permission.has_permission(issuer=issuer, vo=vo, action='list_requests_history', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise exception.AccessDenied(f'{issuer} cannot list requests from RSEs {src_rses} to RSEs {dst_rses}. {auth_result.message}')

    for req in request.list_requests_history(src_rse_ids, dst_rse_ids, states, offset, limit, session=session):
        req = req.to_dict()
        yield gateway_update_return_dict(req, session=session)


@read_session
def get_request_metrics(
    src_rse: Optional[str],
    dst_rse: Optional[str],
    activity: Optional[str],
    group_by_rse_attribute: Optional[str],
    issuer: str,
    vo: str = 'def',
    *,
    session: "Session"
) -> dict[str, Any]:
    """
    Get statistics of requests in a specific state grouped by source RSE, destination RSE, and activity.

    :param src_rse: source RSE.
    :param dst_rse: destination RSE.
    :param activity: activity
    :param group_by_rse_attribute: The parameter to group the RSEs by.
    :param issuer: Issuing account as a string.
    :param session: The database session in use.
    """
    src_rse_id = None
    if src_rse:
        src_rse_id = get_rse_id(rse=src_rse, vo=vo, session=session)
    dst_rse_id = None
    if dst_rse:
        dst_rse_id = get_rse_id(rse=dst_rse, vo=vo, session=session)
    kwargs = {'issuer': issuer}
    auth_result = permission.has_permission(issuer=issuer, vo=vo, action='get_request_metrics', kwargs=kwargs, session=session)
    if not auth_result.allowed:
        raise exception.AccessDenied(f'{issuer} cannot get request statistics. {auth_result.message}')

    return request.get_request_metrics(dest_rse_id=dst_rse_id, src_rse_id=src_rse_id, activity=activity, group_by_rse_attribute=group_by_rse_attribute, session=session)
