# -*- coding: utf-8 -*-
# Copyright 2013-2022 CERN
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
#
# Authors:
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2017
# - Vincent Garonne <vincent.garonne@cern.ch>, 2013
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
# - Rob Barnsley <rob.barnsley@skao.int>, 2021-2022
# - Radu Carpa <radu.carpa@cern.ch>, 2022

"""
Interface for the requests abstraction layer
"""

from rucio.api import permission
from rucio.common import exception
from rucio.common.types import InternalAccount, InternalScope
from rucio.common.utils import api_update_return_dict
from rucio.core import request
from rucio.core.rse import get_rse_id


def queue_requests(requests, issuer, vo='def'):
    """
    Submit transfer or deletion requests on destination RSEs for data identifiers.

    :param requests: List of dictionaries containing 'scope', 'name', 'dest_rse_id', 'request_type', 'attributes'
    :param issuer: Issuing account as a string.
    :param vo: The VO to act on.
    :returns: List of Request-IDs as 32 character hex strings
    """

    kwargs = {'requests': requests, 'issuer': issuer}
    if not permission.has_permission(issuer=issuer, vo=vo, action='queue_requests', kwargs=kwargs):
        raise exception.AccessDenied('%(issuer)s can not queue request' % locals())

    for req in requests:
        req['scope'] = InternalScope(req['scope'], vo=vo)
        if 'account' in req:
            req['account'] = InternalAccount(req['account'], vo=vo)

    new_requests = request.queue_requests(requests)
    return [api_update_return_dict(r) for r in new_requests]


def cancel_request(request_id, issuer, account, vo='def'):
    """
    Cancel a request.

    :param request_id: Request Identifier as a 32 character hex string.
    :param issuer: Issuing account as a string.
    :param account: Account identifier as a string.
    :param vo: The VO to act on.
    """

    kwargs = {'account': account, 'issuer': issuer, 'request_id': request_id}
    if not permission.has_permission(issuer=issuer, vo=vo, action='cancel_request_', kwargs=kwargs):
        raise exception.AccessDenied('%s cannot cancel request %s' % (account, request_id))

    raise NotImplementedError


def cancel_request_did(scope, name, dest_rse, request_type, issuer, account, vo='def'):
    """
    Cancel a request based on a DID and request type.

    :param scope: Data identifier scope as a string.
    :param name: Data identifier name as a string.
    :param dest_rse: RSE name as a string.
    :param request_type: Type of the request as a string.
    :param issuer: Issuing account as a string.
    :param account: Account identifier as a string.
    :param vo: The VO to act on.
    """

    dest_rse_id = get_rse_id(rse=dest_rse, vo=vo)

    kwargs = {'account': account, 'issuer': issuer}
    if not permission.has_permission(issuer=issuer, vo=vo, action='cancel_request_did', kwargs=kwargs):
        raise exception.AccessDenied('%(account)s cannot cancel %(request_type)s request for %(scope)s:%(name)s' % locals())

    scope = InternalScope(scope, vo=vo)
    return request.cancel_request_did(scope, name, dest_rse_id, request_type)


def get_next(request_type, state, issuer, account, vo='def'):
    """
    Retrieve the next request matching the request type and state.

    :param request_type: Type of the request as a string.
    :param state: State of the request as a string.
    :param issuer: Issuing account as a string.
    :param account: Account identifier as a string.
    :param vo: The VO to act on.
    :returns: Request as a dictionary.
    """

    kwargs = {'account': account, 'issuer': issuer, 'request_type': request_type, 'state': state}
    if not permission.has_permission(issuer=issuer, vo=vo, action='get_next', kwargs=kwargs):
        raise exception.AccessDenied('%(account)s cannot get the next request of type %(request_type)s in state %(state)s' % locals())

    reqs = request.get_next(request_type, state)
    return [api_update_return_dict(r) for r in reqs]


def get_request_by_did(scope, name, rse, issuer, vo='def'):
    """
    Retrieve a request by its DID for a destination RSE.

    :param scope: The scope of the data identifier as a string.
    :param name: The name of the data identifier as a string.
    :param rse: The destination RSE of the request as a string.
    :param issuer: Issuing account as a string.
    :param vo: The VO to act on.
    :returns: Request as a dictionary.
    """
    rse_id = get_rse_id(rse=rse, vo=vo)

    kwargs = {'scope': scope, 'name': name, 'rse': rse, 'rse_id': rse_id, 'issuer': issuer}
    if not permission.has_permission(issuer=issuer, vo=vo, action='get_request_by_did', kwargs=kwargs):
        raise exception.AccessDenied('%(issuer)s cannot retrieve the request DID %(scope)s:%(name)s to RSE %(rse)s' % locals())

    scope = InternalScope(scope, vo=vo)
    req = request.get_request_by_did(scope, name, rse_id)

    return api_update_return_dict(req)


def get_request_history_by_did(scope, name, rse, issuer, vo='def'):
    """
    Retrieve a historical request by its DID for a destination RSE.

    :param scope: The scope of the data identifier as a string.
    :param name: The name of the data identifier as a string.
    :param rse: The destination RSE of the request as a string.
    :param issuer: Issuing account as a string.
    :param vo: The VO to act on.
    :returns: Request as a dictionary.
    """
    rse_id = get_rse_id(rse=rse, vo=vo)

    kwargs = {'scope': scope, 'name': name, 'rse': rse, 'rse_id': rse_id, 'issuer': issuer}
    if not permission.has_permission(issuer=issuer, vo=vo, action='get_request_history_by_did', kwargs=kwargs):
        raise exception.AccessDenied('%(issuer)s cannot retrieve the request DID %(scope)s:%(name)s to RSE %(rse)s' % locals())

    scope = InternalScope(scope, vo=vo)
    req = request.get_request_history_by_did(scope, name, rse_id)

    return api_update_return_dict(req)


def list_requests(src_rses, dst_rses, states, issuer, vo='def'):
    """
    List all requests in a specific state from a source RSE to a destination RSE.

    :param src_rses: source RSEs.
    :param dst_rses: destination RSEs.
    :param states: list of request states.
    :param issuer: Issuing account as a string.
    """
    src_rse_ids = [get_rse_id(rse=rse, vo=vo) for rse in src_rses]
    dst_rse_ids = [get_rse_id(rse=rse, vo=vo) for rse in dst_rses]

    kwargs = {'src_rse_id': src_rse_ids, 'dst_rse_id': dst_rse_ids, 'issuer': issuer}
    if not permission.has_permission(issuer=issuer, vo=vo, action='list_requests', kwargs=kwargs):
        raise exception.AccessDenied('%(issuer)s cannot list requests from RSE %(src_rse)s to RSE %(dst_rse)s' % locals())

    for req in request.list_requests(src_rse_ids, dst_rse_ids, states):
        req = req.to_dict()
        yield api_update_return_dict(req)


def list_requests_history(src_rses, dst_rses, states, issuer, vo='def', offset=None, limit=None):
    """
    List all historical requests in a specific state from a source RSE to a destination RSE.

    :param src_rses: source RSEs.
    :param dst_rses: destination RSEs.
    :param states: list of request states.
    :param issuer: Issuing account as a string.
    :param offset: offset (for paging).
    :param limit: limit number of results.
    """
    src_rse_ids = [get_rse_id(rse=rse, vo=vo) for rse in src_rses]
    dst_rse_ids = [get_rse_id(rse=rse, vo=vo) for rse in dst_rses]

    kwargs = {'src_rse_id': src_rse_ids, 'dst_rse_id': dst_rse_ids, 'issuer': issuer}
    if not permission.has_permission(issuer=issuer, vo=vo, action='list_requests_history', kwargs=kwargs):
        raise exception.AccessDenied('%(issuer)s cannot list requests from RSE %(src_rse)s to RSE %(dst_rse)s' % locals())

    for req in request.list_requests_history(src_rse_ids, dst_rse_ids, states, offset, limit):
        req = req.to_dict()
        yield api_update_return_dict(req)
