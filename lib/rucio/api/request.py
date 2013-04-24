# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

from rucio.api import permission
from rucio.common import exception
from rucio.core import request


def queue_request(account, issuer, scope, name, dest_rse, req_type, metadata={}):
    """
    Submit a transfer or deletion request on a destination RSE for a data identifier.

    :param account: Account identifier as a string.
    :param account: Issuing account as a string.
    :param scope: Data identifier scope as a string.
    :param name: Data identifier name as a string.
    :param dest_rse: RSE name as a string.
    :param req_type: Type of the request as a string.
    :param metadata: Metadata key/value pairs as a dictionary.
    :returns: Request-ID as a 32 character hex string.
    """

    kwargs = {'account': account, 'issuer': issuer, 'scope': scope, 'name': name, 'dest_rse': dest_rse, 'req_type': req_type, 'metadata': metadata}
    if not permission.has_permission(issuer=issuer, action='queue_request', kwargs=kwargs):
        raise exception.AccessDenied('%(account)s can not request %(req_type)s on %(destination_rse)s for %(scope)s:%(name)s' % locals())

    return request.queue_request(scope=scope, name=name, dest_rse=dest_rse, req_type=req_type, metadata=metadata)


def submit_deletion(account, issuer, url):
    """
    Submit a deletion request to a deletiontool.

    :param account: Account identifier as a string.
    :param src_url: URL acceptable to deletiontool as a string.
    :returns: Deletiontool external ID.
    """

    kwargs = {'account': account, 'issuer': issuer, 'url': url}
    if not permission.has_permission(issuer=issuer, action='submit_deletion', kwargs=kwargs):
        raise exception.AccessDenied('%(account)s can not delete' % locals())

    return request.submit_deletion(url)


def submit_transfer(account, issuer, request_id, src_urls, dest_urls, transfertool, metadata={}):
    """
    Submit a transfer request to a transfertool.

    :param account: Account identifier as a string.
    :param request_id: Associated request identifier as a string.
    :param src_urls: Source URL acceptable to transfertool as a list of strings.
    :param dest_urls: Destination URL acceptable to transfertool as a list of strings.
    :param transfertool: Transfertool as a string.
    :param metadata: Metadata key/value pairs as a dictionary.
    :returns: Transfertool external ID.
    """

    kwargs = {'account': account, 'issuer': issuer, 'request_id': request_id, 'src_urls': src_urls, 'dest_urls': dest_urls, 'transfertool': transfertool, 'metadata': metadata}
    if not permission.has_permission(issuer=issuer, action='submit_transfer', kwargs=kwargs):
        raise exception.AccessDenied('%(account)s cannot submit a transfer with %s(transfertool)s from %(src_urls)s to %(dest_urls)s' % locals())

    return request.submit_transfer(request_id, src_urls=src_urls, dest_urls=dest_urls, transfertool=transfertool, metadata=metadata)


def query_request(account, issuer, request_id):
    """
    Query the status of a request.

    :param account: Account identifier as a string.
    :param request_id: Request-ID as a 32 character hex string.
    :returns: Request status information as a dictionary.
    """

    kwargs = {'account': account, 'issuer': issuer, 'request_id': request_id}
    if not permission.has_permission(issuer=issuer, action='query_request', kwargs=kwargs):
        raise exception.AccessDenied('%(account)s cannot query request %s(request_id)s' % locals())

    return request.query_request(request_id)


def cancel_request(account, issuer, request_id):
    """
    Cancel a request.

    :param account: Account identifier as a string.
    :param request_id: Request Identifier as a 32 character hex string.
    """

    kwargs = {'account': account, 'issuer': issuer, 'request_id': request_id}
    if not permission.has_permission(issuer=issuer, action='cancel_request_', kwargs=kwargs):
        raise exception.AccessDenied('%(account)s cannot cancel request %s(request_id)s' % locals())

    return request.cancel_request(request_id)


def cancel_request_did(account, issuer, scope, name, dest_rse, req_type):
    """
    Cancel a request based on a DID and request type.

    :param account: Account identifier as a string.
    :param scope: Data identifier scope as a string.
    :param name: Data identifier name as a string.
    :param dest_rse: RSE name as a string.
    :param req_type: Type of the request as a string.
    """

    kwargs = {'account': account, 'issuer': issuer}
    if not permission.has_permission(issuer=issuer, action='cancel_request_did', kwargs=kwargs):
        raise exception.AccessDenied('%(account)s cannot cancel %(req_type)s request for %(scope)s:%(name)s' % locals())

    return request.cancel_request_did(scope, name, dest_rse, req_type)


def get_next(account, issuer, req_type, state):
    """
    Retrieve the next request matching the request type and state.

    :param account: Account identifier as a string.
    :param req_type: Type of the request as a string.
    :param state: State of the request as a string.
    :returns: Request as a dictionary.
    """

    kwargs = {'account': account, 'issuer': issuer, 'req_type': req_type, 'state': state}
    if not permission.has_permission(issuer=issuer, action='get_next', kwargs=kwargs):
        raise exception.AccessDenied('%(account)s cannot get the next request of type %(req_type)s in state %(state)s' % locals())

    return request.get_next(req_type, state)
