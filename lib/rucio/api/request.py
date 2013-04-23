# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013


def queue_request(account, scope, name, dest_rse, req_type, metadata={}):
    """
    Submit a request to a destination RSE for a data identifier.

    :param account: Account identifier as a string.
    :param scope: Scope name as a string.
    :param name: Data identifier name as a string.
    :param dest_rse: RSE name as a string.
    :param req_type: Type of the request as a string.
    :param metadata: Metadata key/value pairs as a dictionary.
    :returns: Request-ID as a 32 character hex string.
    """

    return '6f36a8bf8c1c49008f3ab2051de75e1b'


def submit_deletion():
    """
    Submit a deletion request to a deletiontool.
    """
    pass


def submit_transfer(account, source, destination, transfertool='fts3-mock', metadata={}):
    """
    Submit a transfer request to a transfertool.

    :param account: Account identifier as a string.
    :param source: Source URL acceptable to transfertool as a string.
    :param destination: Destination URL acceptable to transfertool as a string.
    :param transfertool: Transfertool as a string.
    :param metadata: Metadata key/value pairs as a dictionary.
    :returns: Transfertool external ID.
    """

    return '6f36a8bf8c1c49008f3ab2051de75e1b'


def query_request(account, request_id):
    """
    Query the status of a request.

    :param account: Account identifier as a string.
    :param request_id: Request-ID as a 32 character hex string.
    :returns: Request status information as a dictionary.
    """

    return {'meta': 'data'}


def cancel_request(account, request_id):
    """
    Cancel a request.

    :param account: Account identifier as a string.
    :param request_id: Request Identifier as a 32 character hex string.
    """

    return


def get_next(account, req_type, state=None):
    """
    Retrieve the next request matching the request type and state.

    :param account: Account identifier as a string.
    :param req_type: Type of the request as a string.
    :param state: State of the request as a string. None selects all.
    :returns: Request as a dictionary.
    """

    return {'meta': 'data'}
