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
from rucio.core import transfer


def submit_rse_transfer(account, scope, name, destination_rse, metadata={}):
    """
    Submit a transfer to a destination RSE for a data identifier.

    :param account: Account identifier as a string.
    :param scope: Scope name as a string.
    :param name: Data identifier name as a string.
    :param destination_rse: RSE name as a string.
    :param metadata: Metadata key/value pairs as a dictionary.
    :returns: Rucio-Transfer-Identifier as a 32 character hex string.
    """

    kwargs = {'account': account, 'scope': scope, 'name': name, 'destination_rse': destination_rse, 'metadata': metadata}
    if not permission.has_permission(issuer=account, action='submit_rse_transfer', kwargs=kwargs):
        raise exception.AccessDenied('Account %(account)s can not submit a transfer to RSE %(destination_rse)s for %(scope)s:%(name)s' % locals())

    return transfer.submit_rse_transfer(scope, name, destination_rse, metadata)


def submit_transfer(account, source, destination, transfertool='fts3', metadata={}):
    """
    Submit a transfer to a transfertool.

    :param account: Account identifier as a string.
    :param source: Source URL acceptable to transfertool as a string.
    :param destination: Destination URL acceptable to transfertool as a string.
    :param transfertool: Transfertool as a string.
    :param metadata: Metadata key/value pairs as a dictionary.
    :returns: Rucio-Transfer-Identifier as a 32 character hex string.
    """

    kwargs = {'account': account, 'source': source, 'destination': destination, 'transfertool': transfertool, 'metadata': metadata}
    if not permission.has_permission(issuer=account, action='submit_transfer', kwargs=kwargs):
        raise exception.AccessDenied('Account %(account)s can not submit a transfer with %s(transfertool)s from %(source)s to %(destination)s' % locals())

    return transfer.submit_transfer(source=source, destination=destination, transfertool=transfertool, metadata=metadata)


def query_transfer(account, rucio_transfer_id):
    """
    Query the status of a transfer.

    :param account: Account identifier as a string.
    :param rucio_transfer_id: Rucio-Transfer-Identifier as a 32 character hex string.
    :returns: Transfer status information as a dictionary.
    """

    kwargs = {'account': account, 'rucio_transfer_id': rucio_transfer_id}
    if not permission.has_permission(issuer=account, action='query_transfer', kwargs=kwargs):
        raise exception.AccessDenied('Account %(account)s can not query transfer %s(transfer_id)s' % locals())

    return transfer.query_transfer(rucio_transfer_id)


def cancel_transfer(account, rucio_transfer_id):
    """
    Cancel a transfer.

    :param account: Account identifier as a string.
    :param rucio_transfer_id: Rucio-Transfer-Identifier as a 32 character hex string.
    """

    kwargs = {'account': account, 'rucio_transfer_id': rucio_transfer_id}
    if not permission.has_permission(issuer=account, action='cancel_transfer', kwargs=kwargs):
        raise exception.AccessDenied('Account %(account)s can not cancel transfer %s(transfer_id)s' % locals())

    return transfer.cancel_transfer(rucio_transfer_id)
