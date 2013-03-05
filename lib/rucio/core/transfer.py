# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

from rucio.transfertool import fts3


def submit_rse_transfer(scope, name, destination_rse, metadata):
    """
    Submit a transfer to a destination RSE for a data identifier.

    :param scope: Scope name as a string.
    :param name: Data identifier name as a string.
    :param destination_rse: RSE name as a string.
    :param metadata: Metadata key/value pairs as a dictionary.
    :returns: Rucio-Transfer-Identifier as a 32 character hex string.
    """

    source = 'uri://scope_name_source_resolved'
    destination = 'uri://scope_name_destination_resolved'
    transfertool = 'fts3'

    return submit_transfer(source=source, destination=destination, transfertool=transfertool, metadata=metadata)


def submit_transfer(source, destination, transfertool, metadata):
    """
    Submit a transfer to a transfertool.

    :param source: Source URL acceptable to transfertool as a string.
    :param destination: Destination URL acceptable to transfertool as a string.
    :param transfertool: Transfertool as a string.
    :param metadata: Metadata key/value pairs as a dictionary.
    :returns: Rucio-Transfer-Identifier as a 32 character hex string.
    """

    if transfertool == 'fts3':
        transfer_id = fts3.submit(source, destination, metadata)

        # store rucio transfer id, external transfer id, transfer tool selection in database
        rucio_transfer_id = transfer_id
        return rucio_transfer_id


def query_transfer(transfer_id):
    """
    Query the status of a transfer.

    :param rucio_transfer_id: Rucio-Transfer-Identifier as a 32 character hex string.
    :returns: Transfer status information as a dictionary.
    """

    # select correct transfertool based on rucio transfer id entry in database
    transfertool = 'fts3'

    if transfertool == 'fts3':
        fts_info = fts3.query(transfer_id)
        fts_info['rucio_transfer_id'] = 'dummy'
        return fts_info


def cancel_transfer(rucio_transfer_id):
    """
    Cancel a transfer.

    :param rucio_transfer_id: Rucio-Transfer-Identifier as a 32 character hex string.
    """

    # select correct transfertool and external transfer id based on rucio transfer id entry in database
    transfertool = 'fts3'

    if transfertool == 'fts3':
        transfer_id = rucio_transfer_id
        return fts3.cancel(transfer_id)
