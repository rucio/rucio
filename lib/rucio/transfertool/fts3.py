# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

import uuid


def submit(source, destination, metadata):
    """
    Submit a transfer to FTS3 via JSON.

    :param source: Source URL acceptable to transfertool as a string.
    :param destination: Destination URL acceptable to transfertool as a string.
    :param metadata: Metadata key/value pairs as a dictionary.
    :returns: FTS transfer identifier.
    """

    return str(uuid.uuid4()).replace('-', '')


def query(transfer_id):
    """
    Query the status of a transfer in FTS3 via JSON.

    :param transfer_id: FTS transfer identifier as a string.
    :returns: Transfer status information as a dictionary.
    """

    return {'transfer_id': transfer_id, 'state': 'DONE', 'transfertool': 'fts3'}


def cancel(transfer_id):
    """
    Cancel a transfer that has been submitted to FTS via JSON.

    :param transfer_id: FTS transfer identifier as a string.
    """

    pass
