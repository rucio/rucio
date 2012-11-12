# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2012


def add_replication_rule(scope, lfn, rse_tag, replication_factor=1, locked=False, lifetime=None):
    """
    Adds a replication rule.

    :param scope: The scope name.
    :param lfn: The file identifier (LFN).
    :param rse_tag: The file location (RSE).

    """
    raise NotImplementedError


def delete_replication_rule(scope, lfn, rse_tag):
    """
    Deletes a replication rule.

    :param scope: The scope name.
    :param lfn: The file identifier (LFN).
    :param rse_tag: The file location (RSE).

    """
    raise NotImplementedError


def set_replication_rule(scope, lfn, rse_tag):
    """
    Sets a replication rule.

    :param scope: The scope name.
    :param lfn: The file identifier (LFN).
    :param rse_tag: The file location (RSE).

    """
    raise NotImplementedError
