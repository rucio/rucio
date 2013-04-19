# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

"""
Constants.

Each constant is in the format:
    CONSTANT_NAME = VALUE, DESCRIPTION
VALUE is what will be stored in the DB.
DESCRIPTION is the meaningful string for client
"""

from rucio.db.enum import DeclEnum


class AccountStatus(DeclEnum):
    ACTIVE = 'ACTIVE', 'ACTIVE'
    SUSPENDED = 'SUSPENDED', 'SUSPENDED'
    DELETED = 'DELETED', 'DELETED'


class ScopeStatus(DeclEnum):
    OPEN = 'OPEN', 'OPEN'
    CLOSED = 'CLOSED', 'CLOSED'
    DELETED = 'DELETED', 'DELETED'


class DIDType(DeclEnum):
    FILE = 'FILE', 'FILE'
    DATASET = 'DATASET', 'DATASET'
    CONTAINER = 'CONTAINER', 'CONTAINER'
