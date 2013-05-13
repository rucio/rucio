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


class AccountType(DeclEnum):
    USER = 'USER', 'USER'
    GROUP = 'GROUP', 'GROUP'
    SERVICE = 'SERVICE', 'SERVICE'


class IdentityType(DeclEnum):
    X509 = 'X509', 'X509'
    GSS = 'GSS', 'GSS'
    USERPASS = 'USERPASS', 'USERPASS'


class ScopeStatus(DeclEnum):
    OPEN = 'OPEN', 'OPEN'
    CLOSED = 'CLOSED', 'CLOSED'
    DELETED = 'DELETED', 'DELETED'


class DIDType(DeclEnum):
    FILE = 'FILE', 'FILE'
    DATASET = 'DATASET', 'DATASET'
    CONTAINER = 'CONTAINER', 'CONTAINER'


class DIDAvailability(DeclEnum):
    LOST = 'LOST', 'LOST'
    DELETED = 'DELETED', 'DELETED'
    AVAILABLE = 'AVAILABLE', 'AVAILABLE'


class KeyType(DeclEnum):
    ALL = 'ALL', 'ALL'
    COLLECTION = 'COLLECTION', 'COLLECTION'
    FILE = 'FILE', 'FILE'
    DERIVED = 'DERIVED', 'DERIVED'


class RSEType(DeclEnum):
    DISK = 'DISK', 'DISK'
    TAPE = 'TAPE', 'TAPE'


class ReplicasState(DeclEnum):
    AVAILABLE = 'AVAILABLE', 'AVAILABLE'
    UNAVAILABLE = 'UNAVAILABLE', 'UNAVAILABLE'
    COPYING = 'COPYING', 'COPYING'
    BEING_DELETED = 'BEING_DELETED', 'BEING_DELETED'
    BAD = 'BAD', 'BAD'


class RuleState(DeclEnum):
    REPLICATING = 'REPLICATING', 'REPLICATING'
    OK = 'OK', 'OK'
    STUCK = 'STUCK', 'STUCK'
    SUSPENDED = 'SUSPENDED', 'SUSPENDED'


class RuleGrouping(DeclEnum):
    ALL = 'ALL', 'ALL'
    DATASET = 'DATASET', 'DATASET'
    NONE = 'NONE', 'NONE'


class LockState(DeclEnum):
    REPLICATING = 'REPLICATING', 'REPLICATING'
    OK = 'OK', 'OK'
    STUCK = 'STUCK', 'STUCK'


class SubscriptionState(DeclEnum):
    ACTIVE = 'ACTIVE', 'ACTIVE'
    INACTIVE = 'INACTIVE', 'INACTIVE'
    NEW = 'NEW', 'NEW'
    UPDATED = 'UPDATED', 'UPDATED'
    BROKEN = 'BROKEN', 'BROKEN'


class RequestType(DeclEnum):
    TRANSFER = 'TRANSFER', 'TRANSFER'
    DELETE = 'DELETE', 'DELETE'
    UPLOAD = 'UPLOAD', 'UPLOAD'
    DOWNLOAD = 'DOWNLOAD', 'DOWNLOAD'


class RequestState(DeclEnum):
    QUEUED = 'QUEUED', 'QUEUED'
    SUBMITTED = 'SUBMITTED', 'SUBMITTED'
    FAILED = 'FAILED', 'FAILED'
    DONE = 'DONE', 'DONE'
