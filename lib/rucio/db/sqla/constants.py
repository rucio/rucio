# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2015
# - Wen Guan, <wen.guan>, 2016

"""
Constants.

Each constant is in the format:
    CONSTANT_NAME = VALUE, DESCRIPTION
VALUE is what will be stored in the DB.
DESCRIPTION is the meaningful string for client
"""

from datetime import datetime

from rucio.db.sqla.enum import DeclEnum


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
    OPEN = 'O', 'OPEN'
    CLOSED = 'C', 'CLOSED'
    DELETED = 'D', 'DELETED'


class DIDType(DeclEnum):
    FILE = 'F', 'FILE'
    DATASET = 'D', 'DATASET'
    CONTAINER = 'C', 'CONTAINER'
    DELETED_FILE = 'X', 'DELETED_FILE'
    DELETED_DATASET = 'Y', 'DELETED_DATASET'
    DELETED_CONTAINER = 'Z', 'DELETED_CONTAINER'


class DIDAvailability(DeclEnum):
    LOST = 'L', 'LOST'
    DELETED = 'D', 'DELETED'
    AVAILABLE = 'A', 'AVAILABLE'


class DIDReEvaluation(DeclEnum):
    ATTACH = 'A', 'ATTACH'
    DETACH = 'D', 'DETACH'


class KeyType(DeclEnum):
    ALL = 'ALL', 'ALL'
    COLLECTION = 'COLLECTION', 'COLLECTION'
    CONTAINER = 'CONTAINER', 'CONTAINER'
    DATASET = 'DATASET', 'DATASET'
    FILE = 'FILE', 'FILE'
    DERIVED = 'DERIVED', 'DERIVED'


class RSEType(DeclEnum):
    DISK = 'DISK', 'DISK'
    TAPE = 'TAPE', 'TAPE'


class ReplicaState(DeclEnum):
    AVAILABLE = 'A', 'AVAILABLE'
    UNAVAILABLE = 'U', 'UNAVAILABLE'
    COPYING = 'C', 'COPYING'
    BEING_DELETED = 'B', 'BEING_DELETED'
    BAD = 'D', 'BAD'
    SOURCE = 'S', 'SOURCE'


class RuleState(DeclEnum):
    REPLICATING = 'R', 'REPLICATING'
    OK = 'O', 'OK'
    STUCK = 'S', 'STUCK'
    SUSPENDED = 'U', 'SUSPENDED'
    WAITING_APPROVAL = 'W', 'WAITING_APPROVAL'
    INJECT = 'I', 'INJECT'


class RuleGrouping(DeclEnum):
    ALL = 'A', 'ALL'
    DATASET = 'D', 'DATASET'
    NONE = 'N', 'NONE'


class LockState(DeclEnum):
    REPLICATING = 'R', 'REPLICATING'
    OK = 'O', 'OK'
    STUCK = 'S', 'STUCK'


class SubscriptionState(DeclEnum):
    ACTIVE = 'A', 'ACTIVE'
    INACTIVE = 'I', 'INACTIVE'
    NEW = 'N', 'NEW'
    UPDATED = 'U', 'UPDATED'
    BROKEN = 'B', 'BROKEN'


class RequestType(DeclEnum):
    TRANSFER = 'T', 'TRANSFER'
    UPLOAD = 'U', 'UPLOAD'
    DOWNLOAD = 'D', 'DOWNLOAD'
    STAGEIN = 'I', 'STAGEIN'
    STAGEOUT = 'O', 'STAGEOUT'


class RequestState(DeclEnum):
    QUEUED = 'Q', 'QUEUED'
    SUBMITTING = 'G', 'SUBMITTING'
    SUBMITTED = 'S', 'SUBMITTED'
    FAILED = 'F', 'FAILED'
    DONE = 'D', 'DONE'
    LOST = 'L', 'LOST'
    NO_SOURCES = 'N', 'NO_SOURCES'
    ONLY_TAPE_SOURCES = 'O', 'ONLY_TAPE_SOURCES'
    SUBMISSION_FAILED = 'A', 'SUBMISSION_FAILED'
    SUSPEND = 'U', 'SUSPEND'
    WAITING = 'W', 'WAITING'


class RequestErrMsg(DeclEnum):
    NO_SOURCES = 'NO_SOURCES', 'NO_SOURCES'
    SUBMISSION_FAILED = 'SUBMISSION_FAILED', 'SUBMISSION_FAILED'
    TRANSFER_FAILED = 'TRANSFER_FAILED', 'TRANSFER_FAILED'
    OTHER = 'OTHER', 'OTHER'


class RuleNotification(DeclEnum):
    YES = 'Y', 'YES'
    NO = 'N', 'NO'
    CLOSE = 'C', 'CLOSE'


class FTSState(DeclEnum):
    SUBMITTED = 'S', 'SUBMITTED'
    READY = 'R', 'READY'
    ACTIVE = 'A', 'ACTIVE'
    FAILED = 'F', 'FAILED'
    FINISHED = 'X', 'FINISHED'
    FINISHEDDIRTY = 'D', 'FINISHEDDIRTY'
    CANCELED = 'C', 'CANCELED'


class FTSCompleteState(DeclEnum):
    OK = 'O', 'Ok'
    ERROR = 'E', 'Error'


class BadFilesStatus(DeclEnum):
    BAD = 'B', 'BAD'
    DELETED = 'D', 'DELETED'
    LOST = 'L', 'LOST'
    RECOVERED = 'R', 'RECOVERED'
    SUSPICIOUS = 'S', 'SUSPICIOUS'


# Individual constants

OBSOLETE = datetime(year=1970, month=1, day=1)  # Tombstone value to mark obsolete replicas.
