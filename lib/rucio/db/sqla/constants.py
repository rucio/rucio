# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013-2017
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014, 2017
# - Martin Barisits, <martin.barisits@cern.ch>, 2014-2019
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2015-2018
# - Wen Guan, <wen.guan>, 2016
#
# PY3K COMPATIBLE

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


class BadFilesStatus(DeclEnum):
    BAD = 'B', 'BAD'
    DELETED = 'D', 'DELETED'
    LOST = 'L', 'LOST'
    RECOVERED = 'R', 'RECOVERED'
    SUSPICIOUS = 'S', 'SUSPICIOUS'
    TEMPORARY_UNAVAILABLE = 'T', 'TEMPORARY_UNAVAILABLE'


class BadPFNStatus(DeclEnum):
    BAD = 'B', 'BAD'
    SUSPICIOUS = 'S', 'SUSPICIOUS'
    TEMPORARY_UNAVAILABLE = 'T', 'TEMPORARY_UNAVAILABLE'
    AVAILABLE = 'A', 'AVAILABLE'


class DIDAvailability(DeclEnum):
    LOST = 'L', 'LOST'
    DELETED = 'D', 'DELETED'
    AVAILABLE = 'A', 'AVAILABLE'


class DIDReEvaluation(DeclEnum):
    ATTACH = 'A', 'ATTACH'
    DETACH = 'D', 'DETACH'


class DIDType(DeclEnum):
    FILE = 'F', 'FILE'
    DATASET = 'D', 'DATASET'
    CONTAINER = 'C', 'CONTAINER'
    ARCHIVE = 'A', 'ARCHIVE'
    DELETED_FILE = 'X', 'DELETED_FILE'
    DELETED_DATASET = 'Y', 'DELETED_DATASET'
    DELETED_CONTAINER = 'Z', 'DELETED_CONTAINER'


class FTSCompleteState(DeclEnum):
    OK = 'O', 'Ok'
    ERROR = 'E', 'Error'


class FTSState(DeclEnum):
    SUBMITTED = 'S', 'SUBMITTED'
    READY = 'R', 'READY'
    ACTIVE = 'A', 'ACTIVE'
    FAILED = 'F', 'FAILED'
    FINISHED = 'X', 'FINISHED'
    FINISHEDDIRTY = 'D', 'FINISHEDDIRTY'
    CANCELED = 'C', 'CANCELED'


class IdentityType(DeclEnum):
    X509 = 'X509', 'X509'
    GSS = 'GSS', 'GSS'
    USERPASS = 'USERPASS', 'USERPASS'
    SSH = 'SSH', 'SSH'


class KeyType(DeclEnum):
    ALL = 'ALL', 'ALL'
    COLLECTION = 'COLLECTION', 'COLLECTION'
    CONTAINER = 'CONTAINER', 'CONTAINER'
    DATASET = 'DATASET', 'DATASET'
    FILE = 'FILE', 'FILE'
    DERIVED = 'DERIVED', 'DERIVED'


class LifetimeExceptionsState(DeclEnum):
    APPROVED = 'A', 'APPROVED'
    REJECTED = 'R', 'REJECTED'
    WAITING = 'W', 'WAITING'


class LockState(DeclEnum):
    REPLICATING = 'R', 'REPLICATING'
    OK = 'O', 'OK'
    STUCK = 'S', 'STUCK'


class ReplicaState(DeclEnum):
    AVAILABLE = 'A', 'AVAILABLE'
    UNAVAILABLE = 'U', 'UNAVAILABLE'
    COPYING = 'C', 'COPYING'
    BEING_DELETED = 'B', 'BEING_DELETED'
    BAD = 'D', 'BAD'
    SOURCE = 'S', 'SOURCE'
    TEMPORARY_UNAVAILABLE = 'T', 'TEMPORARY_UNAVAILABLE'


class RequestErrMsg(DeclEnum):
    NO_SOURCES = 'NO_SOURCES', 'NO_SOURCES'
    SUBMISSION_FAILED = 'SUBMISSION_FAILED', 'SUBMISSION_FAILED'
    TRANSFER_FAILED = 'TRANSFER_FAILED', 'TRANSFER_FAILED'
    MISMATCH_SCHEME = 'MISMATCH_SCHEME', 'MISMATCH_SCHEME'
    OTHER = 'OTHER', 'OTHER'


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
    MISMATCH_SCHEME = 'M', 'MISMATCH_SCHEME'
    SUSPEND = 'U', 'SUSPEND'
    WAITING = 'W', 'WAITING'


class RequestType(DeclEnum):
    TRANSFER = 'T', 'TRANSFER'
    UPLOAD = 'U', 'UPLOAD'
    DOWNLOAD = 'D', 'DOWNLOAD'
    STAGEIN = 'I', 'STAGEIN'
    STAGEOUT = 'O', 'STAGEOUT'


class RSEType(DeclEnum):
    DISK = 'DISK', 'DISK'
    TAPE = 'TAPE', 'TAPE'


class RuleGrouping(DeclEnum):
    ALL = 'A', 'ALL'
    DATASET = 'D', 'DATASET'
    NONE = 'N', 'NONE'


class RuleNotification(DeclEnum):
    YES = 'Y', 'YES'
    NO = 'N', 'NO'
    CLOSE = 'C', 'CLOSE'
    PROGRESS = 'P', 'PROGRESS'


class RuleState(DeclEnum):
    REPLICATING = 'R', 'REPLICATING'
    OK = 'O', 'OK'
    STUCK = 'S', 'STUCK'
    SUSPENDED = 'U', 'SUSPENDED'
    WAITING_APPROVAL = 'W', 'WAITING_APPROVAL'
    INJECT = 'I', 'INJECT'


class ScopeStatus(DeclEnum):
    OPEN = 'O', 'OPEN'
    CLOSED = 'C', 'CLOSED'
    DELETED = 'D', 'DELETED'


class SubscriptionState(DeclEnum):
    ACTIVE = 'A', 'ACTIVE'
    INACTIVE = 'I', 'INACTIVE'
    NEW = 'N', 'NEW'
    UPDATED = 'U', 'UPDATED'
    BROKEN = 'B', 'BROKEN'


# Individual constants

OBSOLETE = datetime(year=1970, month=1, day=1)  # Tombstone value to mark obsolete replicas.
