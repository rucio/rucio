# -*- coding: utf-8 -*-
# Copyright 2015-2020 CERN
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# - Vincent Garonne <vincent.garonne@cern.ch>, 2015-2017
# - Wen Guan <wen.guan@cern.ch>, 2015-2016
# - Cedric Serfon <cedric.serfon@cern.ch>, 2016
# - Martin Barisits <martin.barisits@cern.ch>, 2017-2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Ruturaj Gujar <ruturaj.gujar23@gmail.com>, 2019
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019
# - Mario Lassnig <mario.lassnig@cern.ch>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

from datetime import datetime
from enum import Enum

# Individual constants

OBSOLETE = datetime(year=1970, month=1, day=1)  # Tombstone value to mark obsolete replicas


# The enum values below are the actual strings stored in the database -- these must be string types.
# This is done explicitly via values_callable to SQLAlchemy enums in models.py and alembic scripts,
# as overloading/overriding Python internal enums is discouraged.

class AccountStatus(Enum):
    ACTIVE = 'ACTIVE'
    SUSPENDED = 'SUSPENDED'
    DELETED = 'DELETED'


class AccountType(Enum):
    USER = 'USER'
    GROUP = 'GROUP'
    SERVICE = 'SERVICE'


class BadFilesStatus(Enum):
    BAD = 'B'
    DELETED = 'D'
    LOST = 'L'
    RECOVERED = 'R'
    SUSPICIOUS = 'S'
    TEMPORARY_UNAVAILABLE = 'T'


class BadPFNStatus(Enum):
    BAD = 'B'
    SUSPICIOUS = 'S'
    TEMPORARY_UNAVAILABLE = 'T'
    AVAILABLE = 'A'


class DIDAvailability(Enum):
    LOST = 'L'
    DELETED = 'D'
    AVAILABLE = 'A'


class DIDReEvaluation(Enum):
    ATTACH = 'A'
    DETACH = 'D'


class DIDType(Enum):
    FILE = 'F'
    DATASET = 'D'
    CONTAINER = 'C'
    ARCHIVE = 'A'
    DELETED_FILE = 'X'
    DELETED_DATASET = 'Y'
    DELETED_CONTAINER = 'Z'


class IdentityType(Enum):
    X509 = 'X509'
    GSS = 'GSS'
    USERPASS = 'USERPASS'
    SSH = 'SSH'
    SAML = 'SAML'
    OIDC = 'OIDC'


class KeyType(Enum):
    ALL = 'ALL'
    COLLECTION = 'COLLECTION'
    CONTAINER = 'CONTAINER'
    DATASET = 'DATASET'
    FILE = 'FILE'
    DERIVED = 'DERIVED'


class LifetimeExceptionsState(Enum):
    APPROVED = 'A'
    REJECTED = 'R'
    WAITING = 'W'


class LockState(Enum):
    REPLICATING = 'R'
    OK = 'O'
    STUCK = 'S'


class ReplicaState(Enum):
    AVAILABLE = 'A'
    UNAVAILABLE = 'U'
    COPYING = 'C'
    BEING_DELETED = 'B'
    BAD = 'D'
    TEMPORARY_UNAVAILABLE = 'T'


class RequestErrMsg(Enum):
    NO_SOURCES = 'NO_SOURCES'
    SUBMISSION_FAILED = 'SUBMISSION_FAILED'
    TRANSFER_FAILED = 'TRANSFER_FAILED'
    MISMATCH_SCHEME = 'MISMATCH_SCHEME'
    OTHER = 'OTHER'


class RequestState(Enum):
    QUEUED = 'Q'
    SUBMITTING = 'G'
    SUBMITTED = 'S'
    FAILED = 'F'
    DONE = 'D'
    LOST = 'L'
    NO_SOURCES = 'N'
    ONLY_TAPE_SOURCES = 'O'
    SUBMISSION_FAILED = 'A'
    MISMATCH_SCHEME = 'M'
    SUSPEND = 'U'
    WAITING = 'W'
    PREPARING = 'P'


class RequestType(Enum):
    TRANSFER = 'T'
    UPLOAD = 'U'
    DOWNLOAD = 'D'
    STAGEIN = 'I'
    STAGEOUT = 'O'


class RSEType(Enum):
    DISK = 'DISK'
    TAPE = 'TAPE'


class RuleGrouping(Enum):
    ALL = 'A'
    DATASET = 'D'
    NONE = 'N'


class RuleNotification(Enum):
    YES = 'Y'
    NO = 'N'
    CLOSE = 'C'
    PROGRESS = 'P'


class RuleState(Enum):
    REPLICATING = 'R'
    OK = 'O'
    STUCK = 'S'
    SUSPENDED = 'U'
    WAITING_APPROVAL = 'W'
    INJECT = 'I'


class ScopeStatus(Enum):
    OPEN = 'O'
    CLOSED = 'C'
    DELETED = 'D'


class SubscriptionState(Enum):
    ACTIVE = 'A'
    INACTIVE = 'I'
    NEW = 'N'
    UPDATED = 'U'
    BROKEN = 'B'
