# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

import enum
from collections import namedtuple

from rucio.common.config import config_get_bool

"""
Constants.

"""

RESERVED_KEYS = ['scope', 'name', 'account', 'did_type', 'is_open', 'monotonic', 'obsolete', 'complete',
                 'availability', 'suppressed', 'bytes', 'length', 'md5', 'adler32', 'rule_evaluation_action',
                 'rule_evaluation_required', 'expired_at', 'deleted_at', 'created_at', 'updated_at']
# collection_keys =
# file_keys =

KEY_TYPES = ['ALL', 'COLLECTION', 'FILE', 'DERIVED']
# all(container, dataset, file), collection(dataset or container), file, derived(compute from file for collection)

SCHEME_MAP = {'srm': ['srm', 'gsiftp'],
              'gsiftp': ['srm', 'gsiftp'],
              'https': ['https', 'davs', 'srm+https', 'cs3s'],
              'davs': ['https', 'davs', 'srm+https', 'cs3s'],
              'srm+https': ['https', 'davs', 'srm+https', 'cs3s'],
              'cs3s': ['https', 'davs', 'srm+https', 'cs3s'],
              'root': ['root'],
              'scp': ['scp'],
              'rsync': ['rsync'],
              'rclone': ['rclone']}
if config_get_bool('transfers', 'srm_https_compatibility', raise_exception=False, default=False):
    SCHEME_MAP['srm'].append('https')
    SCHEME_MAP['https'].append('srm')
    SCHEME_MAP['srm'].append('davs')
    SCHEME_MAP['davs'].append('srm')

SUPPORTED_PROTOCOLS = ['gsiftp', 'srm', 'root', 'davs', 'http', 'https', 'file', 'storm', 'srm+https', 'scp', 'rsync', 'rclone', 'magnet']

FTS_STATE = namedtuple('FTS_STATE', ['SUBMITTED', 'READY', 'ACTIVE', 'FAILED', 'FINISHED', 'FINISHEDDIRTY', 'NOT_USED',
                                     'CANCELED'])('SUBMITTED', 'READY', 'ACTIVE', 'FAILED', 'FINISHED', 'FINISHEDDIRTY',
                                                  'NOT_USED', 'CANCELED')

FTS_COMPLETE_STATE = namedtuple('FTS_COMPLETE_STATE', ['OK', 'ERROR'])('Ok', 'Error')

# https://gitlab.cern.ch/fts/fts3/-/blob/master/src/db/generic/Job.h#L41
FTS_JOB_TYPE = namedtuple('FTS_JOB_TYPE', ['MULTIPLE_REPLICA', 'MULTI_HOP', 'SESSION_REUSE', 'REGULAR'])('R', 'H', 'Y', 'N')


# Messages constants

MAX_MESSAGE_LENGTH = 4000


class SuspiciousAvailability(enum.Enum):
    ALL = 0
    EXIST_COPIES = 1
    LAST_COPY = 2


class ReplicaState(enum.Enum):
    # From rucio.db.sqla.constants, update that file at the same time as this
    AVAILABLE = 'A'
    UNAVAILABLE = 'U'
    COPYING = 'C'
    BEING_DELETED = 'B'
    BAD = 'D'
    TEMPORARY_UNAVAILABLE = 'T'


@enum.unique
class HermesService(str, enum.Enum):
    """
    The services supported by Hermes2.
    """
    INFLUX = "INFLUX"
    ELASTIC = "ELASTIC"
    EMAIL = "EMAIL"
    ACTIVEMQ = "ACTIVEMQ"
