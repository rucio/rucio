# -*- coding: utf-8 -*-
# Copyright 2013-2021 CERN
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2013-2015
# - Cedric Serfon <cedric.serfon@cern.ch>, 2015-2021
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2018-2021
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Sahan Dilshan <32576163+sahandilshan@users.noreply.github.com>, 2021
# - David Población Criado <david.poblacion.criado@cern.ch>, 2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021
# - Rakshita Varadarajan <rakshitajps@gmail.com>, 2021
# - Joel Dierkes <joel.dierkes@cern.ch>, 2021
# - Christoph Ames <christoph.ames@cern.ch>, 2021

from collections import namedtuple
from enum import Enum

from rucio.common.config import config_get

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
              'https': ['https', 'davs', 's3', 'srm+https'],
              'davs': ['https', 'davs', 's3', 'srm+https'],
              'root': ['root'],
              's3': ['https', 'davs', 's3', 'srm+https'],
              'srm+https': ['https', 'davs', 's3', 'srm+https'],
              'scp': ['scp'],
              'rsync': ['rsync'],
              'rclone': ['rclone']}
if config_get('transfers', 'srm_https_compatibility', raise_exception=False, default=False):
    SCHEME_MAP['srm'].append('https')
    SCHEME_MAP['https'].append('srm')
    SCHEME_MAP['srm'].append('davs')
    SCHEME_MAP['davs'].append('srm')

SUPPORTED_PROTOCOLS = ['gsiftp', 'srm', 'root', 'davs', 'http', 'https', 'file', 's3', 's3+rucio', 's3+https', 'storm', 'srm+https', 'scp', 'rsync', 'rclone']

FTS_STATE = namedtuple('FTS_STATE', ['SUBMITTED', 'READY', 'ACTIVE', 'FAILED', 'FINISHED', 'FINISHEDDIRTY', 'NOT_USED',
                                     'CANCELED'])('SUBMITTED', 'READY', 'ACTIVE', 'FAILED', 'FINISHED', 'FINISHEDDIRTY',
                                                  'NOT_USED', 'CANCELED')

FTS_COMPLETE_STATE = namedtuple('FTS_COMPLETE_STATE', ['OK', 'ERROR'])('Ok', 'Error')

# https://gitlab.cern.ch/fts/fts3/-/blob/master/src/db/generic/Job.h#L41
FTS_JOB_TYPE = namedtuple('FTS_JOB_TYPE', ['MULTIPLE_REPLICA', 'MULTI_HOP', 'SESSION_REUSE', 'REGULAR'])('R', 'H', 'Y', 'N')


class SuspiciousAvailability(Enum):
    ALL = 0
    EXIST_COPIES = 1
    LAST_COPY = 2


class ReplicaState(Enum):
    # From rucio.db.sqla.constants, update that file at the same time as this
    AVAILABLE = 'A'
    UNAVAILABLE = 'U'
    COPYING = 'C'
    BEING_DELETED = 'B'
    BAD = 'D'
    TEMPORARY_UNAVAILABLE = 'T'
