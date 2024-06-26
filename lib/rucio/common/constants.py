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
from typing import Literal, get_args

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

SUPPORTED_PROTOCOLS_LITERAL = Literal['gsiftp', 'srm', 'root', 'davs', 'http', 'https', 'file', 'storm', 'srm+https', 'scp', 'rsync', 'rclone', 'magnet']
SUPPORTED_PROTOCOLS = list(get_args(SUPPORTED_PROTOCOLS_LITERAL))

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


class RseAttr:

    """
    List of functional RSE attributes.

    This class acts as a namespace containing all RSE attributes referenced in
    the Rucio source code. Setting them affects Rucio's behaviour in some way.
    """

    ARCHIVE_TIMEOUT = 'archive_timeout'
    ASSOCIATED_SITES = 'associated_sites'
    AUTO_APPROVE_BYTES = 'auto_approve_bytes'
    AUTO_APPROVE_FILES = 'auto_approve_files'
    BITTORRENT_TRACKER_ADDR = 'bittorrent_tracker_addr'
    BLOCK_MANUAL_APPROVAL = 'block_manual_approval'
    COUNTRY = 'country'
    DECOMMISSION = 'decommission'
    DEFAULT_ACCOUNT_LIMIT_BYTES = 'default_account_limit_bytes'
    FTS = 'fts'
    GLOBUS_ENDPOINT_ID = 'globus_endpoint_id'
    GREEDYDELETION = 'greedyDeletion'
    IS_OBJECT_STORE = 'is_object_store'
    LFN2PFN_ALGORITHM = 'lfn2pfn_algorithm'
    MAXIMUM_PIN_LIFETIME = 'maximum_pin_lifetime'
    MULTIHOP_TOMBSTONE_DELAY = 'multihop_tombstone_delay'
    NAMING_CONVENTION = 'naming_convention'
    OIDC_BASE_PATH = 'oidc_base_path'
    OIDC_SUPPORT = 'oidc_support'
    PHYSGROUP = 'physgroup'
    QBITTORRENT_MANAGEMENT_ADDRESS = 'qbittorrent_management_address'
    RESTRICTED_READ = 'restricted_read'
    RESTRICTED_WRITE = 'restricted_write'
    RULE_APPROVERS = 'rule_approvers'
    S3_URL_STYLE = 's3_url_style'
    SIGN_URL = 'sign_url'
    SIMULATE_MULTIRANGE = 'simulate_multirange'
    SITE = 'site'
    SKIP_UPLOAD_STAT = 'skip_upload_stat'
    SOURCE_FOR_TOTAL_SPACE = 'source_for_total_space'
    SOURCE_FOR_USED_SPACE = 'source_for_used_space'
    STAGING_BUFFER = 'staging_buffer'
    STAGING_REQUIRED = 'staging_required'
    STRICT_COPY = 'strict_copy'
    TOMBSTONE_DELAY = 'tombstone_delay'
    TYPE = 'type'
    USE_IPV4 = 'use_ipv4'
    VERIFY_CHECKSUM = 'verify_checksum'

    # The following RSE attributes are exclusively used in the permission layer
    # and are likely VO-specific.

    BLOCK_MANUAL_APPROVE = 'block_manual_approve'
    CMS_TYPE = 'cms_type'
    DEFAULT_LIMIT_FILES = 'default_limit_files'
    QUOTA_APPROVERS = 'quota_approvers'
    RULE_DELETERS = 'rule_deleters'
