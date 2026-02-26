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
import sys
from collections import namedtuple
from typing import Literal, Union, get_args

"""
Constants.

"""

RESERVED_KEYS = ['scope', 'name', 'account', 'did_type', 'is_open', 'monotonic', 'obsolete', 'complete',
                 'availability', 'suppressed', 'bytes', 'length', 'md5', 'adler32', 'rule_evaluation_action',
                 'rule_evaluation_required', 'expired_at', 'deleted_at', 'created_at', 'updated_at']
# collection_keys =
# file_keys =

DEFAULT_VO = 'def'

DEFAULT_ACTIVITY = 'User Subscriptions'

KEY_TYPES = ['ALL', 'COLLECTION', 'FILE', 'DERIVED']
# all(container, dataset, file), collection(dataset or container), file, derived(compute from file for collection)

BASE_SCHEME_MAP = {'srm': ['srm', 'gsiftp'],
                   'gsiftp': ['srm', 'gsiftp'],
                   'https': ['https', 'davs', 'srm+https', 'cs3s'],
                   'davs': ['https', 'davs', 'srm+https', 'cs3s'],
                   'srm+https': ['https', 'davs', 'srm+https', 'cs3s'],
                   'cs3s': ['https', 'davs', 'srm+https', 'cs3s'],
                   'root': ['root'],
                   'scp': ['scp'],
                   'rsync': ['rsync'],
                   'rclone': ['rclone']}

SORTING_ALGORITHMS_LITERAL = Literal['geoip', 'custom_table', 'random']
SORTING_ALGORITHMS = list(get_args(SORTING_ALGORITHMS_LITERAL))

SUPPORTED_PROTOCOLS_LITERAL = Literal['gsiftp', 'srm', 'root', 'davs', 'http', 'https', 'file', 'storm', 'srm+https', 'scp', 'rsync', 'rclone', 'magnet']
SUPPORTED_PROTOCOLS: list[str] = list(get_args(SUPPORTED_PROTOCOLS_LITERAL))

RSE_SUPPORTED_PROTOCOL_DOMAINS_LITERAL = Literal['ALL', 'LAN', 'WAN']

RSE_BASE_SUPPORTED_PROTOCOL_OPERATIONS_LITERAL = Literal['read', 'write', 'delete']
RSE_BASE_SUPPORTED_PROTOCOL_OPERATIONS: list[str] = list(get_args(RSE_BASE_SUPPORTED_PROTOCOL_OPERATIONS_LITERAL))

RSE_ALL_SUPPORTED_PROTOCOL_OPERATIONS_LITERAL = Literal[RSE_BASE_SUPPORTED_PROTOCOL_OPERATIONS_LITERAL, 'third_party_copy_read', 'third_party_copy_write']
RSE_ALL_SUPPORTED_PROTOCOL_OPERATIONS: list[str] = list(get_args(RSE_ALL_SUPPORTED_PROTOCOL_OPERATIONS_LITERAL))

IMPORTER_SYNC_METHODS_LITERAL = Literal['append', 'edit', 'hard']
IMPORTER_SYNC_METHODS: list[str] = list(get_args(IMPORTER_SYNC_METHODS_LITERAL))

FTS_STATE = namedtuple('FTS_STATE', ['SUBMITTED', 'READY', 'ACTIVE', 'FAILED', 'FINISHED', 'FINISHEDDIRTY', 'NOT_USED',
                                     'CANCELED'])('SUBMITTED', 'READY', 'ACTIVE', 'FAILED', 'FINISHED', 'FINISHEDDIRTY',
                                                  'NOT_USED', 'CANCELED')

FTS_COMPLETE_STATE = namedtuple('FTS_COMPLETE_STATE', ['OK', 'ERROR'])('Ok', 'Error')

# https://gitlab.cern.ch/fts/fts3/-/blob/master/src/db/generic/Job.h#L41
FTS_JOB_TYPE = namedtuple('FTS_JOB_TYPE', ['MULTIPLE_REPLICA', 'MULTI_HOP', 'SESSION_REUSE', 'REGULAR'])('R', 'H', 'Y', 'N')


# Messages constants

MAX_MESSAGE_LENGTH = 4000


@enum.unique
class TransferLimitDirection(enum.Enum):
    SOURCE = 'S'
    DESTINATION = 'D'


@enum.unique
class SuspiciousAvailability(enum.Enum):
    ALL = 0
    EXIST_COPIES = 1
    LAST_COPY = 2


@enum.unique
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


class RSEAttrObj(str):
    def __init__(self, name: str, type_: Union[type[str], type[bool]], doc: str):
        """
        Representation of the strings used in RSE Attributes. Includes the type and a description.

        name : str name of the object
        type_ : str or bool type
        doc : docstring describing the attribute [used for documentation only]
        """
        self.name = name
        self.type_ = type_
        self.doc = doc

    # Allows the
    def __new__(cls, name: str, type_: Union[type[str], type[bool]] = str, doc: str = "") -> 'RSEAttrObj':
        return super().__new__(cls, name)


class RseAttr:

    """
    List of functional RSE attributes.

    This class acts as a namespace containing all RSE attributes referenced in
    the Rucio source code. Setting them affects Rucio's behaviour in some way.
    """
    ARCHIVE_TIMEOUT = RSEAttrObj(
        name='archive_timeout',
        type_=str,
        doc=(
            "Only used for transfers with a tape destination. Controls the number "
            "of seconds the FTS3 transfer manager will wait for the tape archival "
            "of the file to go `FAILED` or `FINISHED`.\n"
            "Default: *None* (no default)."
        ),
    )

    ASSOCIATED_SITES = RSEAttrObj(
        name='associated_sites',
        type_=str,
        doc=(
            "Separated by commas. Used for chaining of subscriptions so that "
            "transfers to one RSE will also be mirrored to associated_sites.\n"
            "Default: *None* (no default)."
        ),
    )

    AUTO_APPROVE_BYTES = RSEAttrObj(
        name='auto_approve_bytes',
        type_=str,
        doc=(
            "Upper limit for the size in bytes of a DID for which rules will be "
            "automatically approved. Example: `500GB`.\n"
            "Default: *None* (no default)."
        ),
    )

    AUTO_APPROVE_FILES = RSEAttrObj(
        name='auto_approve_files',
        type_=str,
        doc=(
            "Upper limit for the number of files covered by a rule which will be "
            "automatically approved.\n"
            "Default: *None* (no default)."
        ),
    )

    BLOCK_MANUAL_APPROVAL = RSEAttrObj(
        name='block_manual_approval',
        type_=bool,
        doc=(
            "Disable manual rule approval for this RSE.\n"
            "Default: ``False``."
        ),
    )

    BITTORRENT_TRACKER_ADDR = RSEAttrObj(
        name='bittorrent_tracker_addr',
        type_=str,
        doc=(
            "Used to configure the URL of the bittorrent tracker API when using the "
            "torrent transfer manager.\n"
            "Default: *None* (no default)."
        ),
    )

    CHECKSUM_KEY = RSEAttrObj(
        name='checksum_key',
        type_=str,
        doc=(
            "Used to specify an alternate RSE attribute to search for supported "
            "checksums beyond those with global support (ADLER32, MD5).\n"
            "Default: ``supported_checksums``."
        ),
    )

    COUNTRY = RSEAttrObj(
        name='country',
        type_=str,
        doc=(
            "Used for country‑level granularity of RSE selectors.\n"
            "Default: *None* (no default)."
        ),
    )

    DECOMMISSION = RSEAttrObj(
        name='decommission',
        type_=bool,
        doc=(
            "Indicates to the RSE Decommissioning Daemon that this RSE is to be "
            "decommissioned.\n"
            "Default: ``False``."
        ),
    )

    DEFAULT_ACCOUNT_LIMIT_BYTES = RSEAttrObj('default_account_limit_bytes', str, "")

    FTS = RSEAttrObj(
        name='fts',
        type_=str,
        doc=(
            "Specify the REST API URL of the FTS3 transfer manager.\n"
            "Default: *None* (no default)."
        ),
    )

    GREEDYDELETION = RSEAttrObj(
        name='greedyDeletion',
        type_=bool,
        doc=(
            "Allow files without a rule locking them to be deleted by a Reaper daemon. "
            "Default behaviour only marks a file for deletion when there is no space "
            "on an RSE for a new required file.\n"
            "Default: ``False``."
        ),
    )

    GLOBUS_ENDPOINT_ID = RSEAttrObj(
        name='globus_endpoint_id',
        type_=str,
        doc=(
            "Specify the REST API URL of the Globus transfer manager.\n"
            "Default: *None* (no default)."
        ),
    )

    HOP_PENALTY = RSEAttrObj(
        name='hop_penalty',
        type_=str,
        doc=(
            "Usage cost of this RSE as an intermediate in multihop transfers. Overrides "
            "the global ``transfers/hop_penalty`` configuration for this particular RSE.\n"
            "Requires ``available_for_multihop`` to be ``True``.\n"
            "Default: *None* (no default)."
        ),
    )

    IS_OBJECT_STORE = RSEAttrObj(
        name='is_object_store',
        type_=bool,
        doc=(
            "Control the auditor daemon's behavior. Instead of dumping all files, list "
            "them by date.\n"
            "Default: ``False``."
        ),
    )

    LFN2PFN_ALGORITHM = RSEAttrObj(
        name='lfn2pfn_algorithm',
        type_=str,
        doc=(
            "Name of the algorithm to be used for generating paths to files on the "
            "storage. Must be defined in the configured policy package.\n"
            "Default: ``default``."
        ),
    )
    MAXIMUM_PIN_LIFETIME = RSEAttrObj('maximum_pin_lifetime', type_=str, doc='')

    MOCK = RSEAttrObj(
        name='mock',
        type_=bool,
        doc=(
            "Flag used for test/mock RSEs.\n"
            "Default: ``False``."
        ),
    )

    MULTIHOP_TOMBSTONE_DELAY = RSEAttrObj(
        name='multihop_tombstone_delay',
        type_=str,
        doc=(
            "Delay before a multihop transfer intermediate rule is to be deleted (seconds).\n"
            "Default: ``7200``."
        ),
    )

    NAMING_CONVENTION = RSEAttrObj(
        name='naming_convention',
        type_=str,
        doc=(
            "Name of the algorithm in the configured policy package which is to be used "
            "to validate DIDs on this RSE.\n"
            "Default: ``None``."
        ),
    )

    OIDC_SUPPORT = RSEAttrObj(
        name='oidc_support',
        type_=bool,
        doc=(
            "Specifies that the RSE supports OIDC authentication for FTS3 transfers.\n"
            "Default: ``False``."
        ),
    )

    PHYSGROUP = RSEAttrObj(
        name='physgroup',
        type_=str,
        doc=(
            "Used for grouping of rules by CERN experiments.\n"
            "Default: ``.``."
        ),
    )

    QBITTORRENT_MANAGEMENT_ADDRESS = RSEAttrObj(
        name='qbittorrent_management_address',
        type_=str,
        doc=(
            "Used to configure the URL of the bittorrent management API when using the "
            "torrent transfer manager.\n"
            "Default: *None* (no default)."
        ),
    )

    QUOTA_APPROVERS = RSEAttrObj(
        name='quota_approvers',
        type_=str,
        doc=(
            "List of Rucio users (comma‑separated) that can approve quota changes. "
            "Permission‑layer only; typically CERN‑specific.\n"
            "Default: ``None``."
        ),
    )

    RESTRICTED_READ = RSEAttrObj(
        name='restricted_read',
        type_=bool,
        doc=(
            "If ``True``, only allow transfers **FROM** this RSE if started by an account "
            "with admin privileges.\n"
            "Default: ``False``."
        ),
    )

    RESTRICTED_WRITE = RSEAttrObj(
        name='restricted_write',
        type_=bool,
        doc=(
            "If ``True``, only allow transfers **TO** this RSE if started by an account "
            "with admin privileges.\n"
            "Default: ``False``."
        ),
    )

    RULE_APPROVERS = RSEAttrObj(
        name='rule_approvers',
        type_=str,
        doc=(
            "List of Rucio users (comma‑separated) that will be notified by email to approve "
            "rules on this RSE.\n"
            "Default: ``None``."
        ),
    )

    RULE_DELETERS = RSEAttrObj(
        name='rule_deleters',
        type_=str,
        doc=(
            "List of Rucio users (comma‑separated) that can delete rules. Permission‑layer only; "
            "typically CERN‑specific.\n"
            "Default: ``None``."
        ),
    )

    SIGN_URL = RSEAttrObj(
        name='sign_url',
        type_=str,
        doc=(
            "Controls if URLs for uploads and transfers are to be cryptographically signed "
            "by an external service.\n"
            "Default: *None* (no default)."
        ),
    )

    SIMULATE_MULTIRANGE = RSEAttrObj(
        name='simulate_multirange',
        type_=str,
        doc=(
            "Control the number of connections for multirange byte requests on commercial cloud "
            "storage. Multirange is not supported on S3.\n"
            "Default: *None* (no default)."
        ),
    )

    SITE = RSEAttrObj(
        name='site',
        type_=str,
        doc=(
            "Used to determine if downloads/transfers are local or wide‑area network.\n"
            "Default: *None* (no default)."
        ),
    )

    SKIP_UPLOAD_STAT = RSEAttrObj(
        name='skip_upload_stat',
        type_=bool,
        doc=(
            "Disables the use of a GFAL ``stat`` when calling ``rucio upload`` for this RSE.\n"
            "Default: ``False``."
        ),
    )

    SOURCE_FOR_TOTAL_SPACE = RSEAttrObj(
        name='source_for_total_space',
        type_=str,
        doc=(
            "Used to specify where Rucio should obtain storage capacity information from.\n"
            "Default: ``storage``."
        ),
    )

    SOURCE_FOR_USED_SPACE = RSEAttrObj(
        name='source_for_used_space',
        type_=str,
        doc=(
            "Used to specify where Rucio should obtain storage usage information from.\n"
            "Default: ``storage``."
        ),
    )

    STAGING_BUFFER = RSEAttrObj(
        name='staging_buffer',
        type_=str,
        doc=(
            "Used with ``TAPE`` RSEs to specify to which RSE a file on tape should be "
            "transferred to as a disk buffer. Destination RSE should have ``staging_area: True``.\n"
            "Default: *None* (no default)."
        ),
    )

    STAGING_REQUIRED = RSEAttrObj(
        name='staging_required',
        type_=bool,
        doc=(
            "Duplicates the ``rse_type`` RSE setting. Specifies that files on this RSE will "
            "require staging from high‑latency storage.\n"
            "Default: ``False``."
        ),
    )

    STRICT_COPY = RSEAttrObj(
        name='strict_copy',
        type_=bool,
        doc=(
            "Instructs the transfer manager to **ONLY** copy the file, disabling all validation "
            "checks such as ``PROPFIND`` and checksumming.\n"
            "Default: ``False``."
        ),
    )

    S3_URL_STYLE = RSEAttrObj(
        name='s3_url_style',
        type_=str,
        doc=(
            "For S3 storage elements [specify](https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html) `path` or `host`."
            "Default: *None* (no default)."
        ),
    )

    TIER = RSEAttrObj(
        name='tier',
        type_=str,
        doc=(
            "Datacenter tier (1‑4).\n"
            "Default: *None* (no default)."
        ),
    )

    TOMBSTONE_DELAY = RSEAttrObj(name='tombstone_delay', type_=str, doc='Delay before a rule is to be deleted (seconds)')

    TYPE = RSEAttrObj(
        name='type',
        type_=str,
        doc=(
            "Values: ``{LOCALGROUPDISK, LOCALGROUPTAPE, GROUPDISK, SCRATCHDISK, MOCK, "
            "TEST, DATADISK}``.\n"
            "Default: ``.``."
        ),
    )

    USE_IPV4 = RSEAttrObj(
        name='use_ipv4',
        type_=bool,
        doc=(
            "Force the transfer manager to use IPv4 for transfers to this RSE.\n"
            "Default: ``False``."
        ),
    )

    VERIFY_CHECKSUM = RSEAttrObj(
        name='verify_checksum',
        type_=bool,
        doc=(
            "Control if checksum is to be queried on transfer source and destination to "
            "confirm successful transfers.\n"
            "Default: ``True``."
        ),
    )

    # VO Specific

    BLOCK_MANUAL_APPROVE = RSEAttrObj(
        name='block_manual_approve',
        type_=bool,
        doc=(
            "VO‑specific duplicate of ``block_manual_approval``.\n"
            "Default: ``False``."
        ),
    )

    CMS_TYPE = RSEAttrObj(
        name='cms_type',
        type_=str,
        doc=(
            "VO‑specific attribute used by CMS.\n"
            "Default: *None* (no default)."
        ),
    )

    DEFAULT_LIMIT_FILES = RSEAttrObj(
        name='default_limit_files',
        type_=str,
        doc=(
            "VO‑specific default limit on number of files.\n"
            "Default: *None* (no default)."
        ),
    )
    OIDC_BASE_PATH = RSEAttrObj(name="oidc_base_path", type_=str, doc="")



# Literal types to allow overloading of functions with RSE attributes in their signature.
# RSE attributes are encoded via the BooleanString decorator as VARCHAR in the database,
# but they are used as either bool or string in the code.
# This is only determined at runtime, so for static type checking
# we need to manually specify which attrs are string and which are bool.
str_like_attrs = [attr for attr in RseAttr.__dict__.values() if isinstance(attr, RSEAttrObj) and attr.type_ is str]
RSE_ATTRS_STR = Literal[str_like_attrs]

bool_like_attrs = [attr for attr in RseAttr.__dict__.values() if isinstance(attr, RSEAttrObj) and attr.type_ is bool]
RSE_ATTRS_BOOL = Literal[bool_like_attrs]

SUPPORTED_SIGN_URL_SERVICES_LITERAL = Literal['gcs', 's3', 'swift']
SUPPORTED_SIGN_URL_SERVICES = list(get_args(SUPPORTED_SIGN_URL_SERVICES_LITERAL))

OPENDATA_DID_STATE_LITERAL = Literal['draft', 'public', 'suspended']
OPENDATA_DID_STATE_LITERAL_LIST = list(get_args(OPENDATA_DID_STATE_LITERAL))

POLICY_ALGORITHM_TYPES_LITERAL = Literal['non_deterministic_pfn', 'scope', 'lfn2pfn', 'pfn2lfn', 'fts3_tape_metadata_plugins', 'fts3_plugins_init', 'auto_approve']
POLICY_ALGORITHM_TYPES = list(get_args(POLICY_ALGORITHM_TYPES_LITERAL))

# https://github.com/rucio/rucio/issues/7958
# When Python 3.11 is the minimum supported version, we can use the standard library enum and remove this logic
if sys.version_info >= (3, 11):
    from http import HTTPMethod
else:
    @enum.unique
    class HTTPMethod(str, enum.Enum):
        """HTTP verbs used in Rucio requests."""

        HEAD = "HEAD"
        OPTIONS = "OPTIONS"
        PATCH = "PATCH"
        GET = "GET"
        POST = "POST"
        PUT = "PUT"
        DELETE = "DELETE"
