# Copyright 2017-2019 CERN for the benefit of the ATLAS collaboration.
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
# - Vincent Garonne <vgaronne@gmail.com>, 2017
# - Eric Vaandering <ericvaandering@gmail.com>, 2018
# - sartiran <root@polgrid107.in2p3.fr>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Sartirana Andrea <sartiran@llr.in2p3.fr>, 2018
# - Martin Barisits <martin.barisits@cern.ch>, 2019
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Eli Chadwick <eli.chadwick@stfc.ac.uk>, 2020
#
# PY3K COMPATIBLE

from jsonschema import validate, ValidationError

from rucio.common.exception import InvalidObject


ACCOUNT_LENGTH = 25

ACCOUNT = {"description": "Account name",
           "type": "string",
           "pattern": "^[a-z0-9-_]{1,%s}$" % ACCOUNT_LENGTH}

ACCOUNTS = {"description": "Array of accounts",
            "type": "array",
            "items": ACCOUNT,
            "minItems": 0,
            "maxItems": 1000}


ACCOUNT_TYPE = {"description": "Account type",
                "type": "string",
                "enum": ["USER", "GROUP", "SERVICE"]}

ACTIVITY = {"description": "Activity name",
            "type": "string",
            "enum": ["Data Brokering", "Data Consolidation", "Data rebalancing",
                     "Debug", "Express", "Functional Test", "Group Subscriptions",
                     "Production Input", "Production Output",
                     "Analysis Input", "Analysis Output", "Staging",
                     "T0 Export", "T0 Tape", "Upload/Download (Job)",
                     "Upload/Download (User)", "User Subscriptions"]}

SCOPE_LENGTH = 25

SCOPE = {"description": "Scope name",
         "type": "string",
         "pattern": r"^(cms)|(user\.[a-z0-9-_]{1,%s})$" % (SCOPE_LENGTH - len('user.'))}

R_SCOPE = {"description": "Scope name",
           "type": "string",
           "pattern": "\\w"}

CMS_LFN_LENGTH = 500
CMS_DATASET_CORE = r'/[a-zA-Z0-9\-_]{1,99}/[a-zA-Z0-9\.\-_]{1,199}/[A-Z\-]{1,50}'
CMS_BLOCK_PART = r'[a-zA-Z0-9\.\-_]{1,100}'

CMS_DATASET = r'^%s$' % CMS_DATASET_CORE
CMS_BLOCK = r'^%s#%s$' % (CMS_DATASET_CORE, CMS_BLOCK_PART)  # Valid dataset name and block separated by #
CMS_LFN = r'^\/store\/[A-Za-z0-9][A-Za-z0-9\.\-\_\/]{1,%s}$' % (CMS_LFN_LENGTH - len('/store/'))

CMS_BLOCK_LENGTH = 100 + 200 + 51 + 101

NAME = {"description": "Data Identifier name",
        "type": "string",
        "pattern": r"%s|%s|%s" % (CMS_DATASET, CMS_BLOCK, CMS_LFN)}

NAME_LENGTH = max(CMS_LFN_LENGTH, CMS_BLOCK_LENGTH)

# read name
R_NAME = NAME

LOCKED = {"description": "Rule locked status",
          "type": ["boolean", "null"]}

ASK_APPROVAL = {"description": "Rule approval request",
                "type": ["boolean", "null"]}

ASYNCHRONOUS = {"description": "Asynchronous rule creation",
                "type": ["boolean", "null"]}

PURGE_REPLICAS = {"description": "Rule purge replica status",
                  "type": "boolean"}

IGNORE_AVAILABILITY = {"description": "Rule ignore availability status",
                       "type": "boolean"}

RSE = {"description": "RSE name",
       "type": "string",
       "pattern": "^T[0-3]_[A-Z]{2}((_[A-Za-z0-9]+)+)$"}

RSE_ATTRIBUTE = {"description": "RSE attribute",
                 "type": "string",
                 "pattern": r'([A-Za-z0-9\._-]+[=<>][A-Za-z0-9_-]+)'}

DEFAULT_RSE_ATTRIBUTE = {"description": "Default RSE attribute",
                         "type": "string",
                         "pattern": r'([A-Z0-9]+([_-][A-Za-z0-9]+)*)'}

REPLICA_STATE = {"description": "Replica state",
                 "type": "string",
                 "enum": ["AVAILABLE", "UNAVAILABLE", "COPYING", "BEING_DELETED", "BAD", "SOURCE", "A", "U", "C", "B", "D", "S"]}

DATE = {"description": "Date",
        "type": "string",
        "pattern": r'((Mon)|(Tue)|(Wed)|(Thu)|(Fri)|(Sat)|(Sun))[,]\s\d{2}\s(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d{4}\s(0\d|1\d|2[0-3])(\:)(0\d|1\d|2\d|3\d|4\d|5\d)(\:)(0\d|1\d|2\d|3\d|4\d|5\d)\s(UTC)'}

DID_TYPE = {"description": "DID type",
            "type": "string",
            "enum": ["DATASET", "CONTAINER", "FILE", "F"]}

GROUPING = {"description": "Rule grouping",
            "type": ["string", "null"],
            "enum": ["DATASET", "NONE", "ALL", None]}

NOTIFY = {"description": "Rule notification setting",
          "type": ["string", "null"],
          "enum": ["Y", "C", "N", "P", None]}

COMMENT = {"description": "Rule comment",
           "type": ["string", "null"],
           "maxLength": 250}

METADATA = {"description": "Rule wfms metadata",
            "type": ["string", "null"],
            "maxLength": 3999}

BYTES = {"description": "Size in bytes",
         "type": "integer"}

ADLER32 = {"description": "adler32",
           "type": "string",
           "pattern": "^[a-fA-F\\d]{8}$"}

WEIGHT = {"description": "Rule weight",
          "type": ["string", "null"]}

MD5 = {"description": "md5",
       "type": "string",
       "pattern": "^[a-fA-F\\d]{32}$"}

UUID = {"description": "Universally Unique Identifier (UUID)",
        "type": "string",
        "pattern": '^(\\{){0,1}[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}(\\}){0,1}$'}

META = {"description": "Data Identifier(DID) metadata",
        "type": "object",
        "properties": {"guid": UUID},
        "additionalProperties": True}

PFN = {"description": "Physical File Name", "type": "string"}

COPIES = {"description": "Number of replica copies", "type": "integer"}

RSE_EXPRESSION = {"description": "RSE expression", "type": "string"}

SOURCE_REPLICA_EXPRESSION = {"description": "RSE expression", "type": ["string", "null"]}

LIFETIME = {"description": "Lifetime", "type": "number"}

RULE_LIFETIME = {"description": "Rule lifetime", "type": ["number", "null"]}

SUBSCRIPTION_ID = {"description": "Rule Subscription id", "type": ["string", "null"]}

PRIORITY = {"description": "Priority of the transfers",
            "type": "integer"}

SPLIT_CONTAINER = {"description": "Rule split container mode",
                   "type": ["boolean", "null"]}

RULE = {"description": "Replication rule",
        "type": "object",
        "properties": {"dids": {"type": "array"},
                       "account": ACCOUNT,
                       "copies": COPIES,
                       "rse_expression": RSE_EXPRESSION,
                       "grouping": GROUPING,
                       "weight": WEIGHT,
                       "lifetime": RULE_LIFETIME,
                       "locked": LOCKED,
                       "subscription_id": SUBSCRIPTION_ID,
                       "source_replica_expression": SOURCE_REPLICA_EXPRESSION,
                       "activity": ACTIVITY,
                       "notify": NOTIFY,
                       "purge_replicas": PURGE_REPLICAS,
                       "ignore_availability": IGNORE_AVAILABILITY,
                       "comment": COMMENT,
                       "ask_approval": ASK_APPROVAL,
                       "asynchronous": ASYNCHRONOUS,
                       "priority": PRIORITY,
                       'split_container': SPLIT_CONTAINER,
                       'meta': METADATA},
        "required": ["dids", "copies", "rse_expression"],
        "additionalProperties": False}

RULES = {"description": "Array of replication rules",
         "type": "array",
         "items": RULE,
         "minItems": 1,
         "maxItems": 1000}

COLLECTION_TYPE = {"description": "Dataset or container type",
                   "type": "string",
                   "enum": ["DATASET", "CONTAINER"]}

COLLECTION = {"description": "Dataset or container",
              "type": "object",
              "properties": {"scope": SCOPE,
                             "name": NAME,
                             "type": COLLECTION_TYPE,
                             "meta": META,
                             "rules": RULES},
              "required": ["scope", "name", "type"],
              "additionalProperties": False}

COLLECTIONS = {"description": "Array of datasets or containers",
               "type": "array",
               "items": COLLECTION,
               "minItems": 1,
               "maxItems": 1000}

# No else if in JSON Schema
# if type == container
#      must match CMS dataset/container guidelines
# else if type == dataset
#      must match CMS block guidelines
# else if type == file
#      must match CMS LFN guidelines
#      CMS scope must not be in /store/user
#      user.jdoe scope must be in /store/user/rucio
#         (making sure it's in /store/user/rucio/jdoe seems to be impossible in JSON Schema, handled outside)
DID = {"description": "Data Identifier(DID)",
       "type": "object",
       "properties": {"scope": SCOPE,
                      "name": NAME,
                      "type": DID_TYPE,
                      "meta": META,
                      "rules": RULES,
                      "bytes": BYTES,
                      "adler32": ADLER32,
                      "md5": MD5,
                      "state": REPLICA_STATE,
                      "pfn": PFN},
       "allOf": [
           {"if": {"properties": {"type": {"const": "CONTAINER"}}},
            "then": {"properties": {"name": {"pattern": CMS_DATASET}}}},
           {"if": {"properties": {"type": {"const": "DATASET"}}},
            "then": {"properties": {"name": {"pattern": CMS_BLOCK}}}},
           {"if": {"properties": {"type": {"const": "FILE"}}},
            "then": {"properties": {"name": {"pattern": CMS_LFN}}}},
           {"if": {"properties": {"type": {"const": "F"}}},
            "then": {"properties": {"name": {"pattern": CMS_LFN}}}},
           {"if": {"allOf": [
               {"properties": {"scope": {"pattern": "^user\\."}}},
               {"properties": {"type": {"const": "FILE"}}},
           ], },
               "then": {"properties": {"name": {"pattern": "^/store/user/rucio/"}}}},
           {"if": {"properties": {"scope": {"const": "cms"}}},
            "then": {"properties": {"name": {"not": {"pattern": "^/store/user/"}}}}},
       ],
       "required": ["scope", "name", "type"],
       "additionalProperties": False}

DID_FILTERS = {"description": "Filters dictionary to list DIDs",
               "type": "object",
               "properties": {"created_before": DATE,
                              "created_afted": DATE},
               "additionalProperties": True}

R_DID = {"description": "Data Identifier(DID)",
         "type": "object",
         "properties": {"scope": R_SCOPE,
                        "name": R_NAME,
                        "type": DID_TYPE,
                        "meta": META,
                        "rules": RULES,
                        "bytes": BYTES,
                        "adler32": ADLER32,
                        "md5": MD5,
                        "state": REPLICA_STATE,
                        "pfn": PFN},
         "required": ["scope", "name"],
         "additionalProperties": False}

DIDS = {"description": "Array of Data Identifiers(DIDs)",
        "type": "array",
        "items": DID,
        "minItems": 1,
        "maxItems": 1000}

R_DIDS = {"description": "Array of Data Identifiers(DIDs)",
          "type": "array",
          "items": R_DID,
          "minItems": 1,
          "maxItems": 1000}

ATTACHMENT = {"description": "Attachement",
              "type": "object",
              "properties": {"scope": SCOPE,
                             "name": NAME,
                             "rse": {"description": "RSE name",
                                     "type": ["string", "null"],
                                     "pattern": "^T[0-3]_[A-Z]{2}((_[A-Za-z0-9]+)+)$"},
                             "dids": R_DIDS},  # Loosen up, we're not creating these DIDs
              "required": ["dids"],
              "additionalProperties": False}

ATTACHMENTS = {"description": "Array of attachments",
               "type": "array",
               "items": ATTACHMENT,
               "minItems": 1,
               "maxItems": 1000}

SUBSCRIPTION_FILTER = {"type": "object",
                       "properties": {"datatype": {"type": "array"},
                                      "prod_step": {"type": "array"},
                                      "stream_name": {"type": "array"},
                                      "project": {"type": "array"},
                                      "scope": {"type": "array"},
                                      "pattern": {"type": "string"},
                                      "excluded_pattern": {"type": "string"},
                                      "group": {"type": "string"},
                                      "provenance": {"type": "string"},
                                      "account": ACCOUNTS,
                                      "grouping": {"type": "string"},
                                      "split_rule": {"type": "boolean"}}}

ADD_REPLICA_FILE = {"description": "add replica file",
                    "type": "object",
                    "properties": {"scope": SCOPE,
                                   "name": NAME,
                                   "bytes": BYTES,
                                   "adler32": ADLER32},
                    "required": ["scope", "name", "bytes", "adler32"]}

ADD_REPLICA_FILES = {"description": "add replica files",
                     "type": "array",
                     "items": ADD_REPLICA_FILE,
                     "minItems": 1,
                     "maxItems": 1000}

CACHE_ADD_REPLICAS = {"description": "rucio cache add replicas",
                      "type": "object",
                      "properties": {"files": ADD_REPLICA_FILES,
                                     "rse": RSE,
                                     "lifetime": LIFETIME,
                                     "operation": {"enum": ["add_replicas"]}},
                      "required": ['files', 'rse', 'lifetime', 'operation']}

DELETE_REPLICA_FILE = {"description": "delete replica file",
                       "type": "object",
                       "properties": {"scope": SCOPE,
                                      "name": NAME},
                       "required": ["scope", "name"]}

DELETE_REPLICA_FILES = {"description": "delete replica files",
                        "type": "array",
                        "items": DELETE_REPLICA_FILE,
                        "minItems": 1,
                        "maxItems": 1000}

CACHE_DELETE_REPLICAS = {"description": "rucio cache delete replicas",
                         "type": "object",
                         "properties": {"files": DELETE_REPLICA_FILES,
                                        "rse": RSE,
                                        "operation": {"enum": ["delete_replicas"]}},
                         "required": ['files', 'rse', 'operation']}

MESSAGE_OPERATION = {"type": "object",
                     "properties": {'operation': {"enum": ["add_replicas", "delete_replicas"]}}}

ACCOUNT_ATTRIBUTE = {"description": "Account attribute",
                     "type": "string",
                     "pattern": r'^[a-zA-Z0-9-_\\/\\.]{1,30}$'}

SCOPE_NAME_REGEXP = '/([^/]*)(?=/)(.*)'

DISTANCE = {"description": "RSE distance",
            "type": "object",
            "properties": {
                "src_rse_id": {"type": "string"},
                "dest_rse_id": {"type": "string"},
                "ranking": {"type": "integer"}
            },
            "required": ["src_rse_id", "dest_rse_id", "ranking"],
            "additionalProperties": True}

IMPORT = {"description": "import data into rucio.",
          "type": "object",
          "properties": {
              "rses": {
                  "type": "object"
              },
              "distances": {
                  "type": "object"
              }
          }}

SCHEMAS = {'account': ACCOUNT,
           'account_type': ACCOUNT_TYPE,
           'activity': ACTIVITY,
           'name': NAME,
           'r_name': R_NAME,
           'rse': RSE,
           'rse_attribute': RSE_ATTRIBUTE,
           'scope': SCOPE,
           'r_scope': R_SCOPE,
           'did': DID,
           'did_filters': DID_FILTERS,
           'r_did': R_DID,
           'dids': DIDS,
           'rule': RULE,
           'r_dids': R_DIDS,
           'collection': COLLECTION,
           'collections': COLLECTIONS,
           'attachment': ATTACHMENT,
           'attachments': ATTACHMENTS,
           'subscription_filter': SUBSCRIPTION_FILTER,
           'cache_add_replicas': CACHE_ADD_REPLICAS,
           'cache_delete_replicas': CACHE_DELETE_REPLICAS,
           'account_attribute': ACCOUNT_ATTRIBUTE,
           'import': IMPORT}


def validate_schema(name, obj):
    """
    Validate object against json schema

    :param name: The json schema name.
    :param obj: The object to validate.
    """
    try:
        if obj:
            validate(obj, SCHEMAS.get(name, {}))
    except ValidationError as error:  # NOQA, pylint: disable=W0612
        raise InvalidObject("Problem validating %(name)s : %(error)s" % locals())

    # Apply some extra constraints to CMS DIDs
    if name.lower() in ['did']:
        validate_cms_did(obj)
    elif name.lower() in ['dids']:
        for did in obj:
            validate_cms_did(did)


def validate_cms_did(obj):
    """
    Special checking for DIDs
    Most of the checking is done with JSON schema, but this check
    makes sure user LFNs are in the correct /store/user/rucio/USERNAME namespace
    """
    if not obj:
        return

    lfn = obj['name']
    did_type = obj['type']
    scope = obj['scope']
    if scope.startswith('user.') and did_type == 'FILE':
        _, user = scope.split('.', 1)
        if not lfn.startswith('/store/user/rucio/%s/' % user):
            raise InvalidObject("Problem with LFN %(lfn)s : Not allowed for user %(user)s" % locals())
