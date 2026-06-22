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

from rucio.common.schema.schema_ref import SchemaRef

ACCOUNT_LENGTH = 25

ACCOUNT = {"description": "Account name",
           "type": "string",
           "maxLength": SchemaRef("ACCOUNT_LENGTH"),
           "pattern": "^[a-z0-9-_]+$"}

ACCOUNTS = {"description": "Array of accounts",
            "type": "array",
            "items": SchemaRef("ACCOUNT"),
            "minItems": 0,
            "maxItems": 1000}


ACCOUNT_TYPE = {"description": "Account type",
                "type": "string",
                "enum": ["USER", "GROUP", "SERVICE"]}

ACTIVITY = {"description": "Activity name",
            "type": "string",
            "enum": ["Data Brokering", "Data Consolidation", "Data Rebalancing",
                     "Debug", "Express", "Functional Test", "Group Subscriptions",
                     "Production Input", "Production Output",
                     "Analysis Input", "Analysis Output", "Staging",
                     "T0 Export", "T0 Tape", "Upload/Download (Job)",
                     "Upload/Download (User)", "User Subscriptions", "Data Challenge"]}

SCOPE_LENGTH = 25

SCOPE = {"description": "Scope name",
         "type": "string",
         "maxLength": SchemaRef("SCOPE_LENGTH"),
         "pattern": "^[a-zA-Z_\\-.0-9]+$"}

R_SCOPE = {"description": "Scope name",
           "type": "string",
           "pattern": "\\w"}

NAME_LENGTH = 250

NAME = {"description": "Data Identifier name",
        "type": "string",
        "maxLength": SchemaRef("NAME_LENGTH"),
        "pattern": r"^[/A-Za-z0-9][/A-Za-z0-9\.\-_]*$"}

R_NAME = {"description": "Data Identifier name",
          "type": "string",
          "pattern": "\\w"}

LOCKED = {"description": "Rule locked status",
          "type": ["boolean", "null"]}

ASK_APPROVAL = {"description": "Rule approval request",
                "type": ["boolean", "null"]}

ASYNCHRONOUS = {"description": "Asynchronous rule creation",
                "type": ["boolean", "null"]}

DELAY_INJECTION = {"description": "Time (in seconds) to wait before starting applying the rule. Implies asynchronous rule creation.",
                   "type": ["integer", "null"]}

PURGE_REPLICAS = {"description": "Rule purge replica status",
                  "type": "boolean"}

IGNORE_AVAILABILITY = {"description": "Rule ignore availability status",
                       "type": "boolean"}

RSE = {"description": "RSE name",
       "type": "string",
       "pattern": "^([A-Z0-9]+([_-][A-Z0-9]+)*)$"}

RSE_ATTRIBUTE = {"description": "RSE attribute",
                 "type": "string",
                 "pattern": r'([A-Za-z0-9\._-]+[=<>][A-Za-z0-9_-]+)'}

DEFAULT_RSE_ATTRIBUTE = {"description": "Default RSE attribute",
                         "type": "string",
                         "pattern": r'([A-Z0-9]+([_-][A-Z0-9]+)*)'}

REPLICA_STATE = {"description": "Replica state",
                 "type": "string",
                 "enum": [
                     "AVAILABLE", "UNAVAILABLE", "COPYING", "BEING_DELETED", "BAD", "SOURCE", "TEMPORARY_UNAVAILABLE",
                     "A", "U", "C", "B", "D", "S", "T"]}

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
        "properties": {"guid": SchemaRef("UUID")},
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

TIME_ENTRY = {
    "description": "Datetime, ISO 8601",
    "type": "string",
    "pattern": r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?$'
}

IP = {
    "description": "Internet Protocol address v4, RFC 791",
    "type": "string",
    "pattern": r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}$'
}

IPv4orIPv6 = {
    "description": "IPv4 or IPv6 address",
    "type": "string",
    "format": "ipv4_or_ipv6"
}

CLIENT_STATE = {
    "description": "Client state",
    "type": "string",
    "enum": ['DONE', 'FAILED', 'PROCESSING', 'ALREADY_DONE', 'FILE_NOT_FOUND', 'FOUND_IN_PCACHE', 'DOWNLOAD_ATTEMPT',
             'FAIL_VALIDATE', 'FOUND_ROOT', 'ServiceUnavailable', 'SERVICE_ERROR', 'CP_TIMEOUT', 'COPY_ERROR',
             'STAGEIN_ATTEMPT_FAILED', 'SourceNotFound', 'MISSINGOUTPUTFILE', 'MD_MISMATCH', 'CHECKSUMCALCULATIONFAILURE',
             'MISSINGINPUT', 'MISSING_INPUT']
}

RULE = {"description": "Replication rule",
        "type": "object",
        "properties": {"dids": {"type": "array"},
                       "account": SchemaRef("ACCOUNT"),
                       "copies": SchemaRef("COPIES"),
                       "rse_expression": SchemaRef("RSE_EXPRESSION"),
                       "grouping": SchemaRef("GROUPING"),
                       "weight": SchemaRef("WEIGHT"),
                       "lifetime": SchemaRef("RULE_LIFETIME"),
                       "locked": SchemaRef("LOCKED"),
                       "subscription_id": SchemaRef("SUBSCRIPTION_ID"),
                       "source_replica_expression": SchemaRef("SOURCE_REPLICA_EXPRESSION"),
                       "activity": SchemaRef("ACTIVITY"),
                       "notify": SchemaRef("NOTIFY"),
                       "purge_replicas": SchemaRef("PURGE_REPLICAS"),
                       "ignore_availability": SchemaRef("IGNORE_AVAILABILITY"),
                       "comment": SchemaRef("COMMENT"),
                       "ask_approval": SchemaRef("ASK_APPROVAL"),
                       "asynchronous": SchemaRef("ASYNCHRONOUS"),
                       "delay_injection": SchemaRef("DELAY_INJECTION"),
                       "priority": SchemaRef("PRIORITY"),
                       'split_container': SchemaRef("SPLIT_CONTAINER"),
                       'meta': SchemaRef("METADATA")},
        "required": ["dids", "copies", "rse_expression"],
        "additionalProperties": False}

RULES = {"description": "Array of replication rules",
         "type": "array",
         "items": SchemaRef("RULE"),
         "minItems": 1,
         "maxItems": 1000}

COLLECTION_TYPE = {"description": "Dataset or container type",
                   "type": "string",
                   "enum": ["DATASET", "CONTAINER"]}

COLLECTION = {"description": "Dataset or container",
              "type": "object",
              "properties": {"scope": SchemaRef("SCOPE"),
                             "name": SchemaRef("NAME"),
                             "type": SchemaRef("COLLECTION_TYPE"),
                             "meta": SchemaRef("META"),
                             "rules": SchemaRef("RULES")},
              "required": ["scope", "name", "type"],
              "additionalProperties": False}

COLLECTIONS = {"description": "Array of datasets or containers",
               "type": "array",
               "items": SchemaRef("COLLECTION"),
               "minItems": 1,
               "maxItems": 1000}

DID = {"description": "Data Identifier(DID)",
       "type": "object",
       "properties": {"scope": SchemaRef("SCOPE"),
                      "name": SchemaRef("NAME"),
                      "type": SchemaRef("DID_TYPE"),
                      "meta": SchemaRef("META"),
                      "rules": SchemaRef("RULES"),
                      "bytes": SchemaRef("BYTES"),
                      "adler32": SchemaRef("ADLER32"),
                      "md5": SchemaRef("MD5"),
                      "state": SchemaRef("REPLICA_STATE"),
                      "pfn": SchemaRef("PFN")},
       "required": ["scope", "name"],
       "additionalProperties": False}

DID_FILTERS = {"description": "Array to filter DIDs by metadata",
               "type": "array",
               "additionalProperties": True}

R_DID = {"description": "Data Identifier(DID)",
         "type": "object",
         "properties": {"scope": SchemaRef("R_SCOPE"),
                        "name": SchemaRef("R_NAME"),
                        "type": SchemaRef("DID_TYPE"),
                        "meta": SchemaRef("META"),
                        "rules": SchemaRef("RULES"),
                        "bytes": SchemaRef("BYTES"),
                        "adler32": SchemaRef("ADLER32"),
                        "md5": SchemaRef("MD5"),
                        "state": SchemaRef("REPLICA_STATE"),
                        "pfn": SchemaRef("PFN")},
         "required": ["scope", "name"],
         "additionalProperties": False}

DIDS = {"description": "Array of Data Identifiers(DIDs)",
        "type": "array",
        "items": SchemaRef("DID"),
        "minItems": 1,
        "maxItems": 1000}

R_DIDS = {"description": "Array of Data Identifiers(DIDs)",
          "type": "array",
          "items": SchemaRef("R_DID"),
          "minItems": 1,
          "maxItems": 1000}

ATTACHMENT = {"description": "Attachment",
              "type": "object",
              "properties": {"scope": SchemaRef("SCOPE"),
                             "name": SchemaRef("NAME"),
                             "rse": {"description": "RSE name",
                                     "type": ["string", "null"],
                                     "pattern": "^([A-Z0-9]+([_-][A-Z0-9]+)*)$"},
                             "dids": SchemaRef("DIDS")},
              "required": ["dids"],
              "additionalProperties": False}

ATTACHMENTS = {"description": "Array of attachments",
               "type": "array",
               "items": SchemaRef("ATTACHMENT"),
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
                                      "account": SchemaRef("ACCOUNTS"),
                                      "grouping": {"type": "string"},
                                      "split_rule": {"type": "boolean"}}}

ADD_REPLICA_FILE = {"description": "add replica file",
                    "type": "object",
                    "properties": {"scope": SchemaRef("SCOPE"),
                                   "name": SchemaRef("NAME"),
                                   "bytes": SchemaRef("BYTES"),
                                   "adler32": SchemaRef("ADLER32")},
                    "required": ["scope", "name", "bytes", "adler32"]}

ADD_REPLICA_FILES = {"description": "add replica files",
                     "type": "array",
                     "items": SchemaRef("ADD_REPLICA_FILE"),
                     "minItems": 1,
                     "maxItems": 1000}

CACHE_ADD_REPLICAS = {"description": "rucio cache add replicas",
                      "type": "object",
                      "properties": {"files": SchemaRef("ADD_REPLICA_FILES"),
                                     "rse": SchemaRef("RSE"),
                                     "lifetime": SchemaRef("LIFETIME"),
                                     "operation": {"enum": ["add_replicas"]}},
                      "required": ['files', 'rse', 'lifetime', 'operation']}

DELETE_REPLICA_FILE = {"description": "delete replica file",
                       "type": "object",
                       "properties": {"scope": SchemaRef("SCOPE"),
                                      "name": SchemaRef("NAME")},
                       "required": ["scope", "name"]}

DELETE_REPLICA_FILES = {"description": "delete replica files",
                        "type": "array",
                        "items": SchemaRef("DELETE_REPLICA_FILE"),
                        "minItems": 1,
                        "maxItems": 1000}

CACHE_DELETE_REPLICAS = {"description": "rucio cache delete replicas",
                         "type": "object",
                         "properties": {"files": SchemaRef("DELETE_REPLICA_FILES"),
                                        "rse": SchemaRef("RSE"),
                                        "operation": {"enum": ["delete_replicas"]}},
                         "required": ['files', 'rse', 'operation']}

MESSAGE_OPERATION = {"type": "object",
                     "properties": {'operation': {"enum": ["add_replicas", "delete_replicas"]}}}

ACCOUNT_ATTRIBUTE = {"description": "Account attribute",
                     "type": "string",
                     "pattern": r'^[a-zA-Z0-9-_\\/\\.]{1,30}$'}

SCOPE_NAME_REGEXP = r"/([^/]+)/(.*)"

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
