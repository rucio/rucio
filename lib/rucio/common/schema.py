# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

from jsonschema import validate, ValidationError

from rucio.common.exception import InvalidObject


account = {"description": "Account name",
           "type": "string",
           "pattern": "^[a-z0-9-]{1,30}$"}

account_type = {"description": "Account type",
                "type": "string",
                "enum": ["USER", "GROUP", "SERVICE"]}

scope = {"description": "Scope name",
         "type": "string",
         "pattern": "^[a-zA-Z'_'.0-9]{1,30}$"}

name = {"description": "Data Identifier name",
        "type": "string",
        "pattern": "^[A-Za-z0-9][A-Za-z0-9\.\-\_]{1,255}$"}

rse = {"description": "RSE name",
       "type": "string",
       "pattern": "^([A-Z0-9]+([_-][A-Z0-9]+)*)$"}

did_type = {"description": "DID type",
            "type": "string",
            "enum": ["DATASET", "CONTAINER", "FILE"]}

bytes = {"description": "Size in bytes",
         "type": "integer"}

adler32 = {"description": "adler32",
           "type": "string",
           "pattern": "^[a-fA-F\d]{8}$"}

md5 = {"description": "md5",
       "type": "string",
       "pattern": "^[a-fA-F\d]{32}$"}

uuid = {"description": "Universally Unique Identifier (UUID)",
        "type": "string",
        "pattern": '^[a-f0-9]{8}[a-f0-9]{4}[a-f0-9]{4}[a-f0-9]{4}[a-f0-9]{12}$'}

meta = {"description": "Data Identifier(DID) metadata",
        "type": "object",
        "properties": {"guid": uuid},
        "additionalProperties": True}

pfn = {"description": "Physical File Name", "type": "string"}

copies = {"description": "Number of replica copies", "type": "integer"}

rse_expression = {"description": "RSE expression", "type": "string"}

lifetime = {"description": "Lifetime", "type": "number"}

rule = {"description": "Replication rule",
        "type": "object",
        "properties": {"copies": copies,
                       "rse_expression": rse_expression,
                       "lifetime": lifetime},
        "required": ["copies", "rse_expression"],
        "additionalProperties": False}

rules = {"description": "Array of replication rules",
         "type": "array",
         "items": rule,
         "minItems": 1,
         "maxItems": 1000}

collection_type = {"description": "Dataset or container type",
                   "type": "string",
                   "enum": ["DATASET", "CONTAINER"]}

collection = {"description": "Dataset or container",
              "type": "object",
              "properties": {"scope": scope,
                             "name": name,
                             "type": collection_type,
                             "meta": meta,
                             "rules": rules},
              "required": ["scope", "name", "type"],
              "additionalProperties": False}

collections = {"description": "Array of datasets or containers",
               "type": "array",
               "items": collection,
               "minItems": 1,
               "maxItems": 1000}

did = {"description": "Data Identifier(DID)",
       "type": "object",
       "properties": {"scope": scope,
                      "name": name,
                      "type": did_type,
                      "meta": meta,
                      "rules": rules,
                      "bytes": bytes,
                      "adler32": adler32,
                      "md5": md5,
                      "pfn": pfn},
       "required": ["scope", "name"],
       "additionalProperties": False}

dids = {"description": "Array of Data Identifiers(DIDs)",
        "type": "array",
        "items": did,
        "minItems": 1,
        "maxItems": 1000}

attachment = {"description": "Attachement",
              "type": "object",
              "properties": {"scope": scope,
                             "name": name,
                             "rse": rse,
                             "dids": dids},
              "required": ["dids"],
              "additionalProperties": False}

attachments = {"description": "Array of attachments",
               "type": "array",
               "items": attachment,
               "minItems": 1,
               "maxItems": 1000}

subscription_filter = {"type": "object",
                       "properties": {"datatype": {"type": "array"},
                                      "prod_step": {"type": "array"},
                                      "stream_name": {"type": "array"},
                                      "project": {"type": "array"},
                                      "scope": {"type": "array"},
                                      "pattern": {"type": "string"},
                                      "excluded_pattern": {"type": "string"},
                                      "group": {"type": "string"},
                                      "provenance": {"type": "string"},
                                      "account": {"type": "string", "pattern": "^[a-z0-9-]{1,30}$"},
                                      "grouping": {"type": "string"}}}

schemas = {'account': account,
           'account_type': account_type,
           'name': name,
           'rse': rse,
           'scope': scope,
           'did': did,
           'dids': dids,
           'collection': collection,
           'collections': collections,
           'attachment': attachment,
           'attachments': attachments,
           'subscription_filter': subscription_filter}


def validate_schema(name, obj):
    """
    Validate object against json schema

    :param name: The json schema name.
    :param obj: The object to validate.
    """
    try:
        validate(obj, schemas.get(name, {}))
    except ValidationError, e:  # NOQA
        raise InvalidObject("%(e)s" % locals())
