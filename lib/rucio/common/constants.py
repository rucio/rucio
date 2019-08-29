# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2015-2019
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2018
#
# PY3K COMPATIBLE

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
              'https': ['https', 'davs', 's3'],
              'davs': ['https', 'davs', 's3'],
              'root': ['root'],
              's3': ['https', 'davs', 's3']}

SUPPORTED_PROTOCOLS = ['gsiftp', 'srm', 'root', 'davs', 'http', 'https', 'file', 's3', 's3+rucio', 's3+https', 'storm']
