# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

"""
Constants.

"""

reserved_keys = ['scope', 'name', 'account', 'did_type', 'is_open', 'monotonic', 'hidden', 'obsolete', 'complete',
                 'is_new', 'availability', 'suppressed', 'bytes', 'length', 'md5', 'adler32', 'rule_evaluation_action',
                 'rule_evaluation_required', 'expired_at', 'deleted_at', 'created_at', 'updated_at']
# collection_keys =
# file_keys =

key_types = ['ALL', 'COLLECTION', 'FILE', 'DERIVED']
# all(container, dataset, file), collection(dataset or container), file, derived(compute from file for collection)
