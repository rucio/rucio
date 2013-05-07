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

reserved_keys = ['scope', 'name', 'type', 'account', 'length', 'size', 'guid']

key_types = ['ALL', 'COLLECTION', 'FILE', 'DERIVED']
# all(container, dataset, file), collection(dataset or container), file, derived(compute from file for collection)
