# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012

"""
Rucio utilities.
"""

import uuid


def generate_uuid():
    return str(uuid.uuid4()).replace('-', '').lower()


def generate_bytes_uuid():
    return uuid.uuid4().bytes
