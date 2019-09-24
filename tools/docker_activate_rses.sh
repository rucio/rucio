#!/bin/bash
# Copyright 2019 CERN for the benefit of the ATLAS collaboration.
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
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019

# First, create the RSEs
rucio-admin rse add XRD1
rucio-admin rse add XRD2
rucio-admin rse add XRD3

# Add the protocol definitions for the storage servers
rucio-admin rse add-protocol --hostname xrd1 --scheme root --prefix //rucio --port 1094 --impl rucio.rse.protocols.gfal.Default --domain-json '{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy": 1}, "lan": {"read": 1, "write": 1, "delete": 1}}' XRD1
rucio-admin rse add-protocol --hostname xrd2 --scheme root --prefix //rucio --port 1095 --impl rucio.rse.protocols.gfal.Default --domain-json '{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy": 1}, "lan": {"read": 1, "write": 1, "delete": 1}}' XRD2
rucio-admin rse add-protocol --hostname xrd3 --scheme root --prefix //rucio --port 1096 --impl rucio.rse.protocols.gfal.Default --domain-json '{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy": 1}, "lan": {"read": 1, "write": 1, "delete": 1}}' XRD3

# Enable FTS
rucio-admin rse set-attribute --rse XRD1 --key fts --value https://fts:8446
rucio-admin rse set-attribute --rse XRD2 --key fts --value https://fts:8446
rucio-admin rse set-attribute --rse XRD3 --key fts --value https://fts:8446

# Fake a full mesh network
rucio-admin rse add-distance --distance 1 --ranking 1 XRD1 XRD2
rucio-admin rse add-distance --distance 1 --ranking 1 XRD1 XRD3
rucio-admin rse add-distance --distance 1 --ranking 1 XRD2 XRD1
rucio-admin rse add-distance --distance 1 --ranking 1 XRD2 XRD3
rucio-admin rse add-distance --distance 1 --ranking 1 XRD3 XRD1
rucio-admin rse add-distance --distance 1 --ranking 1 XRD3 XRD2

# Indefinite limits for root
rucio-admin account set-limits root XRD1 -1
rucio-admin account set-limits root XRD2 -1
rucio-admin account set-limits root XRD3 -1

# Create a default scope for testing
rucio-admin scope add --account root --scope test

# Delegate credentials to FTS
fts-rest-delegate -vf -s https://fts:8446 -H 9999

# Create initial transfer testing data
dd if=/dev/urandom of=file1 bs=10M count=1
dd if=/dev/urandom of=file2 bs=10M count=1
dd if=/dev/urandom of=file3 bs=10M count=1
dd if=/dev/urandom of=file4 bs=10M count=1

rucio upload --rse XRD1 --scope test file1
rucio upload --rse XRD1 --scope test file2
rucio upload --rse XRD2 --scope test file3
rucio upload --rse XRD2 --scope test file4

rucio add-dataset test:dataset1
rucio attach test:dataset1 test:file1 test:file2

rucio add-dataset test:dataset2
rucio attach test:dataset2 test:file3 test:file4

rucio add-container test:container
rucio attach test:container test:dataset1 test:dataset2

rucio add-rule test:container 1 XRD3

# Create complication
rucio add-dataset test:dataset3
rucio attach test:dataset3 test:file4
