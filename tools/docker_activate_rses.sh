#!/bin/bash
# -*- coding: utf-8 -*-
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

echo "Creating RSEs"

# Create the following topology:
# +------+   1   +------+
# |      |<----->|      |
# | XRD1 |       | XRD2 |
# |      |   +-->|      |
# +------+   |   +------+
#    ^       |
#    | 1     | 1
#    v       |
# +------+   |   +------+
# |      |<--+   |      |
# | XRD3 |       | XRD4 |
# |      |<----->|      |
# +------+   2   +------+
# +------+
# |      |   1
# | WEB1 | <---> TO ALL
# |      |
# +------+

# Step zero, get a compliant proxy
xrdgsiproxy init -bits 2048 -valid 9999:00 -cert /opt/rucio/etc/usercert.pem  -key /opt/rucio/etc/userkey.pem

# First, create the RSEs
rucio-admin rse add XRD1
rucio-admin rse add XRD2
rucio-admin rse add XRD3
rucio-admin rse add XRD4
rucio-admin rse add SSH1
rucio-admin rse add WEB1

# Add the protocol definitions for the storage servers
rucio-admin rse add-protocol --hostname xrd1 --scheme root --prefix //rucio --port 1094 --impl rucio.rse.protocols.xrootd.Default --domain-json '{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 1}, "lan": {"read": 1, "write": 1, "delete": 1}}' XRD1
rucio-admin rse add-protocol --hostname xrd2 --scheme root --prefix //rucio --port 1095 --impl rucio.rse.protocols.xrootd.Default --domain-json '{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 1}, "lan": {"read": 1, "write": 1, "delete": 1}}' XRD2
rucio-admin rse add-protocol --hostname xrd3 --scheme root --prefix //rucio --port 1096 --impl rucio.rse.protocols.xrootd.Default --domain-json '{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 1}, "lan": {"read": 1, "write": 1, "delete": 1}}' XRD3
rucio-admin rse add-protocol --hostname xrd4 --scheme root --prefix //rucio --port 1097 --impl rucio.rse.protocols.xrootd.Default --domain-json '{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 1}, "lan": {"read": 1, "write": 1, "delete": 1}}' XRD4
rucio-admin rse add-protocol --hostname ssh1 --scheme scp --prefix /rucio --port 22 --impl rucio.rse.protocols.ssh.Default --domain-json '{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 1}, "lan": {"read": 1, "write": 1, "delete": 1}}' SSH1
rucio-admin rse add-protocol --hostname ssh1 --scheme rsync --prefix /rucio --port 22 --impl rucio.rse.protocols.ssh.Rsync --domain-json '{"wan": {"read": 2, "write": 2, "delete": 2, "third_party_copy_read": 2, "third_party_copy_write": 2}, "lan": {"read": 2, "write": 2, "delete": 2}}' SSH1
rucio-admin rse add-protocol --hostname ssh1 --scheme rclone --prefix /rucio --port 22 --impl rucio.rse.protocols.rclone.Default --domain-json '{"wan": {"read": 3, "write": 3, "delete": 3, "third_party_copy_read": 3, "third_party_copy_write": 3}, "lan": {"read": 3, "write": 3, "delete": 3}}' SSH1
rucio-admin rse add-protocol --hostname web1 --scheme https --prefix /rucio/ --port 443 --impl rucio.rse.protocols.webdav.Default --domain-json '{"wan": {"read": 3, "write": 3, "delete": 3, "third_party_copy_read": 3, "third_party_copy_write": 3}, "lan": {"read": 3, "write": 3, "delete": 3}}' WEB1

# Set test_container_xrd attribute for xrd containers
rucio-admin rse set-attribute --rse XRD1 --key test_container_xrd --value True
rucio-admin rse set-attribute --rse XRD2 --key test_container_xrd --value True
rucio-admin rse set-attribute --rse XRD3 --key test_container_xrd --value True
rucio-admin rse set-attribute --rse XRD4 --key test_container_xrd --value True
rucio-admin rse set-attribute --rse SSH1 --key test_container_ssh --value True
rucio-admin rse set-attribute --rse WEB1 --key test_container_web --value True

# Workaround, xrootd.py#connect returns with Auth Failed due to execution of the command in subprocess
XrdSecPROTOCOL=gsi XRD_REQUESTTIMEOUT=10 xrdfs xrd1:1094 query config xrd1:1094
XrdSecPROTOCOL=gsi XRD_REQUESTTIMEOUT=10 xrdfs xrd2:1095 query config xrd2:1095
XrdSecPROTOCOL=gsi XRD_REQUESTTIMEOUT=10 xrdfs xrd3:1096 query config xrd3:1096
XrdSecPROTOCOL=gsi XRD_REQUESTTIMEOUT=10 xrdfs xrd3:1096 query config xrd4:1097

# Enable FTS
rucio-admin rse set-attribute --rse XRD1 --key fts --value https://fts:8446
rucio-admin rse set-attribute --rse XRD2 --key fts --value https://fts:8446
rucio-admin rse set-attribute --rse XRD3 --key fts --value https://fts:8446
rucio-admin rse set-attribute --rse XRD4 --key fts --value https://fts:8446
rucio-admin rse set-attribute --rse SSH1 --key fts --value https://fts:8446

# Enable multihop transfers via XRD3
rucio-admin rse set-attribute --rse XRD3 --key available_for_multihop --value True

# Connect the RSEs
rucio-admin rse add-distance --distance 1 --ranking 1 XRD1 XRD2
rucio-admin rse add-distance --distance 1 --ranking 1 XRD1 XRD3
rucio-admin rse add-distance --distance 1 --ranking 1 XRD2 XRD1
rucio-admin rse add-distance --distance 2 --ranking 2 XRD2 XRD3
rucio-admin rse add-distance --distance 1 --ranking 1 XRD3 XRD1
rucio-admin rse add-distance --distance 2 --ranking 2 XRD3 XRD2
rucio-admin rse add-distance --distance 3 --ranking 3 XRD3 XRD4
rucio-admin rse add-distance --distance 3 --ranking 3 XRD4 XRD3

rucio-admin rse add-distance --distance 1 --ranking 1 XRD1 WEB1
rucio-admin rse add-distance --distance 1 --ranking 1 WEB1 XRD1
rucio-admin rse add-distance --distance 1 --ranking 1 XRD2 WEB1
rucio-admin rse add-distance --distance 1 --ranking 1 WEB1 XRD2
rucio-admin rse add-distance --distance 1 --ranking 1 XRD3 WEB1
rucio-admin rse add-distance --distance 1 --ranking 1 WEB1 XRD3
rucio-admin rse add-distance --distance 1 --ranking 1 XRD4 WEB1
rucio-admin rse add-distance --distance 1 --ranking 1 WEB1 XRD4

# Indefinite limits for root
rucio-admin account set-limits root XRD1 -1
rucio-admin account set-limits root XRD2 -1
rucio-admin account set-limits root XRD3 -1
rucio-admin account set-limits root XRD4 -1
rucio-admin account set-limits root SSH1 -1
rucio-admin account set-limits root WEB1 -1

if [[ $* =~ --no-populate ]]; then
    echo "Not populating the RSEs"
else
    source tools/docker_populate_rses.sh
fi

echo "docker_activate_rses.sh done"
