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
# +------+   |   +------+       +------+       +------+
# |      |<--+   |      |       |      |       |      |
# | XRD3 |       | XRD4 |<----->| XRD5 |<----->| WEB1 |
# |      |<----->|      |   1   |      |   1   |      |
# +------+   2   +------+       +------+       +------+

# Step zero, get a compliant proxy. The key must NOT be group/other readable
(KEY=$(mktemp); cat /opt/rucio/etc/userkey.pem > "$KEY"; voms-proxy-init -valid 9999:00 -cert /opt/rucio/etc/usercert.pem -key "$KEY"; rm -f "$KEY")

# First, create the RSEs
rucio-admin rse add XRD1
rucio-admin rse add XRD2
rucio-admin rse add XRD3
rucio-admin rse add XRD4
rucio-admin rse add XRD5
rucio-admin rse add SSH1
rucio-admin rse add WEB1

# Add the protocol definitions for the storage servers
rucio-admin rse add-protocol --hostname xrd1 --scheme root --prefix //rucio --port 1094 --impl rucio.rse.protocols.xrootd.Default --domain-json '{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 1}, "lan": {"read": 1, "write": 1, "delete": 1}}' XRD1
rucio-admin rse add-protocol --hostname xrd2 --scheme root --prefix //rucio --port 1095 --impl rucio.rse.protocols.xrootd.Default --domain-json '{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 1}, "lan": {"read": 1, "write": 1, "delete": 1}}' XRD2
rucio-admin rse add-protocol --hostname xrd3 --scheme root --prefix //rucio --port 1096 --impl rucio.rse.protocols.xrootd.Default --domain-json '{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 1}, "lan": {"read": 1, "write": 1, "delete": 1}}' XRD3
rucio-admin rse add-protocol --hostname xrd4 --scheme root --prefix //rucio --port 1097 --impl rucio.rse.protocols.xrootd.Default --domain-json '{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 1}, "lan": {"read": 1, "write": 1, "delete": 1}}' XRD4
rucio-admin rse add-protocol --hostname xrd5 --scheme root --prefix //rucio --port 1098 --impl rucio.rse.protocols.xrootd.Default --domain-json '{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 1}, "lan": {"read": 1, "write": 1, "delete": 1}}' XRD5
rucio-admin rse add-protocol --hostname xrd5 --scheme davs --prefix //rucio --port 1098 --impl rucio.rse.protocols.gfal.Default --domain-json '{"wan": {"read": 2, "write": 2, "delete": 2, "third_party_copy_read": 2, "third_party_copy_write": 2}, "lan": {"read": 2, "write": 2, "delete": 2}}' XRD5
rucio-admin rse add-protocol --hostname xrd5 --scheme magnet --prefix //rucio --port 10000 --impl rucio.rse.protocols.bittorrent.Default --domain-json '{"wan": {"read": 3, "write": 0, "delete": 0, "third_party_copy_read": 3, "third_party_copy_write": 3}, "lan": {"read": 3, "write": 0, "delete": 0}}' XRD5
rucio-admin rse add-protocol --hostname ssh1 --scheme scp --prefix /rucio --port 22 --impl rucio.rse.protocols.ssh.Default --domain-json '{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 1}, "lan": {"read": 1, "write": 1, "delete": 1}}' SSH1
rucio-admin rse add-protocol --hostname ssh1 --scheme rsync --prefix /rucio --port 22 --impl rucio.rse.protocols.ssh.Rsync --domain-json '{"wan": {"read": 2, "write": 2, "delete": 2, "third_party_copy_read": 2, "third_party_copy_write": 2}, "lan": {"read": 2, "write": 2, "delete": 2}}' SSH1
rucio-admin rse add-protocol --hostname ssh1 --scheme rclone --prefix /rucio --port 22 --impl rucio.rse.protocols.rclone.Default --domain-json '{"wan": {"read": 3, "write": 3, "delete": 3, "third_party_copy_read": 3, "third_party_copy_write": 3}, "lan": {"read": 3, "write": 3, "delete": 3}}' SSH1
rucio-admin rse add-protocol --hostname web1 --scheme davs --prefix /rucio --port 443 --impl rucio.rse.protocols.gfal.Default --domain-json '{"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 2}, "lan": {"read": 1, "write": 1, "delete": 1}}' WEB1
rucio-admin rse add-protocol --hostname web1 --scheme magnet --prefix /var/www/webdav/data/rucio/ --port 10000 --impl rucio.rse.protocols.bittorrent.Default --domain-json '{"wan": {"read": 2, "write": 0, "delete": 0, "third_party_copy_read": 2, "third_party_copy_write": 2}, "lan": {"read": 2, "write": 0, "delete": 0}}' WEB1

# Set test_container_xrd attribute for xrd containers
rucio-admin rse set-attribute --rse XRD1 --key test_container_xrd --value True
rucio-admin rse set-attribute --rse XRD2 --key test_container_xrd --value True
rucio-admin rse set-attribute --rse XRD3 --key test_container_xrd --value True
rucio-admin rse set-attribute --rse XRD4 --key test_container_xrd --value True
rucio-admin rse set-attribute --rse SSH1 --key test_container_ssh --value True
rucio-admin rse set-attribute --rse XRD5 --key oidc_support --value True
rucio-admin rse set-attribute --rse XRD5 --key bittorrent_driver --value qbittorrent
rucio-admin rse set-attribute --rse XRD5 --key qbittorrent_management_address --value https://xrd5:8098/
rucio-admin rse set-attribute --rse XRD5 --key bittorrent_tracker_addr --value http://xrd5:10001/announce
rucio-admin rse set-attribute --rse WEB1 --key oidc_support --value True
rucio-admin rse set-attribute --rse WEB1 --key verify_checksum --value False
rucio-admin rse set-attribute --rse WEB1 --key bittorrent_driver --value qbittorrent
rucio-admin rse set-attribute --rse WEB1 --key qbittorrent_management_address --value https://web1:8099/
rucio-admin rse set-attribute --rse WEB1 --key bittorrent_tracker_addr --value http://web1:10001/announce

# Workaround, xrootd.py#connect returns with Auth Failed due to execution of the command in subprocess
XrdSecPROTOCOL=gsi XRD_REQUESTTIMEOUT=10 XrdSecGSISRVNAMES=xrd1 xrdfs xrd1:1094 query config xrd1:1094
XrdSecPROTOCOL=gsi XRD_REQUESTTIMEOUT=10 XrdSecGSISRVNAMES=xrd2 xrdfs xrd2:1095 query config xrd2:1095
XrdSecPROTOCOL=gsi XRD_REQUESTTIMEOUT=10 XrdSecGSISRVNAMES=xrd3 xrdfs xrd3:1096 query config xrd3:1096
XrdSecPROTOCOL=gsi XRD_REQUESTTIMEOUT=10 XrdSecGSISRVNAMES=xrd4 xrdfs xrd4:1097 query config xrd4:1097

# Enable FTS
rucio-admin rse set-attribute --rse XRD1 --key fts --value https://fts:8446
rucio-admin rse set-attribute --rse XRD2 --key fts --value https://fts:8446
rucio-admin rse set-attribute --rse XRD3 --key fts --value https://fts:8446
rucio-admin rse set-attribute --rse XRD4 --key fts --value https://fts:8446
rucio-admin rse set-attribute --rse XRD5 --key fts --value https://fts:8446
rucio-admin rse set-attribute --rse SSH1 --key fts --value https://fts:8446
rucio-admin rse set-attribute --rse WEB1 --key fts --value https://fts:8446

# Enable multihop transfers via XRD3
rucio-admin rse set-attribute --rse XRD3 --key available_for_multihop --value True

# Connect the RSEs
rucio-admin rse add-distance --distance 1 XRD1 XRD2
rucio-admin rse add-distance --distance 1 XRD1 XRD3
rucio-admin rse add-distance --distance 1 XRD2 XRD1
rucio-admin rse add-distance --distance 2 XRD2 XRD3
rucio-admin rse add-distance --distance 1 XRD3 XRD1
rucio-admin rse add-distance --distance 2 XRD3 XRD2
rucio-admin rse add-distance --distance 3 XRD3 XRD4
rucio-admin rse add-distance --distance 3 XRD4 XRD3
rucio-admin rse add-distance --distance 1 XRD4 XRD5
rucio-admin rse add-distance --distance 1 XRD5 XRD4
rucio-admin rse add-distance --distance 1 XRD5 WEB1
rucio-admin rse add-distance --distance 1 WEB1 XRD5

# Indefinite limits for root
rucio-admin account set-limits root XRD1 -1
rucio-admin account set-limits root XRD2 -1
rucio-admin account set-limits root XRD3 -1
rucio-admin account set-limits root XRD4 -1
rucio-admin account set-limits root SSH1 -1

# Create a default scope for testing
rucio-admin scope add --account root --scope test

# Create initial transfer testing data
dd if=/dev/urandom of=file1 bs=10M count=1
dd if=/dev/urandom of=file2 bs=10M count=1
dd if=/dev/urandom of=file3 bs=10M count=1
dd if=/dev/urandom of=file4 bs=10M count=1

XrdSecGSISRVNAMES=xrd1 rucio upload --rse XRD1 --scope test file1
XrdSecGSISRVNAMES=xrd1 rucio upload --rse XRD1 --scope test file2
XrdSecGSISRVNAMES=xrd2 rucio upload --rse XRD2 --scope test file3
XrdSecGSISRVNAMES=xrd2 rucio upload --rse XRD2 --scope test file4

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

# FTS Check
fts-rest-whoami -v -s https://fts:8446

# Delegate credentials to FTS
fts-rest-delegate -vf -s https://fts:8446 -H 9999
