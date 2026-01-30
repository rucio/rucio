#!/usr/bin/env python3
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

# ruff: noqa: S607
import os
import subprocess
import tempfile

from rucio.client import Client
from rucio.client.uploadclient import UploadClient
from rucio.common.exception import NoFilesUploaded

print("Creating RSEs")

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
with tempfile.NamedTemporaryFile(mode='w') as f:
    f.write(open('/opt/rucio/etc/userkey.pem').read())
    f.flush()
    os.chmod(f.name, 0o600)
    subprocess.run(f'voms-proxy-init -valid 9999:00 -cert /opt/rucio/etc/usercert.pem -key {f.name}', shell=True, check=True)

client = Client()
upload_client = UploadClient()

client.import_data({
    "rses": {
        "XRD1": {
            "rse_type": "DISK",
            "protocols": [
                {"scheme": "root", "hostname": "xrd1", "port": 1094, "prefix": "//rucio", "impl": "rucio.rse.protocols.xrootd.Default",
                 "domains": {"wan": {"read": 0, "write": 0, "delete": 0, "third_party_copy_read": 0, "third_party_copy_write": 0},
                             "lan": {"read": 0, "write": 0, "delete": 0}}}],
            "attributes": {
                "test_container_xrd": "True",
                "fts": "https://fts:8446",
            }
        },
        "XRD2": {
            "rse_type": "DISK",
            "protocols": [
                {"scheme": "root", "hostname": "xrd2", "port": 1095, "prefix": "//rucio", "impl": "rucio.rse.protocols.xrootd.Default",
                 "domains": {"wan": {"read": 0, "write": 0, "delete": 0, "third_party_copy_read": 0, "third_party_copy_write": 0},
                             "lan": {"read": 0, "write": 0, "delete": 0}}}],
            "attributes": {
                "test_container_xrd": "True",
                "fts": "https://fts:8446",
            }
        },
        "XRD3": {
            "rse_type": "DISK",
            "protocols": [
                {"scheme": "root", "hostname": "xrd3", "port": 1096, "prefix": "//rucio", "impl": "rucio.rse.protocols.xrootd.Default",
                 "domains": {"wan": {"read": 0, "write": 0, "delete": 0, "third_party_copy_read": 0, "third_party_copy_write": 0},
                             "lan": {"read": 0, "write": 0, "delete": 0}}}],
            "attributes": {
                "test_container_xrd": "True",
                "fts": "https://fts:8446",
                "available_for_multihop": "True",
            }
        },
        "XRD4": {
            "rse_type": "DISK",
            "protocols": [
                {"scheme": "root", "hostname": "xrd4", "port": 1097, "prefix": "//rucio", "impl": "rucio.rse.protocols.xrootd.Default",
                 "domains": {"wan": {"read": 0, "write": 0, "delete": 0, "third_party_copy_read": 0, "third_party_copy_write": 0},
                             "lan": {"read": 0, "write": 0, "delete": 0}}}],
            "attributes": {
                "test_container_xrd": "True",
                "fts": "https://fts:8446",
            }
        },
        "XRD5": {
            "rse_type": "DISK",
            "protocols": [
                {"scheme": "root", "hostname": "xrd5", "port": 1098, "prefix": "//rucio", "impl": "rucio.rse.protocols.xrootd.Default",
                 "domains": {"wan": {"read": 0, "write": 0, "delete": 0, "third_party_copy_read": 0, "third_party_copy_write": 0},
                             "lan": {"read": 0, "write": 0, "delete": 0}}},
                {"scheme": "davs", "hostname": "xrd5", "port": 1098, "prefix": "//rucio", "impl": "rucio.rse.protocols.gfal.Default",
                 "domains": {"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 1},
                             "lan": {"read": 1, "write": 1, "delete": 1}}},
                {"scheme": "magnet", "hostname": "xrd5", "port": 10000, "prefix": "//rucio", "impl": "rucio.rse.protocols.bittorrent.Default",
                 "domains": {"wan": {"read": 2, "write": None, "delete": None, "third_party_copy_read": 2, "third_party_copy_write": 2},
                             "lan": {"read": 2, "write": None, "delete": None}}}],
            "attributes": {
                "fts": "https://fts:8446",
                "oidc_support": "True",
                "bittorrent_driver": "qbittorrent",
                "qbittorrent_management_address": "https://xrd5:8098/",
                "bittorrent_tracker_addr": "http://xrd5:10001/announce",
            }
        },
        "SSH1": {
            "rse_type": "DISK",
            "protocols": [
                {"scheme": "scp", "hostname": "ssh1", "port": 22, "prefix": "/rucio", "impl": "rucio.rse.protocols.ssh.Default",
                 "domains": {"wan": {"read": 0, "write": 0, "delete": 0, "third_party_copy_read": 0, "third_party_copy_write": 0},
                             "lan": {"read": 0, "write": 0, "delete": 0}}},
                {"scheme": "rsync", "hostname": "ssh1", "port": 22, "prefix": "/rucio", "impl": "rucio.rse.protocols.ssh.Rsync",
                 "domains": {"wan": {"read": 1, "write": 1, "delete": 1, "third_party_copy_read": 1, "third_party_copy_write": 1},
                             "lan": {"read": 1, "write": 1, "delete": 1}}},
                {"scheme": "rclone", "hostname": "ssh1", "port": 22, "prefix": "/rucio", "impl": "rucio.rse.protocols.rclone.Default",
                 "domains": {"wan": {"read": 2, "write": 2, "delete": 2, "third_party_copy_read": 2, "third_party_copy_write": 2},
                             "lan": {"read": 2, "write": 2, "delete": 2}}}],
            "attributes": {
                "test_container_ssh": "True",
                "fts": "https://fts:8446",
            }
        },
        "WEB1": {
            "rse_type": "DISK",
            "protocols": [
                {"scheme": "davs", "hostname": "web1", "port": 443, "prefix": "/rucio", "impl": "rucio.rse.protocols.gfal.Default",
                 "domains": {"wan": {"read": 0, "write": 0, "delete": 0, "third_party_copy_read": 0, "third_party_copy_write": 1},
                             "lan": {"read": 0, "write": 0, "delete": 0}}},
                {"scheme": "magnet", "hostname": "web1", "port": 10000, "prefix": "/var/www/webdav/data/rucio/", "impl": "rucio.rse.protocols.bittorrent.Default",
                 "domains": {"wan": {"read": 1, "write": None, "delete": None, "third_party_copy_read": 1, "third_party_copy_write": 1},
                             "lan": {"read": 1, "write": None, "delete": None}}}],
            "attributes": {
                "fts": "https://fts:8446",
                "oidc_support": "True",
                "verify_checksum": False,
                "bittorrent_driver": "qbittorrent",
                "qbittorrent_management_address": "https://web1:8099/",
                "bittorrent_tracker_addr": "http://web1:10001/announce",
            }
        }
    },
    "distances": {
        "XRD1": {"XRD2": {"distance": 1}, "XRD3": {"distance": 1}},
        "XRD2": {"XRD1": {"distance": 1}, "XRD3": {"distance": 2}},
        "XRD3": {"XRD1": {"distance": 1}, "XRD2": {"distance": 2}, "XRD4": {"distance": 3}},
        "XRD4": {"XRD3": {"distance": 3}, "XRD5": {"distance": 1}},
        "XRD5": {"XRD4": {"distance": 1}, "WEB1": {"distance": 1}},
        "WEB1": {"XRD5": {"distance": 1}}
    }
})

# Workaround, xrootd.py#connect returns with Auth Failed due to execution of the command in subprocess
xrd_env = {**os.environ, 'XrdSecPROTOCOL': 'gsi', 'XRD_REQUESTTIMEOUT': '10'}
subprocess.run('xrdfs xrd1:1094 query config xrd1:1094', shell=True, env={**xrd_env, 'XrdSecGSISRVNAMES': 'xrd1'})
subprocess.run('xrdfs xrd2:1095 query config xrd2:1095', shell=True, env={**xrd_env, 'XrdSecGSISRVNAMES': 'xrd2'})
subprocess.run('xrdfs xrd3:1096 query config xrd3:1096', shell=True, env={**xrd_env, 'XrdSecGSISRVNAMES': 'xrd3'})
subprocess.run('xrdfs xrd4:1097 query config xrd4:1097', shell=True, env={**xrd_env, 'XrdSecGSISRVNAMES': 'xrd4'})

# Indefinite limits for root
client.set_local_account_limit('root', 'XRD1', -1)
client.set_local_account_limit('root', 'XRD2', -1)
client.set_local_account_limit('root', 'XRD3', -1)
client.set_local_account_limit('root', 'XRD4', -1)
client.set_local_account_limit('root', 'SSH1', -1)

# Create a default scope for testing
client.add_scope('root', 'test')

# Create initial transfer testing data
for f in ['file1', 'file2', 'file3', 'file4']:
    if not os.path.exists(f):
        open(f, 'wb').write(os.urandom(10 * 1024 * 1024))

for f, rse in [('file1', 'XRD1'), ('file2', 'XRD1'), ('file3', 'XRD2'), ('file4', 'XRD2')]:
    try:
        upload_client.upload([{'path': f, 'rse': rse, 'did_scope': 'test'}])
    except NoFilesUploaded:
        client.update_replicas_states(rse, [{'scope': 'test', 'name': f, 'state': 'A'}])

client.add_did('test', 'dataset1', 'DATASET')
client.attach_dids('test', 'dataset1', [{'scope': 'test', 'name': 'file1'}, {'scope': 'test', 'name': 'file2'}])

client.add_did('test', 'dataset2', 'DATASET')
client.attach_dids('test', 'dataset2', [{'scope': 'test', 'name': 'file3'}, {'scope': 'test', 'name': 'file4'}])

client.add_did('test', 'container', 'CONTAINER')
client.attach_dids('test', 'container', [{'scope': 'test', 'name': 'dataset1'}, {'scope': 'test', 'name': 'dataset2'}])

client.add_replication_rule([{'scope': 'test', 'name': 'container'}], copies=1, rse_expression='XRD3')

# Create complication
client.add_did('test', 'dataset3', 'DATASET')
client.attach_dids('test', 'dataset3', [{'scope': 'test', 'name': 'file4'}])

# FTS Check
subprocess.run('fts-rest-whoami -v -s https://fts:8446', shell=True, check=True)

# Delegate credentials to FTS
subprocess.run('fts-rest-delegate -vf -s https://fts:8446 -H 9999', shell=True, check=True)
