# -*- coding: utf-8 -*-
# Copyright CERN since 2013
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

"""
This submits a transfer to FTS3 via the transfertool.
"""

import sys
import os.path
base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_path)
os.chdir(base_path)

import time  # noqa: E402
from pprint import pprint  # noqa: E402

import rucio.transfertool.fts3  # noqa: E402
from rucio.common.utils import generate_uuid  # noqa: E402

if __name__ == "__main__":
    # token for OAuth 2.0 OIDC authorization scheme is working only with dCache + davs/https protocols (as of September 2019)
    token = '<token>'
    FTS3_TransferTool = rucio.transfertool.fts3.FTS3Transfertool('https://fts3-xdc.cern.ch:8446', token)
    files = [{"sources": ['https://dcache-xdc.desy.de/Users/jaroslav/tests/test.txt'],
              "destinations": ['https://dcache-xdc.desy.de/Users/jaroslav/tests/test.txt-%s' % generate_uuid()],
              "verify_checksum": False,
              "overwrite": True,
              "metadata": {'request_id': 'jwttest-%s' % generate_uuid()},
              "activity": "Rucio_Test_JWT_Authorisation"}]
    job_params = {'request_id': generate_uuid()}
    transfer_id = FTS3_TransferTool.submit(files, job_params, timeout=300)
    print("transfer_id = ", transfer_id)
    time.sleep(10)
    status = FTS3_TransferTool.query([transfer_id])
    pprint(status)
