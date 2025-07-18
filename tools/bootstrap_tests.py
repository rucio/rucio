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

import os
import os.path
import sys
import time
from json import dumps

import requests

base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_path)
os.chdir(base_path)


from rucio.client import Client  # noqa: E402
from rucio.common.config import config_get, config_get_bool  # noqa: E402
from rucio.common.constants import DEFAULT_VO  # noqa: E402
from rucio.common.exception import Duplicate, DuplicateContent, RucioException  # noqa: E402
from rucio.common.types import InternalAccount  # noqa: E402
from rucio.common.utils import extract_scope  # noqa: E402
from rucio.core.account import add_account_attribute  # noqa: E402
from rucio.core.vo import map_vo  # noqa: E402
from rucio.gateway.vo import add_vo  # noqa: E402
from rucio.tests.common_server import reset_config_table  # noqa: E402


def belleii_bootstrap(client):
    scopes = ['raw', 'hraw', 'other', 'mc_tmp', 'mc', 'test', 'user', 'data', 'data_tmp', 'group', 'mock']
    for scope in scopes:
        try:
            client.add_scope(scope=scope, account='root')
        except Duplicate:
            pass
        except Exception as err:
            print(err)

    lpns = ['/belle', '/belle/mc', '/belle/Data', '/belle/user', '/belle/raw', '/belle/mock']
    for lpn in lpns:
        scope, name = extract_scope(lpn)
        try:
            client.add_did(scope=scope, name=name, did_type='CONTAINER')
        except Duplicate:
            pass
        except Exception as err:
            print(err)
        if name != '/belle':
            try:
                client.attach_dids(scope='other', name='/belle', dids=[{'scope': str(scope), 'name': str(name)}])
            except DuplicateContent:
                pass
            except Exception as err:
                print(err)


def create_influxdb_database():
    response = requests.get('http://influxdb:8086/api/v2/buckets?org=rucio',
                            headers={'Authorization': 'Token mytoken'})
    if response.status_code == 200:
        json = response.json()
        buckets = json.get('buckets', [])
        for bucket in buckets:
            bucket_id, name = bucket['id'], bucket['name']
            if name == 'rucio':
                data = {"bucketId": bucket_id, "database": "rucio", "default": True, "org": "rucio", "retention_policy": "example-rp"}
                res = requests.post('http://influxdb:8086/api/v2/dbrps', headers={'Authorization': 'Token mytoken', 'Content-type': 'application/json'}, data=dumps(data))
                return res
    return response


if __name__ == '__main__':
    # Create config table including the long VO mappings
    reset_config_table()
    if config_get_bool('common', 'multi_vo', raise_exception=False, default=False):
        vo = {'vo': map_vo(config_get('client', 'vo', raise_exception=False, default='tst'))}
        try:
            add_vo(new_vo=vo['vo'], issuer='super_root', description='A VO to test multi-vo features', email='N/A', vo=DEFAULT_VO)
        except Duplicate:
            print(f'VO {vo["vo"]} already added')
    else:
        vo = {}

    try:
        client = Client()
    except RucioException as e:
        error_msg = str(e)
        print('Creating client failed:', error_msg)
        if 'Internal Server Error' in error_msg:
            server_log = '/var/log/rucio/httpd_error_log'
            if os.path.exists(server_log):
                # wait for the server to write the error to log
                time.sleep(5)
                with open(server_log, 'r') as fhandle:
                    print(fhandle.readlines()[-200:], file=sys.stderr)
        raise

    try:
        client.add_account('jdoe', 'SERVICE', 'jdoe@email.com')
    except Duplicate:
        print('Account jdoe already added')

    try:
        add_account_attribute(account=InternalAccount('root', **vo), key='admin', value=True)  # bypass client as schema validation fails at API level
    except Exception as error:
        print(error)

    try:
        client.add_account('panda', 'SERVICE', 'panda@email.com')
        add_account_attribute(account=InternalAccount('panda', **vo), key='admin', value=True)
    except Duplicate:
        print('Account panda already added')

    try:
        client.add_scope('jdoe', 'mock')
    except Duplicate:
        print('Scope mock already added')

    try:
        client.add_scope('root', 'archive')
    except Duplicate:
        print('Scope archive already added')

    # add your accounts here, if you test against CERN authed nodes
    additional_test_accounts = [('CN=Mario Lassnig,CN=663551,CN=mlassnig,OU=Users,OU=Organic Units,DC=cern,DC=ch', 'x509', 'mario.lassnig@cern.ch'),
                                ('CN=Martin Barisits,CN=692443,CN=barisits,OU=Users,OU=Organic Units,DC=cern,DC=ch', 'x509', 'martin.barisits@cern.ch'),
                                ('CN=Thomas Beermann,CN=722011,CN=tbeerman,OU=Users,OU=Organic Units,DC=cern,DC=ch', 'x509', 'thomas.beermann@cern.ch'),
                                ('CN=Robot: Rucio build bot,CN=692443,CN=ruciobuildbot,OU=Users,OU=Organic Units,DC=cern,DC=ch', 'x509', 'rucio.build.bot@cern.ch'),
                                ('CN=docker client', 'x509', 'dummy@cern.ch'),
                                ('mlassnig@CERN.CH', 'GSS', 'mario.lassnig@cern.ch')]

    for account in additional_test_accounts:
        try:
            client.add_identity(account='root', identity=account[0], authtype=account[1], email=account[2])
        except Exception:
            print('Already added: ', account)

    if os.getenv('POLICY') == 'belleii':
        belleii_bootstrap(client)
