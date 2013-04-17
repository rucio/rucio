# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013

#import json
#import os
#import subprocess

import pytest

#from rucio.client import Client
#from rucio.db.util import build_database, destroy_database, create_root_account


def pytest_collection_modifyitems(items):
    '''
        Automatically adding markers based on test/class names
    '''
    for item in items:
        if "test_rse_protocol" in item.nodeid:
            item.keywords["protocol"] = pytest.mark.protocol
        else:
            item.keywords["non_protocol"] = pytest.mark.non_protocol


@pytest.fixture(scope="session", autouse=True)
def bootstrap_tests(request):
    pass

# Start apache
#     apache_cmd = ['/usr/sbin/apachectl', 'restart']
#     apache_proc = subprocess.Popen(apache_cmd, stdout=open(os.devnull), stderr=open(os.devnull), shell=False)
#     request.addfinalizer(apache_proc.kill)
#
#
# Reset schema
#     print 'reset schema'
#     destroy_database()
#     build_database()
#     create_root_account()
#
# Add RSEs
#     print 'add RSEs'
#
#     rse_repo_file = 'etc/rse_repository.json'
#     json_data = open(rse_repo_file)
#     repo_data = json.load(json_data)
#     json_data.close()
#
#     c = Client()
#     for rse in repo_data:
#         prefix = repo_data[rse].get('prefix', None)
#         deterministic = repo_data[rse].get('deterministic', True)
#         volatile = repo_data[rse].get('volatile', False)
#         c.add_rse(rse, prefix=prefix, deterministic=deterministic, volatile=volatile)
#
#         for p_id in repo_data[rse]['protocols']['supported']:
#             c.add_protocol(rse, p_id, repo_data[rse]['protocols']['supported'][p_id])
#
# Add meta-data
#     print 'add meta-data'
#     meta_keys = [('project', 'all', None, ['data13_hip', ]),
#                  ('run_number', 'all', None, []),
#                  ('stream_name', 'all', None, []),
#                  ('prod_step', 'all', None, []),
#                  ('datatype', 'all', None, []),
#                  ('version', 'all', None, []),
#                  ('guid', 'file', '^(\{){0,1}[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}(\}){0,1}$', []),
#                  ('events', 'derived', '^\d+$', [])]
#
#     c = Client()
#     for key, key_type, value_regexp, values in meta_keys:
#         c.add_key(key=key, key_type=key_type, value_regexp=value_regexp)
#         for value in values:
#             c.add_value(key=key, value=value)
#             if key == 'project':
#                 c.add_scope('root', value)
