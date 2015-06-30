# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2015

import commands
import json
import requests
import sys

requests.packages.urllib3.disable_warnings()

root_git_dir = commands.getstatusoutput('git rev-parse --show-toplevel')[1]

# Load private_token
try:
    with open(root_git_dir + '/.gitlabkey', 'r') as f:
        private_token = f.readline().strip()
except:
    print 'No gitlab keyfile found at %s' % root_git_dir + '/.gitlabkey'
    sys.exit(-1)

resp = requests.get(url='https://gitlab.cern.ch/api/v3/projects/651/merge_requests',
                    params={'private_token': private_token})
mr_list = json.loads(resp.text)
for mr in mr_list:
    if mr['state'] == 'merged' and mr['source_branch'].startswith('patch') and mr['target_branch'] == 'master':
        has_next = False
        for mr2 in mr_list:
            if mr2['source_branch'] == mr['source_branch'] and mr2['target_branch'] == 'next':
                has_next = True
        if not has_next:
            print 'No NEXT merge request found for \'%s\'' % mr['source_branch']
