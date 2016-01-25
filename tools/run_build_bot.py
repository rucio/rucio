# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2015

import commands
import datetime
import dateutil.parser
import json
import os
import pytz
import requests
import sys
import subprocess
import time

requests.packages.urllib3.disable_warnings()


def needs_testing(mr_id):
    resp = requests.get(url='https://gitlab.cern.ch/api/v3/projects/651/merge_requests/%s/notes' % str(mr_id),
                        params={'private_token': private_token})
    comments = json.loads(resp.text)
    needs_testing = True

    global states

    if mr_id in states:
        comparison_time = states[str(mr_id)]
        needs_testing = False
    else:
        comparison_time = pytz.utc.localize(datetime.datetime.utcfromtimestamp(0))

    for comment in comments:
        if comment['body'].startswith('#### BUILD-BOT TEST') and comment['author']['username'] == 'ruciobuildbot':
            if dateutil.parser.parse(comment['created_at']) > comparison_time:
                needs_testing = False
                comparison_time = dateutil.parser.parse(comment['created_at'])
        elif comment['body'].startswith('Added'):
            if dateutil.parser.parse(comment['created_at']) > comparison_time:
                needs_testing = True
                comparison_time = dateutil.parser.parse(comment['created_at'])
        elif comment['body'].lower().startswith('ruciobuildbot test'):
            if dateutil.parser.parse(comment['created_at']) > comparison_time:
                needs_testing = True
                comparison_time = dateutil.parser.parse(comment['created_at'])

    states[str(mr_id)] = comparison_time.isoformat()
    return needs_testing


def update_merg_request(mr, test_result, comment):
    print '  Updating Merge request and putting comment ...'
    labels = mr['labels']
    try:
        labels.remove('Tests: OK')
    except:
        pass
    try:
        labels.remove('Tests: FAIL')
    except:
        pass

    if test_result:
        labels.append('Tests: OK')
    else:
        labels.append('Tests: FAIL')

    data = {'labels': ', '.join(labels)}
    requests.put(url='https://gitlab.cern.ch/api/v3/projects/651/merge_request/%s' % str(mr['id']),
                 params={'private_token': private_token},
                 data=data)

    data = {'body': ''.join(comment)}
    requests.post(url='https://gitlab.cern.ch/api/v3/projects/651/merge_requests/%s/notes' % str(mr['id']),
                  params={'private_token': private_token},
                  data=data)


def start_test(mr):
    tests_passed = True
    error_lines = []
    print 'Starting testing for MR %s ...' % mr['source_branch']
    # Add remote of user
    resp = requests.get(url='https://gitlab.cern.ch/api/v3/projects/%s' % str(mr['source_project_id']),
                        params={'private_token': private_token})
    proj = json.loads(resp.text)
    commands.getstatusoutput('git remote add %s %s' % (proj['namespace']['name'], proj['http_url_to_repo']))

    # Fetch all
    print '  git fetch --all --prune'
    if commands.getstatusoutput('git fetch --all --prune')[0] != 0:
        print 'Error while fetching all'
        sys.exit(-1)

    # Rebase master/next
    print '  git rebase origin/next next'
    if commands.getstatusoutput('git rebase origin/next next')[0] != 0:
        print 'Error while rebaseing next'
        sys.exit(-1)
    print '  git rebase origin/master master'
    if commands.getstatusoutput('git rebase origin/master master')[0] != 0:
        print 'Error while rebaseing master'
        sys.exit(-1)

    # Check for Cross Merges
    if mr['source_branch'].lower().startswith('patch'):
        print '  Checking for cross-merges:'
        commits = commands.getoutput('git log master..remotes/%s/%s | grep ^commit' % (proj['namespace']['name'], mr['source_branch']))
        for commit in commits.splitlines():
            commit = commit.partition(' ')[2]
            if commands.getstatusoutput('git branch --contains %s | grep next' % commit)[0] == 0:
                print '    Found cross-merge problem with commit %s' % commit
                tests_passed = False
                error_lines.append('##### CROSS-MERGE TESTS:\n')
                error_lines.append('```\n')
                error_lines.append('This patch is suspicious. It looks like there are feature-commits pulled into the master branch!\n')
                error_lines.append('```\n')
                break

    # Checkout the branch to test
    print '  git checkout remotes/%s/%s' % (proj['namespace']['name'], mr['source_branch'])
    if commands.getstatusoutput('git checkout remotes/%s/%s' % (proj['namespace']['name'], mr['source_branch']))[0] != 0:
        print 'Error while checking out branch'
        sys.exit(-1)

    # Restart apache and memcached
    print '  /sbin/service memcached restart'
    if commands.getstatusoutput('/sbin/service memcached restart')[0] != 0:
        print 'Error while restarting memcached'
        sys.exit(-1)

    # Restart apache and memcached
    print '  service httpd restart'
    if commands.getstatusoutput('/sbin/service httpd restart')[0] != 0:
        print 'Error while restarting httpd'
        sys.exit(-1)

    command = """
    cd %s; source .venv/bin/activate;
    pip install -r tools/pip-requires;
    pip install -r tools/pip-requires-client;
    pip install -r tools/pip-requires-test;
    cp tools/patches/nose/tools.py .venv/lib/python2.6/site-packages/nose/tools.py
    cp tools/patches/nose/trivial.py .venv/lib/python2.6/site-packages/nose/tools/trivial.py
    find lib -iname "*.pyc" | xargs rm; rm -rf /tmp/.rucio_*/;
    tools/reset_database.py;
    tools/sync_rses.py;
    tools/sync_meta.py;
    tools/bootstrap_tests.py;
    nosetests -v --logging-filter=-sqlalchemy,-requests,-rucio.client.baseclient --exclude=.*test_rse_protocol_.* --exclude=test_alembic --exclude=test_rucio_cache --exclude=test_rucio_server --exclude=test_dq2* > /tmp/rucio_nose.txt 2> /tmp/rucio_nose.txt;
    tools/reset_database.py;
    nosetests -v lib/rucio/tests/test_alembic.py > /tmp/rucio_alembic.txt 2> /tmp/rucio_alembic.txt;
    flake8 --exclude=*.cfg bin/* lib/ tools/*.py tools/probes/common/* > /tmp/rucio_flake8.txt;
    python ../purge_bin.py;
    """ % (root_git_dir)  # NOQA
    # command = 'cd %s; source .venv/bin/activate; pip install -r tools/pip-requires; pip install -r tools/pip-requires-client; pip install -r tools/pip-requires-test; find lib -iname "*.pyc" | xargs rm; rm -rf /tmp/.rucio_*/; tools/reset_database.py; tools/sync_rses.py; tools/sync_meta.py; tools/bootstrap_tests.py; nosetests -v lib/rucio/tests/test_alembic.py > /tmp/rucio_alembic.txt 2> /tmp/rucio_alembic.txt; flake8 bin/* lib/ tools/*.py tools/probes/common/* > /tmp/rucio_flake8.txt' % (root_git_dir)  # NOQA
    print '  %s' % command
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    process.communicate()

    with open('/tmp/rucio_nose.txt', 'r') as f:
        lines = f.readlines()
        if lines[-1] != 'OK\n':
            tests_passed = False
            error_lines.append('##### UNIT TESTS:\n')
            error_lines.append('```\n')
            error_lines.extend(lines)
            error_lines.append('```\n')

    with open('/tmp/rucio_alembic.txt', 'r') as f:
        lines = f.readlines()
        if lines[-1] != 'OK\n':
            tests_passed = False
            error_lines.append('##### ALEMBIC:\n')
            error_lines.append('```\n')
            error_lines.extend(lines)
            error_lines.append('```\n')

    if os.stat('/tmp/rucio_flake8.txt').st_size != 0:
        with open('/tmp/rucio_flake8.txt', 'r') as f:
            lines = f.readlines()
            tests_passed = False
            error_lines.append('##### FLAKE8:\n')
            error_lines.append('```\n')
            error_lines.extend(lines)
            error_lines.append('```\n')

    if tests_passed:
        error_lines.insert(0, '#### BUILD-BOT TEST RESULT: OK\n\n')
    else:
        error_lines.insert(0, '#### BUILD-BOT TEST RESULT: FAIL\n\n')

    update_merg_request(mr=mr, test_result=tests_passed, comment=error_lines)

    # Checkout original master
    print '  git checkout master'
    if commands.getstatusoutput('git checkout master')[0] != 0:
        print 'Error while checking out master'
        sys.exit(-1)

print 'Checking if a job is currently running ...'
if os.path.isfile('/tmp/rucio_test.pid'):
    # Check if the pid file is older than 90 minutes
    if os.stat('/tmp/rucio_test.pid').st_mtime < time.time()-60*90:
        os.remove('/tmp/rucio_test.pid')
        open('/tmp/rucio_test.pid', 'a').close()
    else:
        sys.exit(-1)
else:
    open('/tmp/rucio_test.pid', 'a').close()

root_git_dir = commands.getstatusoutput('git rev-parse --show-toplevel')[1]

# Load private_token
print 'Loading private token ...'
try:
    with open(root_git_dir + '/.gitlabkey', 'r') as f:
        private_token = f.readline().strip()
except:
    print 'No gitlab keyfile found at %s' % root_git_dir + '/.gitlabkey'
    sys.exit(-1)

# Load state file
print 'Loading state file ...'
try:
    with open('/tmp/ruciobuildbot.states') as data_file:
        states = json.load(data_file)
except:
    states = {}

# Get all open merge requests
print 'Getting all open merge requests ...'
resp = requests.get(url='https://gitlab.cern.ch/api/v3/projects/651/merge_requests',
                    params={'private_token': private_token, 'state': 'opened'})
mr_list = json.loads(resp.text)
for mr in mr_list:
    print 'Checking MR %s -> %s if it needs testing ...' % (mr['source_branch'], mr['target_branch']),
    if mr['target_branch'] == 'next' and needs_testing(mr_id=mr['id']):
        print 'YES'
        start_test(mr=mr)
    else:
        print 'NO'

print 'Writing state file ...'
with open('/tmp/ruciobuildbot.states', 'w') as outfile:
    json.dump(states, outfile)

os.remove('/tmp/rucio_test.pid')
