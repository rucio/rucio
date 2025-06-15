#!/usr/bin/env python
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

import json
import subprocess
import sys

import requests

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()

COMPONENT_COLOR = 'd4c5f9'

option_doc = False
option_backport = False

if len(sys.argv) == 1:
    print('generate-release-notes VERSION [--doc] [--backport]')
    sys.exit(-1)
for arg in sys.argv:
    if arg == '--doc':
        option_doc = True
    elif arg == '--backport':
        option_backport = True
    else:
        milestone_title = arg


def format_issue(issue, doc=False):
    if not doc:
        if issue['component']:
            return '- %s: %s #%s' % (issue['component'], issue['title'], issue['number'])
        else:
            return '- %s #%s' % (issue['title'], issue['number'])
    else:
        if issue['component']:
            return '- %s: %s [#%s](https://github.com/rucio/rucio/issues/%s)' % (issue['component'], issue['title'], issue['number'], issue['number'])
        else:
            return '- %s [#%s](https://github.com/rucio/rucio/issues/%s)' % (issue['title'], issue['number'], issue['number'])


def load_milestones(github_token, page=1):
    r = requests.get(url='https://api.github.com/repos/rucio/rucio/milestones',
                     headers={'Authorization': 'token %s' % github_token},
                     params={'state': 'all', 'page': page, 'per_page': '100'})
    return json.loads(r.text)


def get_issue_component_type(issue):
    component = None
    type_ = 'enhancement'
    for label in issue['labels']:
        if label['color'] == COMPONENT_COLOR and not component:
            component = label['name']
            next
        elif label['name'].lower() == 'enhancement':
            type_ = 'enhancement'
        elif label['name'].lower() == 'bug':
            type_ = 'bug'
        elif label['name'].lower() == 'feature':
            type_ = 'feature'
    return component, type_


def print_issues(issues, section_title):
    if not issues:
        return
    # Generate the formatted printout
    bugs = [issue for issue in issues if issue['type'] == 'bug']
    bugs = sorted(bugs, key=lambda k: "%s %d" % (k['component'], k['number']))
    enhancements = [issue for issue in issues if issue['type'] == 'enhancement']
    enhancements = sorted(enhancements, key=lambda k: "%s %d" % (k['component'], k['number']))
    features = [issue for issue in issues if issue['type'] == 'feature']
    features = sorted(features, key=lambda k: "%s %d" % (k['component'], k['number']))

    if not option_doc:
        print('\n#', section_title)
        print()
        if features:
            print('## Features\n')
            for issue in features:
                print(format_issue(issue))
            print('')
        if enhancements:
            print('## Enhancements\n')
            for issue in enhancements:
                print(format_issue(issue))
            print('')
        if bugs:
            print('## Bugs\n')
            for issue in bugs:
                print(format_issue(issue))
    else:
        print('\n##', section_title)
        print()
        if features:
            print('### Features\n')
            for issue in features:
                print(format_issue(issue, doc=True))
            print('')
        if enhancements:
            print('### Enhancements\n')
            for issue in enhancements:
                print(format_issue(issue, doc=True))
            print('')
        if bugs:
            print('### Bugs\n')
            for issue in bugs:
                print(format_issue(issue, doc=True))


root_git_dir = subprocess.check_output('git rev-parse --show-toplevel', shell=True).decode("utf-8").rstrip()  # noqa: S607
# Load OAUTH token
try:
    with open(root_git_dir + '/.githubtoken', 'r') as f:
        github_token = f.readline().strip()
except Exception:
    print('No github token file found at %s' % root_git_dir + '/.githubtoken')
    sys.exit(-1)

# Get all Milestones
page = 1
milestones = load_milestones(github_token, page)
while len(milestones) == page * 100:
    page += 1
    milestones.extend(load_milestones(github_token, page))
for milestone in milestones:
    if milestone['title'] == milestone_title:
        milestone_number = milestone['number']
        break

# Get the issues
issues = []
r = requests.get(url='https://api.github.com/repos/rucio/rucio/issues',
                 headers={'Authorization': 'token %s' % github_token},
                 params={'milestone': milestone_number, 'state': 'closed', 'per_page': 100})
for issue in json.loads(r.text):
    component, type_ = get_issue_component_type(issue)
    issues.append({'component': component,
                   'type': type_,
                   'number': issue['number'],
                   'title': issue['title']})
# If --backport is specified, we additionally need to scan older issues
if option_backport:
    r = requests.get(url='https://api.github.com/repos/rucio/rucio/issues',
                     headers={'Authorization': 'token %s' % github_token},
                     params={'labels': 'backport', 'state': 'closed', 'per_page': 100})
    for issue in json.loads(r.text):
        # Load the comments
        r = requests.get(url=issue['comments_url'],
                         headers={'Authorization': 'token %s' % github_token},
                         params={'per_page': 100})
        # Iterate comments
        for comment in json.loads(r.text):
            if 'backport %s' % milestone_title in comment['body'].lower():
                component, type_ = get_issue_component_type(issue)
                issues.append({'component': component,
                               'type': type_,
                               'number': issue['number'],
                               'title': issue['title']})

print_issues([issue for issue in issues if issue['component'] not in ['Clients', 'WebUI']], 'General')
print_issues([issue for issue in issues if issue['component'] in ['Clients']], 'Clients')
print_issues([issue for issue in issues if issue['component'] in ['WebUI']], 'WebUI')
