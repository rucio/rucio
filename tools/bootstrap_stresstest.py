#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#                       http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013

import json
import sys
import traceback

from uuid import uuid4 as uuid

from rucio.client import Client
from rucio.common.exception import Duplicate

UNKNOWN = 3
CRITICAL = 2
WARNING = 1
OK = 0

known_users = [('panda', 'service', ['InputGrove', 'OutputGrove', 'Manure']),
               ('root', 'user', ['data13_hip', 'data12_hip']),
               ('tzero', 'service', [])
               ]
users_total = 2000
scopes_total = 325
rses_total = 750

meta_keys = [('project', 'all', None, ['data13_hip', ]),
             ('run_number', 'all', None, []),
             ('stream_name', 'all', None, []),
             ('prod_step', 'all', None, []),
             ('datatype', 'all', None, []),
             ('version', 'all', None, []),
             ('guid', 'file', '^(\{){0,1}[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}(\}){0,1}$', []),
             ('events', 'derived', '^\d+$', [])]

if __name__ == '__main__':

    # 1. Import the RSEs defined explicetly in the repository file
    with open('etc/rse_repository.json') as json_data:
        repo_data = json.load(json_data)

    c = Client()
    for rse in repo_data:
        try:
            deterministic = repo_data[rse].get('deterministic', True)
            volatile = repo_data[rse].get('volatile', False)
            c.add_rse(rse, deterministic=deterministic, volatile=volatile)
        except Duplicate:
            print '%(rse)s already added' % locals()
        except:
            errno, errstr = sys.exc_info()[:2]
            trcbck = traceback.format_exc()
            print 'Interrupted processing with %s %s %s.' % (errno, errstr, trcbck)
        rses_total -= 1
        for p_id in repo_data[rse]['protocols']['supported']:
            try:
                repo_data[rse]['protocols']['supported'][p_id].update({'scheme': p_id})
                c.add_protocol(rse, repo_data[rse]['protocols']['supported'][p_id])
            except Duplicate:
                pass
            except Exception:
                errno, errstr = sys.exc_info()[:2]
                trcbck = traceback.format_exc()
                print 'Interrupted processing with %s %s %s.' % (errno, errstr, trcbck)
                sys.exit(CRITICAL)
    print '1. Importing RSE repository file finished.'
    # 2. Fill up th DB wo 130 sites with an avg. 6 protocols per site
    protocol = {'impl': 'rucio.rse.protocols.mock.Default',
                'hostame': 'rucio.cern.ch' % uuid(),
                'port': 42,
                'domains': {'LAN': {'read': 1, 'write': 1, 'delete': 1},
                            'WAN': {'read': 1, 'write': 1, 'delete': 1}
                            }
                }
    tmp = rses_total
    while rses_total:
        try:
            c.add_rse('MOCK_%s' % rses_total, deterministic=True, volatile=False)
            c.add_protocol('MOCK_%s' % rses_total, protocol.update({'scheme': 'MOCK'}))
        except Duplicate:
            pass
        except Exception:
            errno, errstr = sys.exc_info()[:2]
            trcbck = traceback.format_exc()
            print 'Interrupted processing with %s %s %s.' % (errno, errstr, trcbck)
            sys.exit(CRITICAL)
        rses_total -= 1
    print '2. Adding %s artificial RSEs finished.' % tmp

    # 3. Create known users
    tmp = users_total
    for user in known_users:
        print 'Adding account %s' % user[0]
        try:
            c.add_account(user[0], user[1])
            c.add_scope(user[0], user[0])  # Adding default scope
        except Duplicate:
            print 'User %s already exists' % user[0]
        users_total -= 1
    print '3. Adding %s known users finished.' % (tmp - users_total)
    tmp = users_total
    # 4. Fill up DB to total number of Users
    while users_total:
        try:
            c.add_account('user%s' % users_total, 'user')  # Adding user
            c.add_scope('user%s' % users_total, 'user%s' % users_total)  # Adding default scope
        except Duplicate:
            print 'User user%s already exists' % users_total
        users_total -= 1
    print '4. Adding %s artificial users (and default scopes) finished.' % tmp

    # 5. Create known scopes
    tmp = scopes_total
    for user in known_users:
        for scope in user[2]:
            try:
                c.add_scope(user[0], scope)
            except Duplicate:
                pass
            except Exception:
                errno, errstr = sys.exc_info()[:2]
                trcbck = traceback.format_exc()
                print 'Interrupted processing with %s %s %s.' % (errno, errstr, trcbck)
                sys.exit(CRITICAL)
            scopes_total -= 1
    print '5. Adding %s known scopes finished.' % (tmp - scopes_total)
    tmp = scopes_total
    # 6. Fill up DB to total number of scopes
    while scopes_total:
        try:
            c.add_scope('root', 'scope%s' % scopes_total)
        except Duplicate:
            pass
        except Exception:
            errno, errstr = sys.exc_info()[:2]
            trcbck = traceback.format_exc()
            print 'Interrupted processing with %s %s %s.' % (errno, errstr, trcbck)
            sys.exit(CRITICAL)
        scopes_total -= 1
    print '6. Adding %s artificial scopes for the user root finished' % tmp

    # 7. Define meta data
    for key, key_type, value_regexp, values in meta_keys:
        try:
            try:
                c.add_key(key=key, key_type=key_type, value_regexp=value_regexp)
            except Duplicate:
                print '%(key)s already added' % locals()

            for value in values:

                try:
                    c.add_value(key=key, value=value)
                except Duplicate:
                    print '%(key)s:%(value)s already added' % locals()

                if key == 'project':
                    try:
                        c.add_scope('root', value)
                    except Duplicate:
                        print 'Scope %(value)s already added' % locals()
        except:
            errno, errstr = sys.exc_info()[:2]
            trcbck = traceback.format_exc()
            print 'Interrupted processing with %s %s %s.' % (errno, errstr, trcbck)
