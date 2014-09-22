#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN) 2014
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - David Cameron, <david.cameron@cern.ch>, 2014
#

# Sets the minimum free space on RSEs according to the policy. The smaller of
# ratio and absolute is the threshold below which to clean.
#  Spacetoken  Free ratio  Free absolute
#  PRODDISK      25%         10.0 TB
#  SCRATCHDISK   50%         100.0 TB
#  DATADISK      10%         500.0 TB
#
# Other tokens (tape, groupdisk, localgroupdisk) are not cleaned automatically.
#
# The capacity of each RSE is SRM used - Rucio used of other RSEs sharing the
# token. This allows RSEs to use space pledged but not used by other RSEs. The
# minimum free space is evaluated based on this capacity. In the reaper Rucio
# calculates the space to clean as MinFreeSpace limit - SRM free, where SRM
# free is the total SRM capacity - Rucio used for this RSE. Therefore the
# MinFreeSpace limit set here must include all the used space for all the other
# RSEs in the token.

import json
import sys
import requests
from urlparse import urlparse

# Try to use server environment (direct database access). If that fails use
# client. Client cannot be used until RUCIO-539 is fixed.
server = False
try:
    from rucio.api import rse as c
    server = True
except:
    from rucio.client import Client
    c = Client()

UNKNOWN, OK, WARNING, CRITICAL = -1, 0, 1, 2

# This is the limit of files to delete in each RSE in the reaper loop. To be
# decided what is the ideal value and if it should be per RSE.
max_files_to_delete = 100


def TB(size):
    return size/1000.0**4

# Get endpoint info from AGIS to know the RSEs in each space token
try:
    url = 'http://atlas-agis-api.cern.ch/request/ddmendpoint/query/list/?json'
    resp = requests.get(url=url)
    data = json.loads(resp.content)
except Exception, e:
    print "Failed to get information from AGIS: %s" % str(e)
    sys.exit(CRITICAL)

# Map of RSE: hostname
rse_host = {}
for endpoint in data:
    host = urlparse(endpoint['se']).hostname
    if host:
        rse_host[endpoint['name']] = host

try:
    rses = [rse['rse'] for rse in c.list_rses()]
except Exception, e:
    print "Failed to get RSEs from Rucio: %s" % str(e)
    sys.exit(CRITICAL)

for rse in rses:

    if not rse.endswith('PRODDISK') and not rse.endswith('DATADISK') and not rse.endswith('SCRATCHDISK'):
        continue

    if not [r for r in data if r['name'] == rse]:
        print "RSE %s not defined in AGIS" % rse
        continue
    try:
        token = c.list_rse_attributes(rse)['spacetoken']
    except:
        print "No space token info for %s" % rse
        continue

    # Client and server API are different for get_rse_usage
    try:
        if server:
            capacity = c.get_rse_usage(rse, None, source='srm')[0]['total']
        else:
            capacity = c.get_rse_usage(rse, filters={'source': 'srm'})['total']
    except:
        print 'No SRM information available for %s' % rse
        continue

    print "RSE %s: total capacity %sTB" % (rse, TB(capacity))

    # If this RSE shares space with others remove rucio used from total space
    # to calculate the limit
    used_others = 0
    for endpoint in data:
        if endpoint['name'] != rse and (rse_host[endpoint['name']] == rse_host[rse] and token == endpoint['token']):
            try:
                if server:
                    used = c.get_rse_usage(endpoint['name'], None, source='rucio')[0]['used']
                else:
                    used = c.get_rse_usage(endpoint['name'], filters={'source': 'rucio'})['used']
            except Exception, e:
                print "No data for %s in Rucio: %s" % (endpoint['name'], str(e))
            print "Removing %fTB used space in %s" % (TB(used), endpoint['name'])
            used_others += used

    capacity -= used_others
    print "Remaining capacity for %s: %sTB" % (rse, TB(capacity))
    if rse.endswith('PRODDISK'):
        minfree = min(capacity * 0.25, 10*(1000**4))
    elif rse.endswith('DATADISK'):
        minfree = min(capacity * 0.1, 500*(1000**4))
    elif rse.endswith('SCRATCHDISK'):
        minfree = min(capacity * 0.5, 100*(1000**4))
    print "RSE %s: calculated minimum free space %sTB" % (rse, TB(minfree))

    # Now add the space used in other tokens to the limit
    minfree += used_others
    try:
        if server:
            c.set_rse_limits(rse, 'MinFreeSpace', minfree, 'root')
            c.set_rse_limits(rse, 'MaxBeingDeletedFiles', max_files_to_delete, 'root')
        else:
            c.set_rse_limits(rse, 'MinFreeSpace', minfree)
            c.set_rse_limits(rse, 'MaxBeingDeletedFiles', max_files_to_delete)
    except Exception, e:
        print "Failed to set RSE limits for %s: %s" % (rse, str(e))
        continue

    print "Set MinFreeSpace for %s to %fTB" % (rse, TB(minfree))

sys.exit(OK)
