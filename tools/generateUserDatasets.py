#!/usr/bin/env python
# Copyright 2013-2020 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Cedric Serfon <cedric.serfon@cern.ch>, 2013-2014
# - Martin Barisits <martin.barisits@cern.ch>, 2016
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

import random
import sys

from math import exp, pow

from rucio.api.rse import add_file_replica, list_rses
from rucio.api.did import attach_identifier, add_identifier
from rucio.api.rule import add_replication_rule
from rucio.api.scope import add_scope
from rucio.api.account import add_account
from rucio.common.exception import InvalidReplicationRule
from rucio.common.exception import Duplicate
from rucio.common.utils import generate_uuid as uuid
from rucio.core import monitor


def fitfunc(x):
    if x < 100:
        return 33292.8 - 3115.44 * x + 151.836 * pow(x, 2) - 3.90351 * pow(x, 3) + 0.0539087 * pow(x, 4) - 0.00037816 * pow(x, 5) + 1.05717e-06 * pow(x, 6)
    else:
        return exp(8.23051e+00 + (-4.04271e-03) * x)


def generatePDF():
    cumul = []
    pdf = []
    cumul.append(0)
    for i in range(1, 2000):
        cumul.append(cumul[i - 1] + fitfunc(i))
    print(cumul[1999])
    print(pdf)
    for i in cumul:
        pdf.append(i / cumul[1999])
    return pdf


def getRandomScope(pdf):
    rnd = random.random()
    for i in range(2001):
        if (rnd >= pdf[i]) and (rnd < pdf[i + 1]):
            return i


def createScope():
    for i in range(2000):
        print(i)
        user = 'user%i' % (i)
        try:
            add_account(user, 'user', 'root')
            add_scope('user.%s' % user, user, 'root')
        except Duplicate as e:
            print(e)


def populateDB(filename=None):
    listrses = list_rses(filters={'deterministic': 1})
    listrses = map(lambda x: x['rse'], listrses)
    account = 'root'

    pdf = generatePDF()

    # Generate 200000 datasets according to the dataset distribution
    for index in range(20000):
        scope_nb = getRandomScope(pdf)
        project = 'user.user%i' % (scope_nb)
        scope = 'user.user%i' % (scope_nb)
        account = 'user%i' % (scope_nb)
        print(scope)
        nbfiles = 53
        filesize = 78000000
        uid = uuid()
        dsn = '%s.%s' % (project, uid)
        rnd_site = random.choice(listrses)
        print('%i Creating %s with %i files of size %i located at %s' % (index, dsn, nbfiles, filesize, rnd_site))
        add_identifier(scope=scope, name=dsn, type='dataset', issuer=account, statuses={'monotonic': True})
        monitor.record(timeseries='dbfiller.addnewdataset', delta=1)
        files = ['file_%s' % uuid() for i in range(nbfiles)]
        listfiles = []
        for file in files:
            listfiles.append({'scope': scope, 'name': file, 'size': filesize})
            add_file_replica(rnd_site, scope, file, filesize, issuer=account)
        monitor.record(timeseries='dbfiller.addreplicas', delta=nbfiles)
        attach_identifier(scope, name=dsn, dids=listfiles, issuer=account)
        monitor.record(timeseries='dbfiller.addnewfile', delta=nbfiles)
        try:
            add_replication_rule(dids=[{'scope': scope, 'name': dsn}], account=account, copies=1, rse_expression=rnd_site,
                                 grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, issuer=account)
            monitor.record(timeseries='dbfiller.addreplicationrules', delta=1)
        except InvalidReplicationRule as e:
            print(e)


def main(argv):
    # createScope()
    populateDB()


if __name__ == '__main__':
    main(sys.argv[1:])
