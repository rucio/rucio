#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#                       http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2013


import random

from rucio.api.rse import add_rse, add_rse_attribute, add_file_replica, list_rses
from rucio.api.did import attach_identifier, add_identifier
from rucio.api.meta import add_key
from rucio.api.rule import add_replication_rule
from rucio.common.exception import InvalidReplicationRule, RucioException
from rucio.common.utils import generate_uuid as uuid


def createMetadata():
    add_key('project', 'all', 'root')
    add_key('run_number', 'all', 'root')
    add_key('stream_name', 'all', 'root')
    add_key('prod_step', 'all', 'root')
    add_key('datatype', 'all', 'root')
    add_key('provenance', 'all', 'root')
    add_key('group', 'all', 'root')


def createRSEs():
    # Add test RSEs
    for i in xrange(0, 3):
        rse1 = str(uuid())
        rse2 = str(uuid())
        add_rse(rse1, issuer='root')
        add_rse(rse2, issuer='root')
        add_rse_attribute(rse1, "T1", True, issuer='root')
        add_rse_attribute(rse2, "T1", True, issuer='root')
        add_rse_attribute(rse1, "DISK", True, issuer='root')
        add_rse_attribute(rse2, "TAPE", True, issuer='root')

    for i in xrange(0, 10):
        rse1 = str(uuid())
        add_rse(rse1, issuer='root')
        add_rse_attribute(rse1, "T2", True, issuer='root')
        add_rse_attribute(rse1, "DISK", True, issuer='root')

    source_rse = str(uuid())
    add_rse(source_rse, issuer='root')
    add_rse_attribute(source_rse, "T0", True, issuer='root')


def populateDB():
    listrses = list_rses({'T1': '1'})
    print len(listrses), listrses
    # listrses = list_rses()
    # print len(listrses), listrses
    # sys.exit()
    account = 'root'
    project = 'mc12_8TeV'

    dictDistrib = [{'datatype': 'HITS', 'prodstep': 'merge', 'nbfiles': 302, 'totfilesize': 225394185112, 'nbreplicas': 1}, {'datatype': 'HITS', 'prodstep': 'simul', 'nbfiles': 620, 'totfilesize': 97930909866, 'nbreplicas': 1},
                   {'datatype': 'EVNT', 'prodstep': 'evgen', 'nbfiles': 324, 'totfilesize': 7809298802, 'nbreplicas': 3}, {'datatype': 'AOD', 'prodstep': 'merge', 'nbfiles': 52, 'totfilesize': 106942334943, 'nbreplicas': 4},
                   {'datatype': 'AOD', 'prodstep': 'recon', 'nbfiles': 858, 'totfilesize': 182186965627, 'nbreplicas': 1}]

    for d in dictDistrib:
        for day in xrange(0, 180):
            for i in xrange(0, 30):
                scope = project
                prod_step = d['prodstep']
                datatype = d['datatype']
                nbfiles = int(d['nbfiles'])
                filesize = int(int(d['totfilesize'])/float(nbfiles))
                nbfiles = int(random.gauss(nbfiles, nbfiles/10))
                filesize = int(random.gauss(filesize, filesize/10))
                nbreplicas = int(d['nbreplicas'])
                dataset_meta = {'project': project, 'stream_name': 'dummy', 'prod_step': prod_step, 'datatype': datatype}
                source_rses = []
                if nbreplicas:
                    iter = 0
                    while (len(source_rses) != nbreplicas and iter != 100):
                        rnd_site = random.choice(listrses)
                        iter += 1
                        if rnd_site not in source_rses:
                            source_rses.append(rnd_site)

                    try:
                        dsn = '%s.%s.%s.%i.%i' % (project, prod_step, datatype, day, i)
                        print '%i Creating %s with %i files of size %i located at %i sites' % (i, dsn, nbfiles, filesize, len(source_rses))
                        add_identifier(scope=scope, name=dsn, type='dataset', issuer=account, statuses={'monotonic': True}, meta=dataset_meta)
                        files = ['file_%s' % uuid() for i in xrange(nbfiles)]
                        listfiles = []
                        for file in files:
                            listfiles.append({'scope': scope, 'name': file, 'size': filesize})
                            for source_rse in source_rses:
                                add_file_replica(source_rse, scope, file, filesize, issuer=account)
                        attach_identifier(scope, name=dsn, dids=listfiles, issuer=account)
                        for source_rse in source_rses:
                            try:
                                add_replication_rule(dids=[{'scope': scope, 'name': dsn}], account=account, copies=1, rse_expression=source_rse,
                                                     grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, issuer='root')
                            except InvalidReplicationRule, e:
                                print e
                    except RucioException, e:
                        print e

# createRSEs()
# createMetadata()
populateDB()
