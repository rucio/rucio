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

import os
import random
import sys
import time

from rucio.api.rse import add_rse, add_rse_attribute, add_file_replica, list_rses
from rucio.api.did import attach_identifier, add_identifier
from rucio.api.meta import add_key
from rucio.api.rule import add_replication_rule
from rucio.api.scope import add_scope
from rucio.api.account import add_account
from rucio.common.exception import InvalidReplicationRule
from rucio.common.exception import Duplicate
from rucio.common.utils import generate_uuid as uuid
from rucio.core import monitor


dictGroups = {'(null)': 'group0', '/atlas/dataprep/role=production': 'group1', '/atlas/det-indet/role=production': 'group2', '/atlas/det-larg/role=production': 'group3',
              '/atlas/det-muon/role=production': 'group4', '/atlas/perf-egamma/role=production': 'group5', '/atlas/perf-flavtag/role=production': 'group6', '/atlas/perf-jets/role=production': 'group7',
              '/atlas/perf-tau/role=production': 'group8', '/atlas/phys-beauty/role=production': 'group9', '/atlas/phys-exotics/role=production': 'group10', '/atlas/phys-higgs/role=production': 'group11',
              '/atlas/phys-sm/role=production': 'group12', '/atlas/phys-susy/role=production': 'group13', '/atlas/phys-top/role=production': 'group14', '/atlas/trig-daq/role=production': 'group15',
              '/atlas/trig-hlt/role=production': 'group16'}


def createScope():
    #add_account('panda', 'user', 'root')
    #add_account('tier0', 'user', 'root')
    #add_scope('data12_8TeV', 'root', 'root')
    add_scope('mc12_8TeV', 'root', 'root')
    for i in xrange(0, 20):
        print i
        group = 'group%i' % (i)
        try:
            add_account(group, 'user', 'root')
            add_scope('group.%s' % (group), group, 'root')
        except Duplicate, e:
            print e


def createMetadata():
    add_key('project', 'all', 'root')
    add_key('run_number', 'all', 'root')
    add_key('stream_name', 'all', 'root')
    add_key('prod_step', 'all', 'root')
    add_key('datatype', 'all', 'root')
    add_key('campaign', 'all', 'root')
    add_key('provenance', 'all', 'root')
    add_key('group', 'all', 'root')


def createRSEs():
    #Add test RSEs
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


def populateDB(filename=None):
    listrses = list_rses(filters={'deterministic': 1})
    print listrses
    listrses = map(lambda x: x['rse'], listrses)
    account = 'root'
    nbDatasets = 0
    list = []
    dictDistrib = {}

    if not filename:
        if os.getenv('RUCIO_HOME'):
            filename = os.getenv('RUCIO_HOME') + '/etc/data12_8TeV_distribution.txt'
        else:
            filename = '/opt/rucio/etc/data12_8TeV_distribution.txt'

    # Get the dataset distribution
    f = open(filename, 'r')
    for line in f:
        if not line.startswith('NBDATASETS'):
            line = line.rstrip('\n')
            strsplit = line.split()
            dictDistrib[(nbDatasets, nbDatasets + int(strsplit[0]))] = strsplit[1:]
            nbDatasets += int(strsplit[0])
            list.append([nbDatasets, ] + strsplit[1:])
    f.close()

    # Generate 200000 datasets according to the dataset distribution
    for i in xrange(0, 200000):
        rnd = random.random() * nbDatasets
        for lower, upper in dictDistrib:
            if (rnd > lower) and (rnd < upper):
                project = dictDistrib[lower, upper][0]
                scope = project
                run_number = random.randint(0, 1000000)
                tag = random.randint(0, 10000)
                stream_name = dictDistrib[lower, upper][1]
                prod_step = dictDistrib[lower, upper][2]
                datatype = dictDistrib[lower, upper][3]
                provenance = dictDistrib[lower, upper][4]
                group = dictDistrib[lower, upper][5]
                if group == '/atlas/role=production':
                    #account = 'atlasprod'
                    account = 'panda'
                    if provenance == 'T0':
                        group = 'tier0'
                        account = 'tier0'
                    else:
                        group = 'panda'
                else:
                    #account = dictGroups[group]
                    account = 'panda'
                    scope = 'group.%s' % (dictGroups[group])
                    group = dictGroups[group]
                nbfiles = int(dictDistrib[lower, upper][6])
                filesize = int(int(dictDistrib[lower, upper][7])/float(nbfiles))
                nbreplicas = int(dictDistrib[lower, upper][8])
                if group == 'panda' or group == 'tier0':
                    dataset_meta = {'project': project, 'run_number': run_number, 'stream_name': stream_name, 'prod_step': prod_step, 'datatype': datatype, 'provenance': provenance, 'group': group}
                else:
                    campaign = int(tag/1000.)
                    dataset_meta = {'project': project, 'run_number': run_number, 'stream_name': stream_name, 'prod_step': prod_step, 'datatype': datatype, 'provenance': provenance, 'group': group, 'campaign': '%s_repro_%i' % (group, campaign)}
                source_rses = []
                if nbreplicas:
                    iter = 0
                    while (len(source_rses) != nbreplicas and iter != 100):
                        rnd_site = random.choice(listrses)
                        iter += 1
                        if (not rnd_site in source_rses):
                            source_rses.append(rnd_site)

                    run_number_string = str(run_number)
                    run_number_string = run_number_string.rjust(7, '0')
                    dsn = '%s.%s.%s.%s.%s.%s' % (project, run_number_string, stream_name, prod_step, datatype, tag)
                    print '%i Creating %s:%s with %i files of size %i located at %i sites' % (i, scope, dsn, nbfiles, filesize, len(source_rses))
                    stime1 = time.time()
                    add_identifier(scope=scope, name=dsn, type='dataset', issuer=account, statuses={'monotonic': True}, meta=dataset_meta)
                    stime2 = time.time()
                    print 'Time to generate a dataset : %s' % str(stime2 - stime1)
                    monitor.record(timeseries='dbfiller.addnewdataset',  delta=1)
                    files = ['file_%s' % uuid() for i in xrange(nbfiles)]
                    listfiles = []
                    for file in files:
                        listfiles.append({'scope': scope, 'name': file, 'size': filesize})
                        for source_rse in source_rses:
                            add_file_replica(source_rse, scope, file, filesize, issuer=account)
                    stime3 = time.time()
                    print 'Time to create replicas : %s' % str(stime3 - stime2)
                    monitor.record(timeseries='dbfiller.addreplicas',  delta=nbfiles*len(source_rses))
                    attach_identifier(scope, name=dsn, dids=listfiles, issuer=account)
                    stime4 = time.time()
                    print 'Time to attach files : %s' % str(stime4 - stime3)
                    monitor.record(timeseries='dbfiller.addnewfile',  delta=nbfiles)
                    for source_rse in source_rses:
                        try:
                            add_replication_rule(dids=[{'scope': scope, 'name': dsn}], account=account, copies=1, rse_expression=source_rse,
                                                 grouping='DATASET', weight=None, lifetime=None, locked=False, subscription_id=None, issuer='root')
                            monitor.record(timeseries='dbfiller.addreplicationrules',  delta=1)
                        except InvalidReplicationRule, e:
                            print e
                    stime5 = time.time()
                    print 'Time to attach files : %s' % str(stime5 - stime4)


def main(argv):
    #createRSEs()
    #createMetadata()
    #createScope()
    filename = None
    try:
        filename = argv[0]
    except IndexError:
        print 'Will use the default file : data12_8TeV_distribution.txt'
    populateDB(filename)


if __name__ == '__main__':
    main(sys.argv[1:])
