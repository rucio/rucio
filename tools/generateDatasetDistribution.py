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

from rucio.api.rse import add_rse, add_rse_attribute, add_file_replica, list_rses
from rucio.api.did import attach_identifier, add_identifier
from rucio.api.meta import add_key
from rucio.api.rule import add_replication_rule
from rucio.common.exception import InvalidReplicationRule
from rucio.common.utils import generate_uuid as uuid


dictGroups = {'(null)': 'group0', '/atlas/dataprep/role=production': 'group1', '/atlas/det-indet/role=production': 'group2', '/atlas/det-larg/role=production': 'group3',
              '/atlas/det-muon/role=production': 'group4', '/atlas/perf-egamma/role=production': 'group5', '/atlas/perf-flavtag/role=production': 'group6', '/atlas/perf-jets/role=production': 'group7',
              '/atlas/perf-tau/role=production': 'group8', '/atlas/phys-beauty/role=production': 'group9', '/atlas/phys-exotics/role=production': 'group10', '/atlas/phys-higgs/role=production': 'group11',
              '/atlas/phys-sm/role=production': 'group12', '/atlas/phys-susy/role=production': 'group13', '/atlas/phys-top/role=production': 'group14', '/atlas/trig-daq/role=production': 'group15',
              '/atlas/trig-hlt/role=production': 'group16'}


def createMetadata():
    add_key('project', 'all', 'root')
    add_key('run_number', 'all', 'root')
    add_key('stream_name', 'all', 'root')
    add_key('prod_step', 'all', 'root')
    add_key('datatype', 'all', 'root')
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
                uid = uuid()
                project = dictDistrib[lower, upper][0]
                scope = project
                run_number = str(uid)
                stream_name = dictDistrib[lower, upper][1]
                prod_step = dictDistrib[lower, upper][2]
                datatype = dictDistrib[lower, upper][3]
                provenance = dictDistrib[lower, upper][4]
                group = dictDistrib[lower, upper][5]
                if group == '/atlas/role=production':
                    account = 'atlasprod'
                    if provenance == 'T0':
                        group = 'tier0'
                    else:
                        group = 'panda'
                else:
                    account = dictGroups[group]
                    scope = 'group.%s' % (dictGroups[group])
                    group = dictGroups[group]
                nbfiles = int(dictDistrib[lower, upper][6])
                filesize = int(int(dictDistrib[lower, upper][7])/float(nbfiles))
                nbreplicas = int(dictDistrib[lower, upper][8])
                dataset_meta = {'project': project, 'run_number': run_number, 'stream_name': stream_name, 'prod_step': prod_step, 'datatype': datatype, 'provenance': provenance, 'group': group}
                source_rses = []
                if nbreplicas:
                    iter = 0
                    while (len(source_rses) != nbreplicas and iter != 100):
                        rnd_site = random.choice(listrses)
                        iter += 1
                        if (not rnd_site in source_rses):
                            source_rses.append(rnd_site)

                    dsn = '%s.%s.%s.%s.%s' % (project, run_number, stream_name, prod_step, datatype)
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


def main(argv):
    #createRSEs()
    #createMetadata()
    filename = None
    try:
        filename = argv[0]
    except IndexError:
        print 'Will use the default file : data12_8TeV_distribution.txt'
    populateDB(filename)


if __name__ == '__main__':
    main(sys.argv[1:])
