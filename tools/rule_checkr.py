#!/usr/bin/env python

# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2013

"""
Rule checker which checks the validity of rules
"""

import argparse
import os
import sys

from tabulate import tabulate
from sqlalchemy.sql.expression import and_

from rucio.core.did import list_child_dids
from rucio.core.rse_expression_parser import parse_expression
from rucio.db import models
from rucio.db.constants import DIDType
from rucio.db.session import get_session


def check_rule(rule, session):
    """
    Checks a rule
    Returns a report object
    """

    report = {'rule_id': rule.id,
              'num_files': 0,
              'did_type': None,
              'num_datasets': None,  # In case of a container
              'missing_locks': 0,
              'locks_placed_wrong': 0,
              'missing_replicas': 0,
              'failed_parse': 0}

    try:
        rse_set = parse_expression(expression=rule.rse_expression, session=session)
    except:
        report['failed_parse'] = 1
        return report

    did_type = session.query(models.DataIdentifier.did_type).filter_by(scope=rule.scope, name=rule.name).one()[0]
    report['did_type'] = str(did_type)

    if did_type == DIDType.CONTAINER:
        report['num_datasets'] = 0
        child_dids = list_child_dids(scope=rule.scope, name=rule.name, session=session)
        for did in child_dids:
            if did['type'] == DIDType.DATASET:
                report['num_datasets'] += 1
                files = session.query(models.DataIdentifierAssociation.child_scope, models.DataIdentifierAssociation.child_name).filter_by(scope=did['scope'], name=did['name']).all()
                report['num_files'] += len(files)
                report = check_locks(report=report,
                                     rule_id=rule.id,
                                     copies=rule.copies,
                                     rse_set=rse_set,
                                     grouping=rule.grouping,
                                     did=(did['scope'], did['name']),
                                     did_type=DIDType.DATASET,
                                     files=files,
                                     session=session)
                report = check_replicas(report=report,
                                        copies=rule.copies,
                                        rse_set=rse_set,
                                        did=(did['scope'], did['name']),
                                        did_type=DIDType.DATASET,
                                        files=files,
                                        session=session)
    elif did_type == DIDType.DATASET:
        files = session.query(models.DataIdentifierAssociation.child_scope, models.DataIdentifierAssociation.child_name).filter_by(scope=rule.scope, name=rule.name).all()
        report['num_files'] = len(files)
        report = check_locks(report=report,
                             rule_id=rule.id,
                             copies=rule.copies,
                             rse_set=rse_set,
                             grouping=rule.grouping,
                             did=(rule.scope, rule.name),
                             did_type=DIDType.DATASET,
                             files=files,
                             session=session)
        report = check_replicas(report=report,
                                copies=rule.copies,
                                rse_set=rse_set,
                                did=(rule.scope, rule.name),
                                did_type=DIDType.DATASET,
                                files=files,
                                session=session)
    else:
        report['num_files'] = 1
        report = check_locks(report=report,
                             rule_id=rule.id,
                             copies=rule.copies,
                             rse_set=rse_set,
                             grouping=rule.grouping,
                             did=(rule.scope, rule.name),
                             did_type=DIDType.FILE,
                             files=[(rule.scope, rule.name)],
                             session=session)
        report = check_replicas(report=report,
                                copies=rule.copies,
                                rse_set=rse_set,
                                did=(rule.scope, rule.name),
                                did_type=DIDType.DATASET,
                                files=[(rule.scope, rule.name)],
                                session=session)
    return report


def check_locks(report, rule_id, copies, rse_set, grouping, did, did_type, files, session):
    """
    Checks if the rule has the right locks
    """
    if did_type == DIDType.DATASET:
        locks = session.query(models.DataIdentifierAssociation.child_scope,
                              models.DataIdentifierAssociation.child_name,
                              models.ReplicaLock.rse_id,
                              models.ReplicaLock.state).join(models.ReplicaLock, and_(
                                  models.DataIdentifierAssociation.child_scope == models.ReplicaLock.scope,
                                  models.DataIdentifierAssociation.child_name == models.ReplicaLock.name)).filter(
                                      models.DataIdentifierAssociation.scope == did[0],
                                      models.DataIdentifierAssociation.name == did[1],
                                      models.ReplicaLock.rule_id == rule_id).all()
    else:
        locks = session.query(models.ReplicaLock.scope,
                              models.ReplicaLock.name,
                              models.ReplicaLock.rse_id,
                              models.ReplicaLock.state).filter_by(scope=did[0], name=did[1], rule_id=rule_id).all()
    did_dict = {}
    for file in files:
        did_dict[(file[0], file[1])] = {'locks': 0}

    for lock in locks:
        did_dict[(lock[0], lock[1])]['locks'] += 1
        if lock[2] not in rse_set:
            report['locks_placed_wrong'] += 1

    for elem in [tmp for tmp in did_dict.values() if tmp['locks'] != copies]:
        report['missing_locks'] += 1
    return report


def check_replicas(report, copies, rse_set, did, did_type, files, session):
    """
    Checks if the rule has the right replicas
    """
    if did_type == DIDType.DATASET:
        replicas = session.query(models.DataIdentifierAssociation.child_scope,
                                 models.DataIdentifierAssociation.child_name,
                                 models.RSEFileAssociation.rse_id).join(models.RSEFileAssociation, and_(
                                     models.DataIdentifierAssociation.child_scope == models.RSEFileAssociation.scope,
                                     models.DataIdentifierAssociation.child_name == models.RSEFileAssociation.name)).filter(
                                         models.DataIdentifierAssociation.scope == did[0],
                                         models.DataIdentifierAssociation.name == did[1]).all()
    else:
        replicas = session.query(models.RSEFileAssociation.scope,
                                 models.RSEFileAssociation.name,
                                 models.RSEFileAssociation.rse_id).filter_by(scope=did[0],
                                                                             name=did[1]).all()

    replica_dict = {}
    for replica in replicas:
        if (replica[0], replica[1]) in replica_dict:
            replica_dict[(replica[0], replica[1])]['rse_ids'].append(replica[2])
        else:
            replica_dict[(replica[0], replica[1])] = {'rse_ids': [replica[2]]}

    for file in files:
        rse_cnt = 0
        if (file[0], file[1]) not in replica_dict:
            report['missing_replicas'] += copies
            continue
        for rse in replica_dict[(file[0], file[1])]['rse_ids']:
            if rse in rse_set:
                rse_cnt += 1
        if rse_cnt < copies:
            report['missing_replicas'] += copies - rse_cnt

    return report


argparser = argparse.ArgumentParser(prog=os.path.basename(sys.argv[0]), add_help=True)

argparser.add_argument('--all', '-a', default=False, action='store_true', help="Scan all available rules")
argparser.add_argument('--fraction', '-f', help="Scan a fraction  of the available rules", type=float)
argparser.add_argument('--num', '-n', help="Scan a fixed number of available rules", type=int)

if len(sys.argv) == 1:
    argparser.print_help()
    sys.exit(-1)

args = argparser.parse_args()

#if args.all:
#    print 'all'
#elif args.fraction is not None:
#    print 'fraction'
#elif args.num is not None:
#    print 'num'

session = get_session()

total_cnt = session.query(models.ReplicationRule).count()
print "There are currently %d replication rules registered in Rucio" % total_cnt

if session.bind.dialect.name != 'sqlite':
    query = session.query(models.ReplicationRule).order_by('dbms_random.value')
else:
    query = session.query(models.ReplicationRule).order_by('RANDOM()')

if args.fraction is not None:
    print 'Reading up to %d rules (fraction=%f)' % (int(total_cnt * args.fraction), args.fraction)
    if args.fraction > 1 or args.fraction <= 0:
        raise ValueError('The fraction value must be between 0 and 1')
    query = query.limit(int(total_cnt * args.fraction))
elif args.num is not None:
    print 'Reading up to %d rules (num)' % args.num
    if args.num <= 0:
        raise ValueError('The num value must be bigger than 0')
    query = query.limit(args.num)
elif args.all:
    print 'Reading all rules'

overall_report = {'problematic_rules': 0,
                  'missing_locks': 0,
                  'locks_placed_wrong': 0,
                  'missing_replicas': 0,
                  'failed_parse': 0}
failed_rules = []

for rule in query.yield_per(100):
    report = check_rule(rule=rule, session=session)
    overall_report['missing_locks'] += report['missing_locks']
    overall_report['locks_placed_wrong'] += report['locks_placed_wrong']
    overall_report['missing_replicas'] += report['missing_replicas']
    overall_report['failed_parse'] += report['failed_parse']
    if report['missing_locks'] != 0 or report['locks_placed_wrong'] != 0 or report['missing_replicas'] != 0 or report['failed_parse'] != 0:
        overall_report['problematic_rules'] += 1
        failed_rules.append(report)
print 'Overall Report:'
print tabulate(overall_report.items())
print 'Detailed report of problematic rules:'
if failed_rules:
    print tabulate([item.values() for item in failed_rules], headers=failed_rules[0].keys())
