# -*- coding: utf-8 -*-
# Copyright 2017-2021 CERN
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
# - Martin Barisits <martin.barisits@cern.ch>, 2017-2021
# - Tomas Javurek <tomas.javurek@cern.ch>, 2018-2019
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020

"""
This script is to be used to background rebalance ATLAS t2 datadisks
"""
from __future__ import print_function, division

from sqlalchemy import or_

from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rse import get_rse_usage, get_rse_attribute
from rucio.daemons.bb8.common import rebalance_rse
from rucio.db.sqla import models
from rucio.db.sqla.session import get_session
from rucio.db.sqla.constants import RuleState


tolerance = 0.15
max_total_rebalance_volume = 200 * 1E12
max_rse_rebalance_volume = 20 * 1E12
min_total = 50 * 1E12
total_rebalance_volume = 0


# groupdisks
def group_space(site):
    """
    groupdisks of given site
    contributing to primaries
    """
    site_groupdisks = []
    group_total = 0
    try:
        site_groupdisks = parse_expression('site=%s&spacetoken=ATLASDATADISK&type=GROUPDISK' % site)
    except:
        return group_total

    for rse in site_groupdisks:
        used = get_rse_usage(rse_id=rse['id'], source='rucio')[0]['used']
        group_total += used

    return group_total


# Calculate the current ratios
rses = parse_expression("(datapolicynucleus=true|tier=1)&type=DATADISK\\bb8-enabled=false")
total_primary = 0
total_secondary = 0
total_total = 0
global_ratio = float(0)
for rse in rses:
    site_name = get_rse_attribute(key='site', rse_id=rse['id'])[0]
    rse['groupdisk'] = group_space(site_name)
    rse['primary'] = get_rse_usage(rse_id=rse['id'], source='rucio')[0]['used'] - get_rse_usage(rse_id=rse['id'], source='expired')[0]['used']
    rse['primary'] += rse['groupdisk']
    rse['secondary'] = get_rse_usage(rse_id=rse['id'], source='expired')[0]['used']
    rse['total'] = get_rse_usage(rse_id=rse['id'], source='storage')[0]['total'] - get_rse_usage(rse_id=rse['id'], source='min_free_space')[0]['used']
    rse['ratio'] = float(rse['primary']) / float(rse['total'])
    total_primary += rse['primary']
    total_secondary += rse['secondary']
    total_total += float(rse['total'])
    rse['receive_volume'] = 0  # Already rebalanced volume in this run

global_ratio = float(total_primary) / float(total_total)
print('Global ratio: %f' % (global_ratio))
for rse in sorted(rses, key=lambda k: k['ratio']):
    print('  %s (%f)' % (rse['rse'], rse['ratio']))

rses_over_ratio = sorted([rse for rse in rses if rse['ratio'] > global_ratio + global_ratio * tolerance], key=lambda k: k['ratio'], reverse=True)
rses_under_ratio = sorted([rse for rse in rses if rse['ratio'] < global_ratio - global_ratio * tolerance], key=lambda k: k['ratio'], reverse=False)

session = get_session()
active_rses = session.query(models.ReplicationRule.rse_expression).filter(or_(models.ReplicationRule.state == RuleState.REPLICATING, models.ReplicationRule.state == RuleState.STUCK),
                                                                          models.ReplicationRule.comments == 'T2 Background rebalancing').group_by(models.ReplicationRule.rse_expression).all()

# Excluding RSEs
print('Excluding RSEs as destination which have active Background Rebalancing rules:')
for rse in active_rses:
    print('  %s' % (rse[0]))
    for des in rses_under_ratio:
        des_as_expr = des['rse']
        if des_as_expr == rse[0]:
            rses_under_ratio.remove(des)
            break

print('Excluding RSEs as destination which are too small by size:')
for des in rses_under_ratio:
    if des['total'] < min_total:
        print('  %s' % (des['rse']))
        rses_under_ratio.remove(des)

print('Excluding RSEs as sources which are too small by size:')
for src in rses_over_ratio:
    if src['total'] < min_total:
        print('  %s' % (src['rse']))
        rses_over_ratio.remove(src)

print('Excluding RSEs as destinations which are blocklisted:')
for des in rses_under_ratio:
    if des['availability'] != 7:
        print('  %s' % (des['rse']))
        rses_under_ratio.remove(des)

print('Excluding RSEs as sources which are blocklisted:')
for src in rses_over_ratio:
    if src['availability'] != 7:
        print('  %s' % (src['rse']))
        rses_over_ratio.remove(src)

# Loop over RSEs over the ratio
for source_rse in rses_over_ratio:

    # The volume that would be rebalanced, not real availability of the data:
    available_source_rebalance_volume = int((source_rse['primary'] - global_ratio * source_rse['secondary']) / (global_ratio + 1))
    if available_source_rebalance_volume > max_rse_rebalance_volume:
        available_source_rebalance_volume = max_rse_rebalance_volume
    if available_source_rebalance_volume > max_total_rebalance_volume - total_rebalance_volume:
        available_source_rebalance_volume = max_total_rebalance_volume - total_rebalance_volume

    # Select a target:
    for destination_rse in rses_under_ratio:
        if available_source_rebalance_volume > 0:
            if destination_rse['receive_volume'] >= max_rse_rebalance_volume:
                continue
            available_target_rebalance_volume = max_rse_rebalance_volume - destination_rse['receive_volume']
            if available_target_rebalance_volume >= available_source_rebalance_volume:
                available_target_rebalance_volume = available_source_rebalance_volume

            vo_str = 'on VO {}'.format(destination_rse['vo']) if destination_rse['vo'] != 'def' else 'def'
            print('Rebalance %dTB from %s(%f) to %s(%f)%s' % (available_target_rebalance_volume / 1E12, source_rse['rse'], source_rse['ratio'], destination_rse['rse'], destination_rse['ratio'], vo_str))
            expr = destination_rse['rse']
            rebalance_rse(rse_id=source_rse['id'], max_bytes=available_target_rebalance_volume, dry_run=False, comment='Nuclei Background rebalancing', force_expression=expr)

            destination_rse['receive_volume'] += available_target_rebalance_volume
            total_rebalance_volume += available_target_rebalance_volume
            available_source_rebalance_volume -= available_target_rebalance_volume
