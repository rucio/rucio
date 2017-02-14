# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2016-2017

"""
This script is to be used to background rebalance ATLAS Nuclei datadisks
"""

from sqlalchemy import or_

from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rse import get_rse_usage
from rucio.daemons.bb8.common import rebalance_rse
from rucio.db.sqla import models
from rucio.db.sqla.session import get_session
from rucio.db.sqla.constants import RuleState


tolerance = 0.1
max_total_rebalance_volume = 200 * 1E12
max_rse_rebalance_volume = 20 * 1E12

total_rebalance_volume = 0

# Calculate the current ratios
rses = parse_expression('(datapolicynucleus=1|tier=1)&type=DATADISK')
total_primary = 0
total_secondary = 0
global_ratio = float(0)
for rse in rses:
    rse['primary'] = get_rse_usage(rse=None, rse_id=rse['id'], source='rucio')[0]['used']
    rse['secondary'] = get_rse_usage(rse=None, rse_id=rse['id'], source='expired')[0]['used']
    rse['ratio'] = float(rse['primary']) / float(rse['secondary'])
    total_primary += rse['primary']
    total_secondary += rse['secondary']
    rse['receive_volume'] = 0  # Already rebalanced volume in this run
global_ratio = float(total_primary) / float(total_secondary)

print 'Global ratio: %f' % (global_ratio)
for rse in sorted(rses, key=lambda k: k['ratio']):
    print '  %s (%f)' % (rse['rse'], rse['ratio'])

rses_over_ratio = sorted([rse for rse in rses if rse['ratio'] > global_ratio + global_ratio * tolerance], key=lambda k: k['ratio'], reverse=True)
rses_under_ratio = sorted([rse for rse in rses if rse['ratio'] < global_ratio - global_ratio * tolerance], key=lambda k: k['ratio'], reverse=False)

session = get_session()
active_rses = session.query(models.ReplicationRule.rse_expression).filter(or_(models.ReplicationRule.state == RuleState.REPLICATING, models.ReplicationRule.state == RuleState.STUCK),
                                                                          models.ReplicationRule.comments == 'Nuclei Background rebalancing').group_by(models.ReplicationRule.rse_expression).all()
print 'Excluding RSEs as destination which have active Background Rebalancing rules:'
for rse in active_rses:
    print '  %s' % (rse[0])
    for des in rses_under_ratio:
        if des['rse'] == rse[0]:
            rses_under_ratio.remove(des)
            break

# Loop over RSEs over the ratio
for source_rse in rses_over_ratio:
    if source_rse['ratio'] > global_ratio + global_ratio * tolerance:
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

                print 'Rebalance %dTB from %s(%f) to %s(%f)' % (available_target_rebalance_volume / 1E12, source_rse['rse'], source_rse['ratio'], destination_rse['rse'], destination_rse['ratio'])
                rebalance_rse(source_rse['rse'], max_bytes=available_target_rebalance_volume, dry_run=False, comment='Nuclei Background rebalancing', force_expression=destination_rse['rse'])

                destination_rse['receive_volume'] += available_target_rebalance_volume
                total_rebalance_volume += available_target_rebalance_volume
                available_source_rebalance_volume -= available_target_rebalance_volume
