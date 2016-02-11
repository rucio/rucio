# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2016

import logging
from operator import itemgetter

from rucio.common.config import config_get, config_get_int
from rucio.common.exception import DataIdentifierNotFound
from rucio.core.did import get_did
from rucio.core.replica import list_dataset_replicas
from rucio.core.rse import list_rse_attributes
from rucio.core.rse_expression_parser import parse_expression
from rucio.daemons.c3po.collectors.free_space import FreeSpaceCollector
from rucio.daemons.c3po.collectors.network_metrics import NetworkMetricsCollector
from rucio.daemons.c3po.utils.dataset_cache import DatasetCache
from rucio.daemons.c3po.utils.expiring_dataset_cache import ExpiringDatasetCache
from rucio.daemons.c3po.utils.popularity import get_popularity
from rucio.db.sqla.constants import ReplicaState


class PlacementAlgorithm:
    """
    Placement algorithm that focusses on free space on T2 DATADISK RSEs.
    """
    def __init__(self):
        self._fsc = FreeSpaceCollector()
        self._nmc = NetworkMetricsCollector()
        self._added_cache = ExpiringDatasetCache(config_get('c3po', 'redis_host'), config_get_int('c3po', 'redis_port'), timeout=86400)
        self._dc = DatasetCache(config_get('c3po', 'redis_host'), config_get_int('c3po', 'redis_port'), timeout=86400)

        rse_expr = "tier=2&type=DATADISK"
        rses = parse_expression(rse_expr)

        self._rses = {}
        self._sites = {}
        for rse in rses:
            rse_attrs = list_rse_attributes(rse['rse'])
            rse_attrs['rse'] = rse['rse']
            self._rses[rse['rse']] = rse_attrs
            self._sites[rse_attrs['site']] = rse_attrs

        self.__setup_penalties()

    def __setup_penalties(self):
        self._penalties = {}
        for rse, _ in self._rses.items():
            self._penalties[rse] = 1.0

    def __update_penalties(self):
        for rse, penalty in self._penalties.items():
            if penalty > 1.0:
                self._penalties[rse] = penalty - 1

    def place(self, did):
        self.__update_penalties()
        decision = {'did': ':'.join(did)}
        if (self._added_cache.check_dataset(':'.join(did))):
            decision['error_reason'] = 'already added replica for this did in the last 24h'
            return decision

        if (not did[0].startswith('data')) and (not did[0].startswith('mc')):
            decision['error_reason'] = 'not a data or mc dataset'
            return decision

        try:
            meta = get_did(did[0], did[1])
        except DataIdentifierNotFound:
            decision['error_reason'] = 'did does not exist'
            return decision
        if meta['length'] is None:
            meta['length'] = 0
        if meta['bytes'] is None:
            meta['bytes'] = 0
        logging.debug('got %s:%s, num_files: %d, bytes: %d' % (did[0], did[1], meta['length'], meta['bytes']))

        decision['length'] = meta['length']
        decision['bytes'] = meta['bytes']

        last_accesses = self._dc.get_did(did)
        self._dc.add_did(did)

        decision['last_accesses'] = last_accesses

        pop = get_popularity(did)
        decision['popularity'] = pop or 0.0

        if (last_accesses < 5) and (pop < 8.0):
            decision['error_reason'] = 'did not popular enough'
            return decision

        available_reps = {}
        reps = list_dataset_replicas(did[0], did[1])
        num_reps = 0
        space_info = self._fsc.get_rse_space()
        max_mbps = 0.0
        for rep in reps:
            rse_attr = list_rse_attributes(rep['rse'])
            if 'type' not in rse_attr:
                continue
            if rse_attr['type'] != 'DATADISK':
                continue
            if rep['state'] == ReplicaState.AVAILABLE:
                net_metrics = {}
                for metric_type in ('fts', 'fax', 'perfsonar'):
                    net_metrics = self._nmc.getConnections(rse_attr['site'], metric_type)
                    if net_metrics:
                        break
                if len(net_metrics) == 0:
                    continue
                available_reps[rep['rse']] = {}
                for dst_site, mbps in net_metrics.items():
                    if dst_site in self._sites:
                        if mbps > max_mbps:
                            max_mbps = mbps
                        dst_rse = self._sites[dst_site]['rse']
                        rse_space = space_info[dst_rse]
                        penalty = self._penalties[dst_rse]
                        free_space = float(rse_space['free']) / float(rse_space['total']) * 100.0
                        available_reps[rep['rse']][dst_rse] = {'free_space': free_space, 'penalty': penalty, 'mbps': float(mbps)}

                num_reps += 1

        # decision['replica_rses'] = available_reps
        decision['num_replicas'] = num_reps

        if num_reps >= 5:
            decision['error_reason'] = 'more than 4 replicas already exist'
            return decision

        src_dst_ratios = []

        for src, dsts in available_reps.items():
            for dst, metrics in dsts.items():
                bdw = metrics['mbps'] / max_mbps * 100.0
                ratio = metrics['free_space'] * bdw * penalty
                src_dst_ratios.append((src, dst, ratio))

        if len(src_dst_ratios) == 0:
            decision['error_reason'] = 'found no suitable src/dst for replication'
            return decision

        sorted_ratios = sorted(src_dst_ratios, key=itemgetter(2), reverse=True)
        logging.debug(sorted_ratios)
        decision['destination_rse'] = sorted_ratios[0][1]
        decision['source_rse'] = sorted_ratios[0][0]
        decision['rse_ratios'] = src_dst_ratios
        self._penalties[sorted_ratios[0][0]] = 10.0

        self._added_cache.add_dataset(':'.join(did))

        return decision
