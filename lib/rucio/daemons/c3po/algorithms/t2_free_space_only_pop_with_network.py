# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2016-2017

import logging
from operator import itemgetter

from rucio.common.config import config_get, config_get_int
from rucio.common.exception import DataIdentifierNotFound
from rucio.core.did import get_did
from rucio.core.replica import list_dataset_replicas
from rucio.core.rse import list_rse_attributes, get_rse
from rucio.core.rse_expression_parser import parse_expression
from rucio.daemons.c3po.collectors.free_space import FreeSpaceCollector
from rucio.daemons.c3po.collectors.network_metrics import NetworkMetricsCollector
from rucio.daemons.c3po.utils.dataset_cache import DatasetCache
from rucio.daemons.c3po.utils.expiring_dataset_cache import ExpiringDatasetCache
from rucio.daemons.c3po.utils.popularity import get_popularity
from rucio.daemons.c3po.utils.timeseries import RedisTimeSeries
from rucio.db.sqla.constants import ReplicaState


class PlacementAlgorithm:
    """
    Placement algorithm that focusses on free space on T2 DATADISK RSEs. It incorporates network metrics for placement decisions.
    """
    def __init__(self, datatypes, dest_rse_expr, max_bytes_hour, max_files_hour, max_bytes_hour_rse, max_files_hour_rse, min_popularity, min_recent_requests, max_replicas):
        self._fsc = FreeSpaceCollector()
        self._nmc = NetworkMetricsCollector()
        self._added_cache = ExpiringDatasetCache(config_get('c3po', 'redis_host'), config_get_int('c3po', 'redis_port'), timeout=86400)
        self._dc = DatasetCache(config_get('c3po', 'redis_host'), config_get_int('c3po', 'redis_port'), timeout=86400)
        self._added_bytes = RedisTimeSeries(config_get('c3po', 'redis_host'), config_get_int('c3po', 'redis_port'), window=3600, prefix="added_bytes_")
        self._added_files = RedisTimeSeries(config_get('c3po', 'redis_host'), config_get_int('c3po', 'redis_port'), window=3600, prefix="added_files_")

        self._datatypes = datatypes.split(',')
        self._dest_rse_expr = dest_rse_expr
        self._max_bytes_hour = max_bytes_hour
        self._max_files_hour = max_files_hour
        self._max_bytes_hour_rse = max_bytes_hour_rse
        self._max_files_hour_rse = max_files_hour_rse
        self._min_popularity = min_popularity
        self._min_recent_requests = min_recent_requests
        self._max_replicas = max_replicas

        rses = parse_expression(self._dest_rse_expr)

        self._rses = {}
        self._sites = {}
        for rse in rses:
            rse_attrs = list_rse_attributes(rse['rse'])
            rse_attrs['rse'] = rse['rse']
            self._rses[rse['rse']] = rse_attrs
            self._sites[rse_attrs['site']] = rse_attrs

        self._dst_penalties = {}
        self._src_penalties = {}

        self._print_params()

    def _print_params(self):
        logging.debug('Parameter Overview:')
        logging.debug('Algorithm: t2_free_space_only_pop_with_network')
        logging.debug('Datatypes: %s' % ','.join(self._datatypes))
        logging.debug('Max bytes/files per hour: %d / %d' % (self._max_bytes_hour, self._max_files_hour))
        logging.debug('Max bytes/files per hour per RSE: %d / %d' % (self._max_bytes_hour_rse, self._max_files_hour_rse))
        logging.debug('Min recent requests / Min popularity: %d / %d' % (self._min_recent_requests, self._min_popularity))
        logging.debug('Max existing replicas: %d' % self._max_replicas)

    def __update_penalties(self):
        for rse, penalty in self._dst_penalties.items():
            if penalty < 100.0:
                self._dst_penalties[rse] += 10.0

        for rse, penalty in self._src_penalties.items():
            if penalty < 100.0:
                self._src_penalties[rse] += 10.0

    def check_did(self, did):
        decision = {'did': ':'.join(did)}
        if (self._added_cache.check_dataset(':'.join(did))):
            decision['error_reason'] = 'already added replica for this did in the last 24h'
            return decision

        if (not did[0].startswith('data')) and (not did[0].startswith('mc')):
            decision['error_reason'] = 'not a data or mc dataset'
            return decision

        datatype = did[1].split('.')[4].split('_')[0]

        if datatype not in self._datatypes:
            decision['error_reason'] = 'wrong datatype'
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

        total_added_bytes = sum(self._added_bytes.get_series('total'))
        total_added_files = sum(self._added_files.get_series('total'))

        logging.debug("total_added_bytes: %d" % total_added_bytes)
        logging.debug("total_added_files: %d" % total_added_files)

        if ((total_added_bytes + meta['bytes']) > self._max_bytes_hour):
            decision['error_reason'] = 'above bytes limit of %d bytes' % self._max_bytes_hour
            return decision
        if ((total_added_files + meta['length']) > self._max_files_hour):
            decision['error_reason'] = 'above files limit of %d files' % self._max_files_hour
            return decision

        last_accesses = self._dc.get_did(did)
        self._dc.add_did(did)

        decision['last_accesses'] = last_accesses

        try:
            pop = get_popularity(did)
            decision['popularity'] = pop or 0.0
        except Exception:
            decision['error_reason'] = 'problems connecting to ES'
            return decision

        if (last_accesses < self._min_recent_requests) and (pop < self._min_popularity):
            decision['error_reason'] = 'did not popular enough'
            return decision

        return decision

    def place(self, did):
        self.__update_penalties()
        self._added_bytes.trim()
        self._added_files.trim()

        decision = self.check_did(did)

        if 'error_reason' in decision:
            return decision

        meta = get_did(did[0], did[1])
        available_reps = {}
        reps = list_dataset_replicas(did[0], did[1])
        num_reps = 0
        space_info = self._fsc.get_rse_space()
        max_mbps = 0.0
        for rep in reps:
            rse_attr = list_rse_attributes(rep['rse'])
            src_rse = rep['rse']
            if 'site' not in rse_attr:
                continue

            src_site = rse_attr['site']
            src_rse_info = get_rse(src_rse)

            if 'type' not in rse_attr:
                continue
            if rse_attr['type'] != 'DATADISK':
                continue
            if src_rse_info['availability'] & 4 == 0:
                continue

            if rep['state'] == ReplicaState.AVAILABLE:
                if rep['available_length'] == 0:
                    continue
                net_metrics = {}
                net_metrics_type = None
                for metric_type in ('fts', 'fax', 'perfsonar', 'dashb'):
                    net_metrics_type = metric_type
                    net_metrics = self._nmc.getMbps(src_site, metric_type)
                    if net_metrics:
                        break
                if len(net_metrics) == 0:
                    continue
                available_reps[src_rse] = {}
                for dst_site, mbps in net_metrics.items():
                    if src_site == dst_site:
                        continue
                    if dst_site in self._sites:
                        if mbps > max_mbps:
                            max_mbps = mbps
                        dst_rse = self._sites[dst_site]['rse']
                        dst_rse_info = get_rse(dst_rse)

                        if dst_rse_info['availability'] & 2 == 0:
                            continue

                        site_added_bytes = sum(self._added_bytes.get_series(dst_rse))
                        site_added_files = sum(self._added_files.get_series(dst_rse))

                        if ((site_added_bytes + meta['bytes']) > self._max_bytes_hour_rse):
                            continue
                        if ((site_added_files + meta['length']) > self._max_files_hour_rse):
                            continue

                        queued = self._nmc.getQueuedFiles(src_site, dst_site)

                        # logging.debug('queued %s -> %s: %d' % (src_site, dst_site, queued))
                        if queued > 0:
                            continue
                        rse_space = space_info.get(dst_rse, {'free': 0, 'total': 1})
                        if src_rse not in self._src_penalties:
                            self._src_penalties[src_rse] = 100.0
                        src_penalty = self._src_penalties[src_rse]
                        if dst_rse not in self._dst_penalties:
                            self._dst_penalties[dst_rse] = 100.0
                        dst_penalty = self._dst_penalties[dst_rse]

                        free_space = float(rse_space['free']) / float(rse_space['total']) * 100.0
                        available_reps[src_rse][dst_rse] = {'free_space': free_space, 'src_penalty': src_penalty, 'dst_penalty': dst_penalty, 'mbps': float(mbps), 'metrics_type': net_metrics_type}

                num_reps += 1

        # decision['replica_rses'] = available_reps
        decision['num_replicas'] = num_reps

        if num_reps >= 5:
            decision['error_reason'] = 'more than 4 replicas already exist'
            return decision

        src_dst_ratios = []

        if max_mbps == 0.0:
            decision['error_reason'] = 'could not find enough network metrics'
            return decision

        for src, dsts in available_reps.items():
            for dst, metrics in dsts.items():
                if dst in available_reps:
                    continue
                bdw = (metrics['mbps'] / max_mbps) * 100.0
                src_penalty = self._src_penalties[src]
                dst_penalty = self._dst_penalties[dst]

                ratio = ((metrics['free_space'] / 4.0) + bdw) * src_penalty * dst_penalty
                src_dst_ratios.append((src, dst, ratio))

        if len(src_dst_ratios) == 0:
            decision['error_reason'] = 'found no suitable src/dst for replication'
            return decision

        sorted_ratios = sorted(src_dst_ratios, key=itemgetter(2), reverse=True)
        logging.debug(sorted_ratios)
        destination_rse = sorted_ratios[0][1]
        source_rse = sorted_ratios[0][0]
        decision['destination_rse'] = destination_rse
        decision['source_rse'] = source_rse
        # decision['rse_ratios'] = src_dst_ratios
        self._dst_penalties[destination_rse] = 10.0
        self._src_penalties[source_rse] = 10.0

        self._added_cache.add_dataset(':'.join(did))

        self._added_bytes.add_point(destination_rse, meta['bytes'])
        self._added_files.add_point(destination_rse, meta['length'])

        self._added_bytes.add_point('total', meta['bytes'])
        self._added_files.add_point('total', meta['length'])

        return decision
