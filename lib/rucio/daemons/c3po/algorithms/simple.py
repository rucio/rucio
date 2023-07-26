# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
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

import logging
from operator import itemgetter
from random import shuffle

from rucio.common.exception import DataIdentifierNotFound
from rucio.core.did import get_did
from rucio.core.replica import list_dataset_replicas
from rucio.daemons.c3po.collectors.agis import MappingCollector
from rucio.daemons.c3po.collectors.workload import WorkloadCollector
from rucio.db.sqla.constants import ReplicaState


class PlacementAlgorithm:
    def __init__(self):
        self._mc = MappingCollector()
        self._wc = WorkloadCollector()
        self.__setup_penalties()

    def __setup_penalties(self):
        self._penalties = {}
        for panda_site in self._wc.get_sites():
            site = self._mc.panda_to_site(panda_site)
            self._penalties[site] = 0.1

    def __update_penalties(self):
        for site, penalty in self._penalties.items():
            if penalty > 0.1:
                self._penalties[site] = penalty - 0.1

    def place(self, did):
        self.__update_penalties()
        decision = {'did': '{}:{}'.format(did['scope'].internal, did['name'])}
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

        available_rses = []
        available_sites = []
        reps = list_dataset_replicas(did[0], did[1])

        num_reps = 0
        for rep in reps:
            if rep['state'] == ReplicaState.AVAILABLE:
                available_rses.append(rep['rse'])
                available_sites.append(self._mc.ddm_to_site(rep['rse']))
                num_reps += 1

        decision['replica_rses'] = available_rses
        decision['num_replicas'] = num_reps
        if num_reps >= 5:
            decision['error_reason'] = 'more than 4 replicas already exist'
            return decision

        site_ratios = {}
        site_job_info = {}
        for panda_site in self._wc.get_sites():
            site = self._mc.panda_to_site(panda_site)
            job_info = self._wc.get_job_info(panda_site)
            ratio = float(job_info[0]) / (float(job_info[1]) + float(job_info[2]) / 2)
            penalty = self._penalties[site]
            site_ratios[site] = ratio * penalty
            site_job_info[site] = (job_info, penalty)

        decision['site_ratios'] = site_ratios
        decision['site_job_info'] = site_job_info
        picked_site = None
        picked_rse = None

        for site, _ in sorted(site_ratios.items(), key=itemgetter(1)):
            if site in available_sites:
                continue
            rses_for_site = self._mc.site_to_ddm(site)
            if rses_for_site is None:
                continue

            for rse in rses_for_site:
                if 'DATADISK' in rse:
                    picked_rse = rse
                    picked_site = site
                    break
            if picked_rse:
                break

        if picked_rse is None:
            decision['error_reason'] = 'could not pick RSE'
            return decision

        decision['destination_rse'] = picked_rse
        if picked_site:
            self._penalties[site] = 1

        picked_source = None
        shuffle(available_rses)
        for rse in available_rses:
            if 'TAPE' in rse:
                continue
            picked_source = rse
            break

        if picked_source is None:
            picked_source = available_rses[0]

        decision['source_rse'] = picked_source
        logging.debug("Picked %s as source and %s as destination RSE" % (picked_source, picked_rse))

        return decision
