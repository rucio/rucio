# -*- coding: utf-8 -*-
# Copyright CERN since 2015
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

"""
C3PO PanDA workload collector
"""

from __future__ import division

import logging
from json import loads
from time import time

from requests import get

from rucio.common.config import config_get, config_get_int
from rucio.daemons.c3po.utils.timeseries import RedisTimeSeries


class WorkloadCollector(object):
    """
    Collector to retrieve the workload from PanDA. It stores it as a time series in Redis and provides
    the average and maximum number of running jobs for a sliding window.
    """

    class __WorkloadCollector(object):
        """
        Private class needed implement singleton.
        """
        def __init__(self, delete_keys=False):
            self._avg_jobs = {}
            self._cur_jobs = {}
            self._max_jobs = {}
            self._tms = RedisTimeSeries(config_get('c3po', 'redis_host'), config_get_int('c3po', 'redis_port'), config_get_int('c3po-workload', 'window'), 'jobs_')

            self._request_headers = {"Accept": "application/json", "Content-Type": "application/json"}
            self._request_url = config_get('c3po-workload', 'panda_url')
            if delete_keys:
                self._tms.delete_keys()
            self.reload_cache()

        def reload_cache(self):
            self._tms.trim()

            for key in self._tms.get_keys():
                site = "_".join(key.split('_')[1:])
                job_series = self._tms.get_series(site)
                num_jobs = len(job_series)
                if num_jobs > 0:
                    self._avg_jobs[site] = sum(job_series) / num_jobs
                    self._max_jobs[site] = max(job_series)
                    self._cur_jobs[site] = job_series[-1]

        def collect_workload(self):
            start = time()
            resp = get(self._request_url, headers=self._request_headers)
            logging.debug("PanDA response took %fs" % (time() - start))

            start = time()
            jobs = loads(resp.text)['jobs']
            logging.debug("decoding JSON response took %fs" % (time() - start))
            sites = {}

            start = time()
            for job in jobs:
                if job['computingsite'] not in sites:
                    sites[job['computingsite']] = 0
                sites[job['computingsite']] += 1
            for site, jobs in sites.items():
                self._tms.add_point(site, jobs)

            logging.debug("processing took %fs" % (time() - start))
            self.reload_cache()

    instance = None

    def __init__(self):
        if not WorkloadCollector.instance:
            WorkloadCollector.instance = WorkloadCollector.__WorkloadCollector()

    def get_avg_jobs(self, site):
        return self.instance._avg_jobs[site]

    def get_max_jobs(self, site):
        return self.instance._max_jobs[site]

    def get_cur_jobs(self, site):
        return self.instance._cur_jobs[site]

    def get_sites(self):
        return list(self.instance._avg_jobs.keys())

    def get_job_info(self, site):
        return (self.get_cur_jobs(site), self.get_avg_jobs(site), self.get_max_jobs(site))

    def get_series(self, site):
        return self.instance._tms.get_series(site)

    def collect_workload(self):
        self.instance.collect_workload()
