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

from json import loads

from requests import get

from rucio.common.config import config_get


class MappingCollector(object):
    """
    Provides mappings from PanDA / DDM resources to ATLAS sites and back.
    """
    class _MappingCollector(object):
        '''
        _MappingCollector
        '''

        def __init__(self):
            '''
            __init__
            '''
            self._fetch_panda_mapping()
            self._fetch_ddm_mapping()

        def _fetch_panda_mapping(self):
            '''
            _fetch_panda_mapping
            '''
            result = get(config_get('c3po-site-mapper', 'panda_url'))
            data = loads(result.text)
            self.panda_to_site = {}
            self.site_to_panda = {}

            for entry in data:
                self.panda_to_site[entry['panda_resource']] = entry['atlas_site']
                if entry['atlas_site'] not in self.site_to_panda:
                    self.site_to_panda[entry['atlas_site']] = []
                self.site_to_panda[entry['atlas_site']].append(entry['panda_resource'])

        def _fetch_ddm_mapping(self):
            '''
            _fetch_ddm_mapping
            '''
            result = get(config_get('c3po-site-mapper', 'ddm_url'))
            data = loads(result.text)
            self.site_to_ddm = {}
            self.ddm_to_site = {}

            for entry in data:
                self.ddm_to_site[entry['name']] = entry['site']
                if entry['site'] not in self.site_to_ddm:
                    self.site_to_ddm[entry['site']] = []
                self.site_to_ddm[entry['site']].append(entry['name'])

    instance = None

    def __init__(self):
        '''
        __init__
        '''
        if not MappingCollector.instance:
            MappingCollector.instance = MappingCollector._MappingCollector()

    def ddm_to_site(self, ddm):
        '''
        ddm_to_site
        '''
        if ddm not in self.instance.ddm_to_site:
            return None
        return self.instance.ddm_to_site[ddm]

    def panda_to_site(self, panda):
        '''
        panda_to_site
        '''
        if panda not in self.instance.panda_to_site:
            return None
        return self.instance.panda_to_site[panda]

    def site_to_ddm(self, site):
        '''
        site_to_ddm
        '''
        if site not in self.instance.site_to_ddm:
            return None
        return self.instance.site_to_ddm[site]

    def site_to_panda(self, site):
        '''
        site_to_panda
        '''
        if site not in self.instance.site_to_panda:
            return None
        return self.instance.site_to_panda[site]
