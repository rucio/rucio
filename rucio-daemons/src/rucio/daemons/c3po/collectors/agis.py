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
from typing import Optional

from requests import get

from rucio.core.common.config import config_get


class MappingCollector:
    """
    Provides mappings from PanDA / DDM resources to ATLAS sites and back.
    """
    class _MappingCollector:
        '''
        _MappingCollector
        '''

        def __init__(self):
            '''
            __init__
            '''
            self._fetch_panda_mapping()
            self._fetch_ddm_mapping()

        def _fetch_panda_mapping(self) -> None:
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

        def _fetch_ddm_mapping(self) -> None:
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

    def ddm_to_site(self, ddm: str) -> Optional[str]:
        '''
        ddm_to_site
        '''
        if ddm not in self.instance.ddm_to_site:  # type: ignore
            return None
        return self.instance.ddm_to_site[ddm]  # type: ignore

    def panda_to_site(self, panda: str) -> Optional[str]:
        '''
        panda_to_site
        '''
        if panda not in self.instance.panda_to_site:  # type: ignore
            return None
        return self.instance.panda_to_site[panda]  # type: ignore

    def site_to_ddm(self, site: str) -> Optional[str]:
        '''
        site_to_ddm
        '''
        if site not in self.instance.site_to_ddm:  # type: ignore
            return None
        return self.instance.site_to_ddm[site]  # type: ignore

    def site_to_panda(self, site: str) -> Optional[str]:
        '''
        site_to_panda
        '''
        if site not in self.instance.site_to_panda:  # type: ignore
            return None
        return self.instance.site_to_panda[site]  # type: ignore
