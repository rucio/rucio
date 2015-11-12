# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2015

from json import loads
from requests import get

from rucio.common.config import config_get


class MappingCollector:
    """
    Provides mappings from PanDA / DDM resources to ATLAS sites and back.
    """
    class __MappingCollector:
        def __init__(self):
            self._fetchPandaMapping()
            self._fetchDDMMapping()

        def _fetchPandaMapping(self):
            r = get(config_get('c3po-site-mapper', 'panda_url'))
            data = loads(r.text)
            self._panda_to_site = {}
            self._site_to_panda = {}

            for entry in data:
                self._panda_to_site[entry['panda_resource']] = entry['atlas_site']
                if entry['atlas_site'] not in self._site_to_panda:
                    self._site_to_panda[entry['atlas_site']] = []
                self._site_to_panda[entry['atlas_site']].append(entry['panda_resource'])

        def _fetchDDMMapping(self):
            r = get(config_get('c3po-site-mapper', 'ddm_url'))
            data = loads(r.text)
            self._site_to_ddm = {}
            self._ddm_to_site = {}

            for entry in data:
                self._ddm_to_site[entry['name']] = entry['site']
                if entry['site'] not in self._site_to_ddm:
                    self._site_to_ddm[entry['site']] = []
                self._site_to_ddm[entry['site']].append(entry['name'])

    instance = None

    def __init__(self):
        if not MappingCollector.instance:
            MappingCollector.instance = MappingCollector.__MappingCollector()

    def ddm_to_site(self, ddm):
        if ddm not in self.instance._ddm_to_site:
            return None
        return self.instance._ddm_to_site[ddm]

    def panda_to_site(self, panda):
        if panda not in self.instance._panda_to_site:
            return None
        return self.instance._panda_to_site[panda]

    def site_to_ddm(self, site):
        if site not in self.instance._site_to_ddm:
            return None
        return self.instance._site_to_ddm[site]

    def site_to_panda(self, site):
        if site not in self.instance._site_to_panda:
            return None
        return self.instance._site_to_panda[site]
