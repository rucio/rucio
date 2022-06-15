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

from json import dumps, loads
from requests import post
from requests.auth import HTTPBasicAuth

from rucio.common.config import config_get, config_get_options

ELASTIC_URL = config_get('es-atlas', 'url')

ELASTIC_OPTIONS = config_get_options('es-atlas')

AUTH = None
if ('username' in ELASTIC_OPTIONS) and ('password' in ELASTIC_OPTIONS):
    AUTH = HTTPBasicAuth(config_get('es-atlas', 'username'), config_get('es-atlas', 'password'))

if 'ca_cert' in ELASTIC_OPTIONS:
    ELASTIC_CA_CERT = config_get('es-atlas', 'ca_cert')
else:
    ELASTIC_CA_CERT = False

URL = ELASTIC_URL + '/atlas_rucio-popularity-*/_search'


def get_popularity(did):
    """
    Query the popularity for a given DID in the ElasticSearch popularity db.
    """
    query = {
        "query": {
            "bool": {
                "must": [{
                    "range": {
                        "timestamp": {
                            "gt": "now-7d",
                            "lt": "now"
                        }
                    }
                }]
            }
        },
        "aggs": {
            "pop": {"sum": {"field": "ops"}}
        },
        "size": 0
    }

    query['query']['bool']['must'].append({"term": {"scope": did[0].external}})
    query['query']['bool']['must'].append({"term": {"name": did[1]}})

    logging.debug(query)
    if AUTH:
        res = post(URL, data=dumps(query), auth=AUTH, verify=ELASTIC_CA_CERT)
    else:
        res = post(URL, data=dumps(query), verify=ELASTIC_CA_CERT)

    if res.status_code != 200:
        return None

    result = loads(res.text)

    if 'aggregations' in result:
        if 'pop' in result['aggregations']:
            if 'value' in result['aggregations']['pop']:
                return result['aggregations']['pop']['value']

    return None
