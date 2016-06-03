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

from requests import post
from requests.auth import HTTPBasicAuth
from json import dumps, loads

from rucio.common.config import config_get

elastic_url = config_get('c3po-popularity', 'elastic_url')

elastic_username = config_get('c3po-popularity', 'elastic_username')
elastic_password = config_get('c3po-popularity', 'elastic_password')

url = elastic_url + '/atlas_rucio-popularity-*/_search'


def get_popularity(did):
    """
    Query the popularity for a given DID in the ElasticSearch popularity db.
    """
    query = {
        "query": {
            "bool": {
                "must": []
            }
        },
        "filter": {
            "range": {
                "timestamp": {
                    "gt": "now-7d",
                    "lt": "now"
                }
            }
        },
        "aggs": {
            "pop": {"sum": {"field": "ops"}}
        },
        "size": 0
    }

    query['query']['bool']['must'].append({"term": {"scope": did[0]}})
    query['query']['bool']['must'].append({"term": {"name": did[1]}})

    logging.debug(query)
    if elastic_username:
        r = post(url, data=dumps(query), auth=HTTPBasicAuth(elastic_username, elastic_password))
    else:
        r = post(url, data=dumps(query))

    if r.status_code != 200:
        return None

    result = loads(r.text)

    if 'aggregations' in result:
        if 'pop' in result['aggregations']:
            if 'value' in result['aggregations']['pop']:
                return result['aggregations']['pop']['value']

    return None
