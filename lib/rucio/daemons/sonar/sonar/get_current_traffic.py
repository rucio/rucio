"""
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Tomas Javurek, <tomas.javurek@cern.ch>, 2017
 - Vitjan Zavrtanik, <vitjan.zavrtanik@gmail.com>, 2017
 - Hannes Hansen, <hannes.jakob.hansen@cern.ch>, 2018-2019

 PY3K COMPATIBLE
"""

from __future__ import print_function

import sys

from rucio.client import Client
from rucio.db.sqla.session import get_session

"""
Gets current traffic for all the links.
"""


def get_traffic_from_db():
    """
    Gets the size of the current requests
    for each link.
    """
    session = get_session()
    collector = []
    query = '''SELECT
                 SUM(bytes),
                 atlas_rucio.id2rse(source_rse_id),
                 atlas_rucio.id2rse(dest_rse_id)
            FROM atlas_rucio.requests WHERE
                 (state='D' or
                 state='S' or
                 state='F' or
                 state='L')
            group by source_rse_id, dest_rse_id'''
    try:
        result = session.execute(query)
        for row in result:
            link = {'bytes': row[0], 'src_rse': row[1], 'dst_rse': row[2]}
            collector.append(link)

    except Exception as exception:
        print(exception)
        sys.exit()

    return collector


def create_site_map(rse_map):
    """
    Creation of a net of sources and destination with trafic between them.
    """
    client = Client()
    trafic_map = {}
    for link in rse_map:
        src_site = client.list_rse_attributes(link['src_rse'])['site']
        dst_site = client.list_rse_attributes(link['dst_rse'])['site']
        trafic = int(link['bytes'])

        # map creation site to site
        if src_site in trafic_map.keys():
            if dst_site in trafic_map[src_site].keys():
                trafic_map[src_site][dst_site] += trafic
            else:
                trafic_map[src_site][dst_site] = trafic
        else:
            trafic_map[src_site] = {src_site: trafic}

    return trafic_map


def get_link_traffic():
    """
    Returns a dictionary object of the current traffic
    of format {source: name1, destination: name2 , traffic: int}
    """
    rse_map = get_traffic_from_db()
    site_map = create_site_map(rse_map)
    return site_map
