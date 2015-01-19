# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0OA
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2015

"""
methods to get closeness between sites
"""

import json
import logging
import random
import sys
import urllib2

from dogpile.cache import make_region
from dogpile.cache.api import NoValue
from hashlib import sha256

region = make_region().configure('dogpile.cache.memcached',
                                 expiration_time=3600,
                                 arguments={'url': "127.0.0.1:11211", 'distributed_lock': True})

# for local test
# region = make_region().configure('dogpile.cache.memory',
#                                  expiration_time=3600)

BIGGEST_DISTANCE = 9999


def get_sitename(rse_name):
    """
    Pass a RSE name and return its site name.

    :param rse_name:      RSE name.
    :returns:             Site name.
    """

    url = 'http://atlas-agis-api.cern.ch/request/ddmendpoint/query/list/?json'
    result = region.get(sha256(url).hexdigest())
    if type(result) is NoValue:
        try:
            logging.debug("Refresh rse site map: %s" % url)
            result = {}
            u = urllib2.urlopen(url)
            content = u.read()
            rses = json.loads(content)
            for item in rses:
                rse = item['name']
                sitename = item['site'].upper()
                result[rse] = sitename
            region.set(sha256(url).hexdigest(), result)
        except:
            logging.error("INFO: failed to load data from url=%s, error: %s" % (url, sys.exc_info()))
    if result and rse_name in result:
        return result[rse_name]
    return None


def get_closeness(dest_rse):
    """
    Pass a RSE name and return its closeness.

    :param dest_rse:      RSE name.
    :returns:             Closeness dict.
    """
    url = 'http://atlas-agis-api.cern.ch/request/site/query/list_links/?json'
    result = region.get(sha256(url).hexdigest())
    if type(result) is NoValue:
        try:
            logging.debug("Refresh closeness: %s" % url)
            result = {}
            u = urllib2.urlopen(url)
            content = u.read()
            site_list = json.loads(content)
            for item in site_list:
                if 'src' in item and 'dst' in item and 'closeness' in item:
                    dst = item['dst'].upper()
                    src = item['src'].upper()
                    if dst not in result:
                        result[dst] = {}
                    result[dst][src] = item['closeness']

                    # fix transfer inside the same site
                    result[dst][dst] = -BIGGEST_DISTANCE
                    if src not in result:
                        result[src] = {}
                    result[src][src] = -BIGGEST_DISTANCE
            region.set(sha256(url).hexdigest(), result)
        except:
            logging.error("INFO: failed to load data from url=%s, error: %s" % (url, sys.exc_info()))

    if result:
        dest_site = get_sitename(dest_rse)
        if dest_site and dest_site in result:
            return result[dest_site]
    return None


def sort_rses(rses, dest_rse):
    """
    Pass a rses list and the destionation rse, return sorted rses list by distance.

    :param rses:       A list of rses.
    :param dest_rse:      Destination rse name.
    :returns:             Sorted rses list.
    """

    rses.sort()
    key = str(dest_rse) + ":" + str(rses)
    sorted_list = region.get(sha256(key).hexdigest())
    if type(sorted_list) is NoValue:
        try:
            sorted_list = None
            closeness = get_closeness(dest_rse)
            close_dict = {}
            for rse in rses:
                site = get_sitename(rse)
                if site in closeness:
                    distance = closeness[site]
                else:
                    distance = BIGGEST_DISTANCE

                if distance not in close_dict:
                    close_dict[distance] = []
                close_dict[distance].append(rse)
            sorted_list = sorted(close_dict.items())
            region.set(sha256(key).hexdigest(), sorted_list)
        except:
            logging.error("INFO: failed to sort rses with network distance, error: %s" % (sys.exc_info()))

    ret_rses = []
    if sorted_list:
        for distance, rse_list in sorted_list:
            random.shuffle(rse_list)
            ret_rses += rse_list
    return ret_rses if ret_rses else None


def sort_sources(sources, dest_rse):
    """
    Pass a sources list and the destionation rse, return its closeness.

    :param sources:       A list of sources, eg: [(rse_name, surl),...].
    :param dest_rse:      Destination rse name.
    :returns:             Sorted sources list.
    """

    sources_dict = {}
    for source in sources:
        src_rse, src_url = source
        if src_rse not in sources_dict:
            sources_dict[src_rse] = []
        sources_dict[src_rse].append(source)

    # sort rses
    rses = sources_dict.keys()
    closest_sorted_rses = sort_rses(rses, dest_rse)
    if not closest_sorted_rses:
        return sources

    logging.debug("Dest: %s, original sources: %s" % (dest_rse, sources))
    ret_sources = []
    for rse in closest_sorted_rses:
        ret_sources += sources_dict[rse]
    logging.debug("Dest: %s, sorted sources: %s" % (dest_rse, ret_sources))
    return ret_sources
