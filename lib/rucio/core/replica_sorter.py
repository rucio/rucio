# -*- coding: utf-8 -*-
# Copyright 2017-2020 CERN
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
#
# Authors:
# - Mario Lassnig <mario.lassnig@cern.ch>, 2017-2020
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018
# - Vincent Garonne <vgaronne@gmail.com>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020
# - Cedric Serfon <cedric.serfon@cern.ch>, 2019
# - Martin Barisits <martin.barisits@cern.ch>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020

# This product includes GeoLite data created by MaxMind,
# available from <a href="http://www.maxmind.com">http://www.maxmind.com</a>

from __future__ import print_function, division

import os
import random
import socket
import tarfile
import time
from collections import OrderedDict
from math import asin, cos, radians, sin, sqrt
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import geoip2.database
import requests
from dogpile.cache import make_region
from dogpile.cache.api import NO_VALUE

from rucio.common import utils
from rucio.common.config import config_get
from rucio.common.exception import InvalidRSEExpression
from rucio.core.rse_expression_parser import parse_expression

if TYPE_CHECKING:
    from typing import Dict, List, Optional

REGION = make_region(function_key_generator=utils.my_key_generator).configure(
    'dogpile.cache.memory',
    expiration_time=30 * 86400,
)


def __download_geoip_db(directory, filename):
    licence_key = config_get('core', 'geoip_licence_key', raise_exception=False, default='NOLICENCE')
    path = 'https://download.maxmind.com/app/geoip_download?edition_id=%s&license_key=%s&suffix=tar.gz' % (filename, licence_key)
    try:
        os.unlink('%s/%s.tar.gz' % (directory, filename))
    except OSError:
        pass
    result = requests.get(path, stream=True)
    if result and result.status_code in [200, ]:
        file_object = open('%s/%s.tar.gz' % (directory, filename), 'wb')
        for chunk in result.iter_content(8192):
            file_object.write(chunk)
        file_object.close()
        tarfile_name = '%s/%s.tar.gz' % (directory, filename)
        with tarfile.open(name=tarfile_name, mode='r:gz') as tfile:
            tfile.extractall(path=directory)
            for entry in tfile:
                if entry.name.find('%s.mmdb' % filename) > -1:
                    print('Will move %s/%s to %s/%s' % (directory, entry.name, directory, entry.name.split('/')[-1]))
                    os.rename('%s/%s' % (directory, entry.name), '%s/%s' % (directory, entry.name.split('/')[-1]))
    else:
        raise Exception('Cannot download GeoIP database: %s, Code: %s, Error: %s' % (filename,
                                                                                     result.status_code,
                                                                                     result.text))


def __get_geoip_db(directory, filename):
    if directory.endswith('/'):
        directory = directory[:-1]
    if not os.path.isfile('%s/%s.mmdb' % (directory, filename)):
        print('%s does not exist. Downloading it.' % (filename))
        __download_geoip_db(directory, filename)
    elif time.time() - os.stat('%s/%s.mmdb' % (directory, filename)).st_atime > 30 * 86400:
        print('%s is too old. Re-downloading it.' % (filename))
        __download_geoip_db(directory, filename)
    return


def __get_lat_long(se, gi):
    """
    Get the latitude and longitude on one host using the GeoLite DB
    :param se  : A hostname or IP.
    :param gi : A Reader object (geoip2 API).
    """
    try:
        ip = socket.getaddrinfo(se, None)[0][4][0]
        response = gi.city(ip)
        return response.location.latitude, response.location.longitude
    except socket.gaierror as error:
        # Host definitively unknown
        print(error)
    return None, None


def __get_distance(se1, client_location, ignore_error):
    """
    Get the distance between 2 host using the GeoLite DB
    :param se1 : A first hostname or IP.
    :param client_location : contains {'ip', 'fqdn', 'site', 'latitude', 'longitude'}
    :ignore_error: Ignore exception when the GeoLite DB cannot be retrieved
    """
    # does not cache ignore_error, str.lower on hostnames/ips is fine
    canonical_parties = list(map(lambda x: str(x).lower(), [se1, client_location['ip']])).sort()
    cache_key = f'replica_sorter:__get_distance|site_distance|{canonical_parties}'
    cache_val = REGION.get(cache_key)
    if cache_val is NO_VALUE:
        directory = '/tmp'
        ipv6_filename = 'GeoLite2-City'
        try:
            __get_geoip_db(directory, ipv6_filename)

            gi = geoip2.database.Reader('%s/%s' % (directory, '%s.mmdb' % ipv6_filename))

            lat1, long1 = __get_lat_long(se1, gi)
            if client_location['latitude'] and client_location['longitude']:
                lat2 = client_location['latitude']
                long2 = client_location['longitude']
            else:
                lat2, long2 = __get_lat_long(client_location['ip'], gi)

            if lat1 and lat2:
                long1, lat1, long2, lat2 = map(radians, [long1, lat1, long2, lat2])
                dlon = long2 - long1
                dlat = lat2 - lat1
                cache_val = 6378 * 2 * asin(sqrt(sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2))
                REGION.set(cache_key, cache_val)
                return cache_val
        except Exception as error:
            if not ignore_error:
                raise error
        # One host is on the Moon
        cache_val = 360000
        REGION.set(cache_key, cache_val)
    return cache_val


def site_selector(replicas, site, vo):
    """
    Return a list of replicas located on one site.
    :param replicas : A dict with RSEs as values and replicas as keys (URIs).
    :param site : The name of the site
    :param vo : The vo within which to search for RSEs
    """
    result = []
    try:
        rses = parse_expression("site=%s" % site, filter={'vo': vo})
    except InvalidRSEExpression:
        return result
    except Exception:
        return result
    rses = [i['rse'] for i in rses]
    for replica in replicas:
        if replicas[replica] in rses:
            result.append(replica)
    return result


def sort_replicas(dictreplica: "Dict", client_location: "Dict", selection: "Optional[str]" = None) -> "List":
    """
    General sorting method for a dictionary of replicas. Returns the List of replicas.

    :param dictreplica: A dict with replicas as keys (URIs).
    :param client_location: Location dictionary containing {'ip', 'fqdn', 'site', 'latitude', 'longitude'}
    :param selection: the selected sorting algorithm.
    :param default: the default sorting algorithm (random, if not defined).
    :returns: the keys of dictreplica in a sorted list.
    """
    if len(dictreplica) == 0:
        return []
    if not selection:
        selection = 'geoip'

    items = [(key, value) for key, value in dictreplica.items()]
    # safety check, TODO: remove if all dictreplica values are 4-tuple with priority as second item
    if isinstance(items[0][1], tuple) and len(items[0][1]) == 4:
        # sort by value[1], which is the priority
        items.sort(key=lambda item: item[1][1])
    dictreplica = OrderedDict(items)

    # all sorts must be stable to preserve the priority (the Python standard sorting functions always are stable)
    if selection == 'geoip':
        replicas = sort_geoip(dictreplica, client_location, ignore_error=True)
    elif selection == 'closeness':
        replicas = sort_closeness(dictreplica, client_location)
    elif selection == 'dynamic':
        replicas = sort_dynamic(dictreplica, client_location)
    elif selection == 'ranking':
        replicas = sort_ranking(dictreplica, client_location)
    elif selection == 'random':
        replicas = sort_random(dictreplica)
    else:
        replicas = list(dictreplica.keys())

    return replicas


def sort_random(dictreplica: "Dict") -> "List":
    """
    Return a list of replicas sorted randomly.
    :param dictreplica: A dict with replicas as keys (URIs).
    """

    list_replicas = list(dictreplica.keys())
    random.shuffle(list_replicas)
    return list_replicas


def sort_geoip(dictreplica: "Dict", client_location: "Dict", ignore_error: bool = False) -> "List":
    """
    Return a list of replicas sorted by geographical distance to the client IP.
    :param dictreplica: A dict with replicas as keys (URIs).
    :param client_location: Location dictionary containing {'ip', 'fqdn', 'site', 'latitude', 'longitude'}
    :param ignore_error: Ignore exception when the GeoLite DB cannot be retrieved
    """

    def distance(pfn):
        return __get_distance(urlparse(pfn).hostname, client_location, ignore_error)

    return list(sorted(dictreplica, key=distance))


def sort_closeness(dictreplica: "Dict", client_location: "Dict") -> "List":
    """
    Return a list of replicas sorted by AGIS closeness. NOT IMPLEMENTED
    :param dictreplica: A dict with replicas as keys (URIs).
    :param client_location: Location dictionary containing {'ip', 'fqdn', 'site', 'latitude', 'longitude'}
    """

    return list(dictreplica.keys())


def sort_ranking(dictreplica: "Dict", client_location: "Dict") -> "List":
    """
    Return a list of replicas sorted by ranking metric. NOT IMPLEMENTED
    :param dictreplica: A dict with replicas as keys (URIs).
    :param client_location: Location dictionary containing {'ip', 'fqdn', 'site', 'latitude', 'longitude'}
    """

    return list(dictreplica.keys())


def sort_dynamic(dictreplica: "Dict", client_location: "Dict") -> "List":
    """
    Return a list of replicas sorted by dynamic network metrics. NOT IMPLEMENTED
    :param dictreplica: A dict with replicas as keys (URIs).
    :param client_location: Location dictionary containing {'ip', 'fqdn', 'site', 'latitude', 'longitude'}
    """

    return list(dictreplica.keys())
