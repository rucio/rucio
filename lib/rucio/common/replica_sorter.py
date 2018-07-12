# Copyright 2012-2018 CERN for the benefit of the ATLAS collaboration.
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
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2017
# - Joaquin Bogado <jbogado@linti.unlp.edu.ar>, 2018
# This product includes GeoLite data created by MaxMind,
# available from <a href="http://www.maxmind.com">http://www.maxmind.com</a>.

from __future__ import print_function

import gzip
import os
import random
import socket
import time

from math import asin, cos, radians, sin, sqrt

from dogpile.cache import make_region

import requests
import pygeoip
import geoip2.database

from rucio.common import utils
from rucio.common.exception import InvalidRSEExpression
from rucio.core.rse_expression_parser import parse_expression

REGION = make_region(function_key_generator=utils.my_key_generator).configure(
    'dogpile.cache.memory',
    expiration_time=30 * 86400,
)


def __download_geoip_db(directory, filename):
    path = 'http://geolite.maxmind.com/download/geoip/database/%s.gz' % (filename)
    try:
        os.unlink('%s/%s.gz' % (directory, filename))
    except OSError:
        pass
    result = requests.get(path, stream=True)
    if result and result.status_code in [200, ]:
        f = open('%s/%s.gz' % (directory, filename), 'wb')
        for chunk in result.iter_content(8192):
            f.write(chunk)
        f.close()


def __get_geoip_db(directory, filename):
    if directory.endswith('/'):
        directory = directory[:-1]
    if not os.path.isfile('%s/%s' % (directory, filename)):
        print('%s does not exist. Downloading it.' % (filename))
        __download_geoip_db(directory, filename)
    elif (time.time() - os.stat('%s/%s' % (directory, filename)).st_atime > 30 * 86400):
        print('%s is too old. Re-downloading it.' % (filename))
        __download_geoip_db(directory, filename)
    else:
        return
    f = gzip.open('%s/%s.gz' % (directory, filename), 'rb')
    file_content = f.read()
    f.close()
    g = open('%s/%s' % (directory, filename), 'wb')
    g.write(file_content)
    g.close()
    os.unlink('%s/%s.gz' % (directory, filename))
    return


def __get_lat_long(se, gi, gi2):
    """
    Get the latitude and longitude on one host using the GeoLite DB
    :param se  : A hostname or IP.
    :param gi  : A GeoIP object (pygeoip API for IPv4).
    :param gi2 : A Reader object (geoip2 API for IPv6).
    """
    try:
        ip = socket.gethostbyname(se)
        d = gi.record_by_addr(ip)
        return d['latitude'], d['longitude']
    except socket.gaierror as e:
        try:
            # Host unknown. It might be IPv6. Trying with geoip2
            print(e)
            ip = socket.getaddrinfo(se, None)[0][4][0]
            response = gi2.city(ip)
            return response.location.latitude, response.location.longitude
        except socket.gaierror as e:
            # Host definitively unknown
            print(e)
            return None, None


@REGION.cache_on_arguments(namespace='site_distance')
def __get_distance(se1, se2):
    """
    Get the distance between 2 host using the GeoLite DB
    :param se1 : A first hostname or IP.
    :param se2 : A second hostname or IP.
    """
    directory = '/tmp'
    filename = 'GeoLiteCity.dat'
    __get_geoip_db(directory, filename)

    directory = '/tmp'
    ipv6_filename = 'GeoLite2-City.mmdb'
    __get_geoip_db(directory, ipv6_filename)

    gi = pygeoip.GeoIP('%s/%s' % (directory, filename))
    gi2 = geoip2.database.Reader('%s/%s' % (directory, ipv6_filename))

    lat1, long1 = __get_lat_long(se1, gi, gi2)
    lat2, long2 = __get_lat_long(se2, gi, gi2)

    if lat1 and lat2:
        long1, lat1, long2, lat2 = map(radians, [long1, lat1, long2, lat2])
        dlon = long2 - long1
        dlat = lat2 - lat1
        a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
        c = 2 * asin(sqrt(a))
        return 6378 * c
    else:
        # One host is on the Moon
        return 360000


def site_selector(replicas, site):
    """
    Return a list of replicas located on one site.
    :param replicas : A dict with RSEs as values and replicas as keys (URIs).
    :param site : The name of the site
    """
    result = []
    try:
        rses = parse_expression("site=%s" % site)
    except InvalidRSEExpression:
        return result
    except Exception:
        return result
    rses = [i['rse'] for i in rses]
    for replica in replicas:
        if replicas[replica] in rses:
            result.append(replica)
    return result


def sort_random(replicas):
    """
    Return a list of replicas sorted randomly.
    :param replicas : A dict with RSEs as values and replicas as keys (URIs).
    """

    list_replicas = list(replicas.keys())
    random.shuffle(list_replicas)

    return list_replicas


def sort_geoip(replicas, client_ip):
    """
    Return a list of replicas sorted by geographical distance to the client IP.
    :param replicas : A dict with RSEs as values and replicas as keys (URIs).
    :param client_ip: The IP of the client.
    """

    distances = {}
    for replica in replicas:
        se = replica.split('/')[2].split(':')[0]
        distance = __get_distance(se, client_ip)
        distances[replica] = distance
    tmp = map(lambda x: x[0], sorted(list(distances.items()), key=lambda x: x[1]))

    return tmp


def sort_closeness(replicas, location):
    """
    Return a list of replicas sorted by AGIS closeness.
    :param replicas : A dict with RSEs as values and replicas as keys (URIs).
    :param location: Location dictionary containing {'ip', 'fqdn', 'site'}
    """

    return replicas


def sort_ranking(replicas, location):
    """
    Return a list of replicas sorted by ranking metric.
    :param replicas : A dict with RSEs as values and replicas as keys (URIs).
    :param location: Location dictionary containing {'ip', 'fqdn', 'site'}
    """

    return replicas


def sort_dynamic(replicas, location):
    """
    Return a list of replicas sorted by dynamic network metrics.
    :param replicas : A dict with RSEs as values and replicas as keys (URIs).
    :param location: Location dictionary containing {'ip', 'fqdn', 'site'}
    """

    return replicas
