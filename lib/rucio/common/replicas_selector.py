# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014
#
# This product includes GeoLite data created by MaxMind,
# available from <a href="http://www.maxmind.com">http://www.maxmind.com</a>.

import geoip2.database
import gzip
import os
import pygeoip
import random
import requests
import socket
import time

from dogpile.cache import make_region
from math import asin, cos, radians, sin, sqrt

from rucio.common import utils
from rucio.common.exception import InvalidRSEExpression
from rucio.core.rse_expression_parser import parse_expression

region = make_region(function_key_generator=utils.my_key_generator).configure(
    'dogpile.cache.memory',
    expiration_time=30 * 86400,
)


def downloadDB(directory, filename):
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


def getGeoIPDB(directory, filename):
    if directory.endswith('/'):
        directory = directory[:-1]
    if not os.path.isfile('%s/%s' % (directory, filename)):
        print '%s does not exist. Downloading it.' % (filename)
        downloadDB(directory, filename)
    elif (time.time() - os.stat('%s/%s' % (directory, filename)).st_atime > 30 * 86400):
        print '%s is too old. Re-downloading it.' % (filename)
        downloadDB(directory, filename)
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


def get_lat_long(se, gi, gi2):
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
    except socket.gaierror, e:
        try:
            # Host unknown. It might be IPv6. Trying with geoip2
            print e
            ip = socket.getaddrinfo(se, None)[0][4][0]
            response = gi2.city(ip)
            return response.location.latitude, response.location.longitude
        except socket.gaierror, e:
            # Host definitively unknown
            print e
            return None, None


@region.cache_on_arguments(namespace='site_distance')
def getDistance(se1, se2):
    """
    Get the distance between 2 host using the GeoLite DB
    :param se1 : A first hostname or IP.
    :param se2 : A second hostname or IP.
    """
    directory = '/tmp'
    filename = 'GeoLiteCity.dat'
    getGeoIPDB(directory, filename)

    directory = '/tmp'
    ipv6_filename = 'GeoLite2-City.mmdb'
    getGeoIPDB(directory, ipv6_filename)

    gi = pygeoip.GeoIP('%s/%s' % (directory, filename))
    gi2 = geoip2.database.Reader('%s/%s' % (directory, ipv6_filename))

    lat1, long1 = get_lat_long(se1, gi, gi2)
    lat2, long2 = get_lat_long(se2, gi, gi2)

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


def random_order(replicas, IPclient):
    """
    Return a list of replicas in a random order.
    :param replicas : A dict with RSEs as values and replicas as keys (URIs).
    :param IPclient: The IP of the client.
    """
    list_replicas = replicas.keys()
    random.shuffle(list_replicas)
    return list_replicas


def geoIP_order(replicas, IPclient):
    """
    Return a list of replicas sorted by distance to the IPclient.
    :param replicas : A dict with RSEs as values and replicas as keys (URIs).
    :param IPclient: The IP of the client.
    """
    distances = {}
    for replica in replicas:
        se = replica.split('/')[2].split(':')[0]
        distance = getDistance(se, IPclient)
        # print replica, distance
        distances[replica] = distance
    # print sorted(distances.items(), key=lambda x: x[1])
    return map(lambda x: x[0], sorted(distances.items(), key=lambda x: x[1]))


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
