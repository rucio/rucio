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

region = make_region(function_key_generator=utils.my_key_generator).configure(
    'dogpile.cache.memory',
    expiration_time=30*86400,
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
    elif (time.time()-os.stat('%s/%s' % (directory, filename)).st_atime > 30*86400):
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
    gi = pygeoip.GeoIP('%s/%s' % (directory, filename))
    try:
        ip = socket.gethostbyname(se1)
        d = gi.record_by_addr(ip)
        lat1, lon1 = d['latitude'], d['longitude']
        ip = socket.gethostbyname(se2)
        d = gi.record_by_addr(ip)
        lat2, lon2 = d['latitude'], d['longitude']
        lon1, lat1, lon2, lat2 = map(radians, [lon1, lat1, lon2, lat2])
        dlon = lon2 - lon1
        dlat = lat2 - lat1
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * asin(sqrt(a))
        return 6378 * c
    except socket.gaierror, e:
        print e
        return 300000


def random_order(replicas, IPclient):
    """
    Return a list of replicas in a random order.
    :param replicas : A list of replicas (URIs).
    :param session: The database session in use.
    """
    random.shuffle(replicas)
    return replicas


def geoIP_order(replicas, IPclient):
    """
    Return a list of replicas sorted by distance to the IPclient.
    :param replicas : A list of replicas (URIs).
    :param session: The database session in use.
    """
    ses = {}
    distances = {}
    for replica in replicas:
        se = replica.split('/')[2].split(':')[0]
        ses[se] = replica
        distance = getDistance(se, IPclient)
        #print replica, distance
        distances[replica] = distance
    #print sorted(distances.items(), key=lambda x: x[1])
    return map(lambda x: x[0], sorted(distances.items(), key=lambda x: x[1]))
