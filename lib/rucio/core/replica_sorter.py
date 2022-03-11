# -*- coding: utf-8 -*-
# Copyright 2020-2022 CERN
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
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Ilija Vukotic <ivukotic@cern.ch>, 2021
# - David Población Criado <david.poblacion.criado@cern.ch>, 2021
# - Martin Barisits <martin.barisits@cern.ch>, 2021
# - Radu Carpa <radu.carpa@cern.ch>, 2021-2022

from __future__ import print_function, division

import random
import shutil
import socket
import tarfile
from collections import OrderedDict
from datetime import datetime, timedelta
from math import asin, cos, radians, sin, sqrt
from pathlib import Path
from tempfile import TemporaryDirectory, TemporaryFile
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import geoip2.database
import requests
from dogpile.cache.api import NO_VALUE

from rucio.common import utils
from rucio.common.cache import make_region_memcached
from rucio.common.config import config_get, config_get_bool, config_get_int
from rucio.common.exception import InvalidRSEExpression
from rucio.core.rse_expression_parser import parse_expression

if TYPE_CHECKING:
    from typing import Dict, List, Optional

REGION = make_region_memcached(expiration_time=900, function_key_generator=utils.my_key_generator)

# This product uses GeoLite data created by MaxMind,
# available from <a href="http://www.maxmind.com">http://www.maxmind.com</a>
GEOIP_DB_EDITION = 'GeoLite2-City'


def extract_file_from_tar_gz(archive_file_obj, file_name, destination):
    """
    Extract one file from the archive and put it at the destination

    archive_fileobj is supposed to be at position 0
    """
    with TemporaryDirectory(prefix=file_name) as tmp_dir:
        tmp_dir = Path(tmp_dir)
        with tarfile.open(fileobj=archive_file_obj, mode='r:gz') as tfile:
            tfile.extractall(path=tmp_dir)
            for entry in tfile:
                if entry.name.find(file_name) > -1:
                    print('Will move %s to %s' % (tmp_dir / entry.name, destination))
                    shutil.move(tmp_dir / entry.name, destination)


def __download_geoip_db(destination):
    edition_id = GEOIP_DB_EDITION
    download_url = config_get('core', 'geoip_download_url', raise_exception=False, default=None)
    verify_tls = config_get_bool('core', 'geoip_download_verify_tls', raise_exception=False, default=True)
    if not download_url:
        licence_key = config_get('core', 'geoip_licence_key', raise_exception=False, default=None)
        if not licence_key:
            raise Exception('Cannot download GeoIP database: licence key not provided')
        download_url = 'https://download.maxmind.com/app/geoip_download?edition_id=%s&license_key=%s&suffix=tar.gz' % (edition_id, licence_key)

    result = requests.get(download_url, stream=True, verify=verify_tls)
    if result and result.status_code in [200, ]:
        with TemporaryFile() as file_obj:
            for chunk in result.iter_content(8192):
                file_obj.write(chunk)
            file_obj.seek(0)

            extract_file_from_tar_gz(archive_file_obj=file_obj, file_name=f'{edition_id}.mmdb', destination=destination)
    else:
        raise Exception('Cannot download GeoIP database: %s, Code: %s, Error: %s' % (edition_id,
                                                                                     result.status_code,
                                                                                     result.text))


def __geoip_db():
    db_path = Path(f'/tmp/{GEOIP_DB_EDITION}.mmdb')
    db_expire_delay = timedelta(days=config_get_int('core', 'geoip_expire_delay', raise_exception=False, default=30))

    must_download = False
    if not db_path.is_file():
        print('%s does not exist. Downloading it.' % db_path)
        must_download = True
    elif db_expire_delay and datetime.fromtimestamp(db_path.stat().st_mtime) < datetime.now() - db_expire_delay:
        print('%s is too old. Re-downloading it.' % db_path)
        must_download = True

    if must_download:
        __download_geoip_db(destination=db_path)

    return geoip2.database.Reader(str(db_path))


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
    canonical_parties = list(map(lambda x: str(x).lower(), [se1, client_location['ip'], client_location.get('latitude', ''), client_location.get('longitude', '')]))
    canonical_parties.sort()
    cache_key = f'replica_sorter:__get_distance|site_distance|{"".join(canonical_parties)}'.replace(' ', '.')
    cache_val = REGION.get(cache_key)
    if cache_val is NO_VALUE:
        try:
            gi = __geoip_db()

            lat1, long1 = __get_lat_long(se1, gi)
            if client_location.get('latitude') and client_location.get('longitude'):
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
        rses = parse_expression("site=%s" % site, filter_={'vo': vo})
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
