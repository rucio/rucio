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

logger = logging.getLogger('rucio_dumps')


def prefix(agis_data, endpoint_name):
    ddmendpoint_data = list(filter(
        lambda d: d['name'] == endpoint_name,
        agis_data,
    ))[0]
    return ddmendpoint_data['endpoint']


def remove_prefix(prefix, path):
    iprefix = iter(prefix)
    ipath = iter(path)
    try:
        cprefix = next(iprefix)
        cpath = next(ipath)
    except StopIteration:
        # Either the path or the prefix is empty
        return path
    while cprefix != cpath:
        try:
            cprefix = next(iprefix)
        except StopIteration:
            # No parts of the prefix are part of the path
            return path

    while cprefix == cpath:
        cprefix = next(iprefix, None)
        try:
            cpath = next(ipath)
        except StopIteration:
            # The path is a subset of the prefix
            return []

    if cprefix is not None:
        # If the prefix is not depleted maybe it is only a coincidence
        # in one of the components of the paths: return the path as is.
        return path

    rest = list(ipath)
    rest.insert(0, cpath)
    return rest


def components(path):
    components = path.strip().strip('/').split('/')
    return [component for component in components if component != '']
