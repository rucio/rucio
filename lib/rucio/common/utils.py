# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012

"""
Rucio utilities.
"""

import urllib
import uuid


def build_url(host, port=None, path=None, params=None, use_ssl=False):
    """
    utitily function to build an url for requests to the rucio system.
    """

    if use_ssl:
        url = "https://"
    else:
        url = "http://"
    url += host
    if port is not None:
        url += ":" + port
    url += "/"
    if path is not None:
        url += path
    if params is not None:
        url += "?"
        url += urllib.urlencode(params)
    return url


def generate_uuid():
    return str(uuid.uuid4()).replace('-', '').lower()


def generate_uuid_bytes():
    return uuid.uuid4().bytes
