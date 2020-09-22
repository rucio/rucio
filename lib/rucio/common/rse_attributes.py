# -*- coding: utf-8 -*-
# Copyright 2015-2020 CERN
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
# - Wen Guan <wen.guan@cern.ch>, 2015
# - Mario Lassnig <mario.lassnig@cern.ch>, 2017
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Brandon White <bjwhite@fnal.gov>, 2019
# - Martin Barisits <martin.barisits@cern.ch>, 2020
#
# PY3K COMPATIBLE

"""
methods to get closeness between sites
"""

import logging
import traceback

from dogpile.cache import make_region
from dogpile.cache.api import NoValue

from rucio.core import rse as rse_core
from rucio.common.config import config_get

REGION = make_region().configure('dogpile.cache.memcached',
                                 expiration_time=3600,
                                 arguments={'url': config_get('cache', 'url', False, '127.0.0.1:11211'), 'distributed_lock': True})


def get_rse_attributes(rse_id, session=None):
    """
    List rse attributes

    :param rse:     the rse name.
    :param rse_id:  The RSE id.
    :param session: The database session in use.

    :returns: A dictionary with RSE attributes for a RSE.
    """

    key = 'rse_attributes_%s' % (rse_id)
    result = REGION.get(key)
    if isinstance(result, NoValue):
        try:
            result = None
            result = rse_core.list_rse_attributes(rse_id=rse_id, session=session)
            REGION.set(key, result)
        except:
            logging.warning("Failed to get RSE %s attributes, error: %s" % (rse_id, traceback.format_exc()))
    return result
