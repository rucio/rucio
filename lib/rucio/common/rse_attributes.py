# -*- coding: utf-8 -*-
# Copyright 2015-2022 CERN
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
# - Radu Carpa <radu.carpa@cern.ch>, 2022

"""
methods to get closeness between sites
"""

import logging
import traceback

from dogpile.cache.api import NoValue

from rucio.core import rse as rse_core
from rucio.common.cache import make_region_memcached
from rucio.db.sqla.constants import RSEType
from rucio.db.sqla.session import read_session
from rucio.rse import rsemanager as rsemgr

REGION = make_region_memcached(expiration_time=900)


class RseData:
    """
    Helper data class storing rse data grouped in one place.
    """
    def __init__(self, id_, name=None, attributes=None, info=None):
        self.id = id_
        self.name = name
        self.attributes = attributes
        self.info = info

    def __str__(self):
        if self.name is not None:
            return self.name
        return self.id

    def __eq__(self, other):
        if other is None:
            return False
        return self.id == other.id

    def is_tape(self):
        if self.info['rse_type'] == RSEType.TAPE or self.info['rse_type'] == 'TAPE':
            return True
        return False

    def is_tape_or_staging_required(self):
        if self.is_tape() or self.attributes.get('staging_required', False):
            return True
        return False

    @read_session
    def load_name(self, session=None):
        if self.name is None:
            self.name = rse_core.get_rse_name(rse_id=self.id, session=session)
        return self.name

    @read_session
    def load_attributes(self, session=None):
        if self.attributes is None:
            self.attributes = get_rse_attributes(self.id, session=session)
        return self.attributes

    @read_session
    def load_info(self, session=None):
        if self.info is None:
            self.info = rsemgr.get_rse_info(rse=self.load_name(session=session),
                                            vo=rse_core.get_rse_vo(rse_id=self.id, session=session),
                                            session=session)
        return self.info


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
