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

import logging
import traceback

from dogpile.cache import make_region
from dogpile.cache.api import NoValue

from rucio.core import rse as rse_core

REGION = make_region().configure('dogpile.cache.memcached',
                                 expiration_time=3600,
                                 arguments={'url': "127.0.0.1:11211", 'distributed_lock': True})

# for local test
# REGION = make_region().configure('dogpile.cache.memory',
#                                  expiration_time=3600)


def get_rse_attributes(rse_id, session=None):
    """
    List rse attributes

    :param rse:     the rse name.
    :param rse_id:  The RSE id.
    :param session: The database session in use.

    :returns: A dictionary with RSE attributes for a RSE.
    """

    result = REGION.get(rse_id)
    if isinstance(result, NoValue):
        try:
            result = None
            result = rse_core.list_rse_attributes(None, rse_id=rse_id, session=session)
            REGION.set(rse_id, result)
        except:
            logging.warning("Failed to get RSE %s attributes, error: %s" % (rse_id, traceback.format_exc()))
    return result
