# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

import logging
import logging.handlers

from rucio.common.config import config_get

logging.basicConfig(level=logging.INFO, format='%(message)s')
handler = logging.handlers.TimedRotatingFileHandler(filename='%s/trace' % config_get('trace', 'tracedir'),
                                                    when='midnight',
                                                    utc=True)
handler.suffix = "%Y-%m-%d"


def trace(payload):
    """
    Write a trace to the archive.

    :param payload: Python datatype that can be coerced into a string.

    TODO: THIS IS NOT MULTI-PROCESS SAFE YET!
    """

    # TODO: This should probably split the payload into proper columns.
    # But then again, that requires some kind of schema. Which is bad as well.
    # Therefore: needs much more thought...
    logging.info(str(payload))
