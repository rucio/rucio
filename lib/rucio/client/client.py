# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012


"""
Client classes for callers of a Glance system
"""

import errno
import httplib
import json
import logging
import os
import socket
import sys

from rucio.common import client as base_client


logger = logging.getLogger(__name__)


class Client(base_client.BaseClient):

    """Main client class for accessing Rucio resources"""

    DEFAULT_PORT = 80

    def add_dataset(self):
        """
        """
        pass
