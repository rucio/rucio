#!/usr/bin/python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2018

import sys
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, '/opt/rucio/.venv/lib/python2.6/site-packages/rucio/web/rest/flask')

from rucio.web.rest.flask.scope import app as application
