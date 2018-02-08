#!/usr/bin/python
import sys
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, '/opt/rucio/lib/rucio/web/rest/flask')

from rucio.web.rest.flask.account import app as accountapp
from rucio.web.rest.flask.scope import app as scopeapp
