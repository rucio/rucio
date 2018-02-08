#!/usr/bin/python
import sys
import logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, '/opt/rucio/.venv/lib/python2.6/site-packages/web/rest/flask')

from rucio.web.rest.flask.did import app as application

