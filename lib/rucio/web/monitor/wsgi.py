# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "rucio.web.monitor.settings")

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
