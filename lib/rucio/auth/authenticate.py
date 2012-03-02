#!/usr/bin/env /Users/Mario/Development/CERN/rucio/.venv/bin/python
"""
@copyright: European Organization for Nuclear Research (CERN)
@contact: U{ph-adp-ddm-lab@cern.ch<mailto:ph-adp-ddm-lab@cern.ch>}
@license: Licensed under the Apache License, Version 2.0 (the "License");
You may not use this file except in compliance with the License.
You may obtain a copy of the License at:
U{http://www.apache.org/licenses/LICENSE-2.0}
@author:
- Mario Lassnig, <mario.lassnig@cern.ch>, CERN PH-ADP-CO, 2012
"""

import web

urls = (
    '/authenticate', 'Authenticate',
    '/validate', 'Validate'
)


class Authenticate:

    def GET(self):
        return "new token"

    application = web.application(urls, globals()).wsgifunc()


class Validate:

    def GET(self):
        return "validated"

    application = web.application(urls, globals()).wsgifunc()


app = web.application(urls, globals())

if __name__ == "__main__":
    app.run()
