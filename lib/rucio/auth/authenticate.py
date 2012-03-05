#!/usr/bin/env python
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

import logging
import uuid
import web

logger = logging.getLogger("rucio.authentication")
sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
logger.addHandler(sh)

urls = (
    '/authenticate', 'Authenticate',
    '/validate', 'Validate'
)


class Authenticate:
    """Authenticate a Rucio account"""

    def GET(self):
        """Get an authentication token for an account.

        HTTP Request Header:
            Rucio-Account: the account name string to authenticate.
            Rucio-Username: the username string to verify.
            Rucio-Password: the password string to verify.

        HTTP Response Header:
            Rucio-Auth-Token: 32-bit hex token encoded as a string

        HTTP Error Headers:
            200 OK
            401 Unauthorized

        Example Request:
            curl -v -X GET -H "Rucio-Account: ddmlab" -H "Rucio-Username: testuser" -H "Rucio-Password: testpassword" http://localhost/authenticate
        """

        web.header('Content-Type', 'application/octet-stream')

        account = web.ctx.env.get('HTTP_RUCIO_ACCOUNT')
        username = web.ctx.env.get('HTTP_RUCIO_USERNAME')
        password = web.ctx.env.get('HTTP_RUCIO_PASSWORD')

        if account is None:
            raise web.BadRequest()

        if username == 'testuser' and password == 'testpassword':
            web.header('Rucio-Auth-Token', str(uuid.uuid4()).replace('-', ''))
            return ""
        else:
            raise web.Unauthorized()

    def PUT(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def POST(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def DELETE(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()


class Validate:

    def GET(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def PUT(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def POST(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()

    def DELETE(self):
        web.header('Content-Type', 'application/octet-stream')
        raise web.BadRequest()


app = web.application(urls, globals())

if __name__ == "__main__":
    app.run()
