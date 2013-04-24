#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013

from json import dumps
from web import application, data, header, OK

from rucio.tests.mock.fts3 import submit, query, cancel

"""
This mock FTS3 interface implements the following functionality:
 Submit job: POST /jobs
 Query job: GET /<jobid>
 Cancel job: DELETE /<jobid>
 Version:  GET /
"""

urls = (
    '/', 'Version',
    '/jobs', 'Submit',
    '/jobs/(.+)', 'QueryCancel'
)


class Submit:

    def POST(self):
        """
        Create a new transfer job.

        HTTP Success:
            200 OK

        :returns: JSON-encoded transfer job identifier
        """

        header('Content-Type', 'application/json')

        return dumps(submit(data()))


class Version:

    def GET(self):
        """
        Return FTS version information.

        HTTP Success:
            200 OK

        :returns: JSON-encoded version information.
        """

        header('Content-Type', 'application/json')

        return dumps({"api": {"major": 0, "minor": 0, "patch": 0},
                      "delegation": {"major": 0, "minor": 0, "patch": 0},
                      "schema": {"major": 0, "minor": 0, "patch": 0}})


class QueryCancel:

    def GET(self, tid):
        """
        Query transfer job information.

        HTTP Success:
            200 OK

        :param tid: JSON-encoded transfer job identifier.
        :returns: JSON-encoded transfer job information.
        """

        header('Content-Type', 'application/json')

        return dumps(query(tid))

    def DELETE(self, tid):
        """
        Kill a transfer job.

        HTTP Success:
            200 OK

        :param tid: JSON-encoded transfer job identifier.
        """

        header('Content-Type', 'application/octet-stream')
        cancel(tid)
        raise OK()


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
