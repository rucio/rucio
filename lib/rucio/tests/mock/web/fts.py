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
from web import application, data, header, OK, BadRequest

from rucio.tests.mock.fts import list_all, submit, query, cancel

"""
This mock FTS3 interface implements the following functionality:
 Submit job:    POST /mockfts
 List all jobs: GET /mockfts/
 Query job:     GET /mockfts/<jobid>
 Cancel job:    DELETE /mockfts/<jobid>
"""

urls = (
    '', 'Submit',
    '/', 'ListAll',
    '/(.+)', 'QueryCancel'
)


class Submit:

    def POST(self):
        """
        Create a new transfer job.

        HTTP Success:
            200 OK

        :returns: JSON-encoded transfer job identifier
        """

        header('Content-Type', 'application/octet-stream')
        return dumps(submit(data()))

    # unused

    def GET(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()


class ListAll:

    def GET(self):
        """
        List all transfer jobs.

        HTTP Success:
            200 OK

        :returns: JSON-encoded list of all transfer job information.
        """

        header('Content-Type', 'application/octet-stream')
        return dumps(list_all())

    # unused

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def POST(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def DELETE(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()


class QueryCancel:

    def GET(self, tid):
        """
        Query transfer job information.

        HTTP Success:
            200 OK

        :param tid: JSON-encoded transfer job identifier.
        :returns: JSON-encoded transfer job information.
        """

        header('Content-Type', 'application/octet-stream')
        return dumps(query(tid=tid))

    def DELETE(self, tid):
        """
        Kill a transfer job.

        HTTP Success:
            200 OK

        :param tid: JSON-encoded transfer job identifier.
        """

        header('Content-Type', 'application/octet-stream')
        cancel(tid=tid)
        raise OK()

    # unused

    def PUT(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()

    def POST(self):
        header('Content-Type', 'application/octet-stream')
        raise BadRequest()


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
