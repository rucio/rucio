RESTful APIs
=============

Each resource can be accessed or modified using specially formed URLs and the standard HTTP methods:

 * GET to read
 * POST to create
 * PUT to update
 * DELETE to remove

We require that all requests are done over SSL. The API supports JSON formats. Rucio uses OAuth_
to authenticate all API requests. The method is to get an authentication token, and use it for the rest of
the requests. Descriptions of the actions you may perform on each resource can be found below.


**Date format**

All dates returned are in UTC and are strings in the following format (RFC 1123, ex RFC 822)::

 Mon, 13 May 2013 10:23:03 UTC

In code format, which can be used in all programming languages that support strftime or strptime::

'%a, %d %b %Y %H:%M:%S UTC'

**SSL only**

We require that all requests(except for the ping) are done over SSL.

**Response formats**

The currently-available response format for all REST endpoints is the string-based format JavaScript Object Notation(JSON_).
The server answer can be one of the following content-type in the http Header::

    Content-type: application/json
    Content-Type: application/x-json-stream

In the last case, it corresponds to JSON objects delimited by newlines(streaming JSON for large answer), e.g.::

    { "id": 1, "foo": "bar" }
    { "id": 2, "foo": "baz" }
    ...

**Error handling**

Errors are returned using standard HTTP error code syntax.
Any additional info is included in the header of the return call, JSON-formatted with the parameters::

    ExceptionClass
    ExceptionMessage

Where ExceptionClass refers to :ref:`exceptions`.

.. _OAuth: http://oauth.net/
.. _JSON: http://www.json.org/

The methods are separated per resource type.

.. toctree::
    :maxdepth: 1

    restapi/account
    restapi/account_limit
    restapi/archive
    restapi/authentication
    restapi/config
    restapi/did
    restapi/heartbeat
    restapi/identity
    restapi/lifetime_exception
    restapi/lock
    restapi/meta
    restapi/nongrid_trace
    restapi/objectstore
    restapi/ping
    restapi/redirect
    restapi/replica
    restapi/request
    restapi/rse
    restapi/rule
    restapi/scope
    restapi/subscription
    restapi/temporary_did
    restapi/trace
