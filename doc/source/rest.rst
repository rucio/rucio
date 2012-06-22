=================
Rucio RESTful API
=================

Each resource can be accessed or modified using specially formed URLs and the HTTP verbs GET, POST, PUT, and DELETE.
Descriptions of the actions you may perform on each resource can be found below.


Resources
=========

The following are the different resources that can be accessed or modified using the API.

 * Session token
 * Rucio account
 * Dataset
 * File
 * Meta-data attributes
 * Rucio Storage Element
 * Permission model
 * Replication rule
 * Transfer request

We use the standard HTTP methods:

 * GET to read
 * POST to create
 * PUT to update
 * DELETE to remove


Requesting a Rucio-Auth-Token with curl via username and password
-----------------------------------------------------------------

Add the necessary request headers, and retrieve the authentication token from the header::

    curl -vvv -X GET -H "Rucio-Account: ddmlab" -H "Rucio-Username: mlassnig" -H "Rucio-Password: secret" http://localhost/auth/userpass

Example response::

* About to connect() to localhost port 80 (#0)
*   Trying ::1... Connection refused
*   Trying 127.0.0.1... connected
* Connected to localhost (127.0.0.1) port 80 (#0)
* GET /auth/userpass HTTP/1.1
* User-Agent: curl/7.21.4 (universal-apple-darwin11.0) libcurl/7.21.4 OpenSSL/0.9.8r zlib/1.2.5
* Host: localhost
* Accept: */*
* Rucio-Account: ddmlab
* Rucio-Username: mlassnig
* Rucio-Password: secret
*
* HTTP/1.1 200 OK
* Content-Type: application/octet-stream
* Rucio-Auth-Token: 65523e8dee194189ab537c3d624db0a0
* Content-Length: 0
* Date: Wed, 14 Mar 2012 10:33:51 GMT
* Server: lighttpd/1.4.30
*
* Connection #0 to host localhost left intact
* Closing connection #0


Manually checking the validity of a Rucio-Auth-Token with curl
--------------------------------------------------------------

You can then check the validity of the authentication token by issuing::

    curl -X GET -H "Rucio-Account: ddmlab" -H "Rucio-Auth-Token: d97bc0a04b464df0a76bac6a95cf28ba" http://127.0.0.1/auth/validate

An HTTP response of 200 OK means the token is valid, and the data returned is the expected lifetime of the token. In case the token is not valid, the response will be a HTTP 401 Unauthorized.

Checking the validity of a token will extend its lifetime by one hour.
