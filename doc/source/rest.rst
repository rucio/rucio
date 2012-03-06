=================
Rucio RESTful API
=================

Each resource can be accessed or modified using specially formed URLs and the HTTP verbs GET, POST, PUT, and DELETE.
Descriptions of the actions you may perform on each resource can be found below.


Resources
=========

The following are the different ressources that can be accessed or modified using the API.

 * Session token
 * Rucio account
 * Dataset
 * File
 * Meta-data attributes
 * Rucio Storage Element
 * Permission model
 * Replication rule
 * Tranfer request

We use the standard HTTP methods:

 * GET to read
 * POST to create
 * PUT to update
 * DELETE to remove

Interesting link about API versioning:  http://www.informit.com/articles/article.aspx?p=1566460

Put vs Post to create: http://jcalcote.wordpress.com/2008/10/16/put-or-post-the-rest-of-the-story/

Session token
=============

Requesting a session token::

    PUT /tokens/ HTTP/1.1
    Authorization: <credentials>
    Content-Type: application/json
    Content-Length: <lenght>
    Accept: application/token.rucio-v1+json    
    Host: <hostname>:<port>
    Date: Tue, 27 Mar 2007 21:15:45 +0000

