==========
redirect.py
==========

.. http:get:: /redirect/<scope>/<name>/?$

        Redirect download

 **Example request**:

 .. sourcecode:: http

    GET /redirect/<scope>/<name>/?$ HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 500: e.__class__.__name__: e.args[0][0]


