==========
lock.py
==========

.. http:get:: /locks

 get locks for a given rse.

 **Example request**:

 .. sourcecode:: http

    GET /locks HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 500: e.__class__.__name__: e.args[0]


.. http:get:: /locks

 get locks for a given scope, name.

 **Example request**:

 .. sourcecode:: http

    GET /locks HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 500: e.__class__.__name__: e.args[0]


