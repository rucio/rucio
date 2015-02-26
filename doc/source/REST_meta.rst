==========
meta.py
==========

.. http:get:: /meta

        List all keys.

 **Example request**:

 .. sourcecode:: http

    GET /meta HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/json'



.. http:post:: /meta

        Create a new allowed key (value is NULL).

 **Example request**:

 .. sourcecode:: http

    POST /meta HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter list'
 :statuscode 409: 'Duplicate': e[0][0]
 :statuscode 400: 'UnsupportedValueType': e[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]



.. http:get:: /meta

        List all values for a key.

 **Example request**:

 .. sourcecode:: http

    GET /meta HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/json'



.. http:post:: /meta

        Create a new value for a key.

 **Example request**:

 .. sourcecode:: http

    POST /meta HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter list'
 :statuscode 409: 'Duplicate': e[0][0]
 :statuscode 400: 'InvalidValueForKey': e[0][0]
 :statuscode 400: 'KeyNotFound': e[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]



