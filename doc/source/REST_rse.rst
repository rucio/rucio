==========
rse.py
==========

.. http:get:: /rses//

 List all RSEs.

 **Example request**:

 .. sourcecode:: http

    GET /rses// HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 400: 'InvalidRSEExpression': e
 :statuscode 400: 'InvalidObject': e[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]


.. http:post:: /rses/<rse>

 Create RSE with given name.

 **Example request**:

 .. sourcecode:: http

    POST /rses/<rse> HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter dictionary'
 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 409: 'Duplicate': e[0][0]
 :statuscode 400: 'InvalidObject': e[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]

.. http:put:: /rses/<rse>

 Update RSE properties (e.g. name, availability).

 **Example request**:

 .. sourcecode:: http

    PUT /rses/<rse> HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter dictionary'
 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 409: 'Duplicate': e[0][0]
 :statuscode 400: 'InvalidObject': e[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]

.. http:get:: /rses/<rse>

 Details about a specific RSE.

 **Example request**:

 .. sourcecode:: http

    GET /rses/<rse> HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/json'

 :statuscode 404: 'RSENotFound': e[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]

.. http:delete:: /rses/<rse>

 Disable RSE with given account name.

 **Example request**:

 .. sourcecode:: http

    DELETE /rses/<rse> HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 404: 'RSENotFound': e.args[0][0]
 :statuscode 401: 'AccessDenied': e.args[0][0]


.. http:post:: /rses

 create rse with given RSE name.

 **Example request**:

 .. sourcecode:: http

    POST /rses HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter dictionary'
 :statuscode 400: 'KeyError': '%s not defined' % str(e
 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 409: 'Duplicate': e[0][0]

.. http:get:: /rses

 list all RSE attributes for a RSE.

 **Example request**:

 .. sourcecode:: http

    GET /rses HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/json'



.. http:delete:: /rses

  No doc string

 **Example request**:

 .. sourcecode:: http

    DELETE /rses HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:




.. http:get:: /rses

 List all supported protocols of the given RSE.

 **Example request**:

 .. sourcecode:: http

    GET /rses HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/json'

 :statuscode 404: 'RSEOperationNotSupported': e[0][0]
 :statuscode 404: 'RSENotFound': e[0][0]
 :statuscode 404: 'RSEProtocolNotSupported': e[0][0]
 :statuscode 404: 'RSEProtocolDomainNotSupported': e[0][0]
 :statuscode 404: 'RSEProtocolNotSupported': 'No prptocols found for this RSE'




.. http:post:: /rses

        Create a protocol for a given RSE.

 **Example request**:

 .. sourcecode:: http

    POST /rses HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter dictionary'
 :statuscode 404: 'RSENotFound': e[0][0]
 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 409: 'Duplicate': e[0][0]
 :statuscode 400: 'InvalidObject': e[0][0]
 :statuscode 404: 'RSEProtocolDomainNotSupported': e[0][0]
 :statuscode 409: 'RSEProtocolPriorityError': e[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]

.. http:get:: /rses

 List all references of the provided RSE for the given protocol.

 **Example request**:

 .. sourcecode:: http

    GET /rses HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/json'

 :statuscode 404: 'RSENotFound': e[0][0]
 :statuscode 404: 'RSEProtocolNotSupported': e[0][0]
 :statuscode 404: 'RSEProtocolDomainNotSupported': e[0][0]

.. http:put:: /rses

        Updates attributes of an existing protocol entry. Because protocol identifier, hostname,

 **Example request**:

 .. sourcecode:: http

    PUT /rses HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter dictionary'
 :statuscode 400: 'InvalidObject': e[0][0]
 :statuscode 404: 'RSEProtocolNotSupported': e[0][0]
 :statuscode 404: 'RSENotFound': e[0][0]
 :statuscode 404: 'RSEProtocolDomainNotSupported': e[0][0]
 :statuscode 409: 'RSEProtocolPriorityError': e[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]

.. http:delete:: /rses

        Deletes a protocol entry for the provided RSE.

 **Example request**:

 .. sourcecode:: http

    DELETE /rses HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 404: 'RSEProtocolNotSupported': e[0][0]
 :statuscode 404: 'RSENotFound': e[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]



.. http:get:: /rses

        Get RSE usage information.

 **Example request**:

 .. sourcecode:: http

    GET /rses HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 404: 'RSENotFound': e[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]

.. http:put:: /rses

 Update RSE usage information.

 **Example request**:

 .. sourcecode:: http

    PUT /rses HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter dictionary'
 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]




.. http:get:: /rses

        Get RSE usage information.

 **Example request**:

 .. sourcecode:: http

    GET /rses HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 404: 'RSENotFound': e[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]





.. http:get:: /rses

        Get RSE limits.

 **Example request**:

 .. sourcecode:: http

    GET /rses HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/json'

 :statuscode 404: 'RSENotFound': e[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]

.. http:put:: /rses

 Update RSE limits.

 **Example request**:

 .. sourcecode:: http

    PUT /rses HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/json'

 :statuscode 400: 'ValueError': 'Cannot decode json parameter dictionary'
 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]



