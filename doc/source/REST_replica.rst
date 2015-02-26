==========
replica.py
==========

.. http:get:: /replicas/<scope>/<name>/?$

        List all replicas for data identifiers.

 **Example request**:

 .. sourcecode:: http

    GET /replicas/<scope>/<name>/?$ HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 404: 'DataIdentifierNotFound': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]

.. http:post:: /replicas/?$/?$/(.+)/(.+)/?$

        Create file replicas at a given RSE.

 **Example request**:

 .. sourcecode:: http

    POST /replicas/?$/?$/(.+)/(.+)/?$ HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter list'
 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 409: 'Duplicate': e[0][0]
 :statuscode 409: 'DataIdentifierAlreadyExists': e[0][0]
 :statuscode 404: 'RSENotFound': e[0][0]
 :statuscode 503: 'ResourceTemporaryUnavailable': e[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]

.. http:put:: /replicas/?$/?$/(.+)/(.+)/?$

        Update a file replicas state at a given RSE.

 **Example request**:

 .. sourcecode:: http

    PUT /replicas/?$/?$/(.+)/(.+)/?$ HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter list'
 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 500: 'UnsupportedOperation': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]

.. http:delete:: /replicas/?$/?$/(.+)/(.+)/?$

        Delete file replicas at a given RSE.

 **Example request**:

 .. sourcecode:: http

    DELETE /replicas/?$/?$/(.+)/(.+)/?$ HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter list'
 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 404: 'RSENotFound': e[0][0]
 :statuscode 503: 'ResourceTemporaryUnavailable': e[0][0]
 :statuscode 404: 'ReplicaNotFound': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]


.. http:post:: /replicas/list/?$/list/?$

        List all replicas for data identifiers.

 **Example request**:

 .. sourcecode:: http

    POST /replicas/list/?$/list/?$ HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 400: 'ValueError': 'Cannot decode json parameter list'
 :statuscode 404: 'DataIdentifierNotFound': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]


.. http:post:: /replicas/getdidsfromreplicas/?$/getdidsfromreplicas/?$

        List the DIDs associated to a list of replicas.

 **Example request**:

 .. sourcecode:: http

    POST /replicas/getdidsfromreplicas/?$/getdidsfromreplicas/?$ HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 400: 'ValueError': 'Cannot decode json parameter list'
 :statuscode 500: e.__class__.__name__: e.args[0][0]


.. http:post:: /replicas/badreplicas/?$/badreplicas/?$

        Declare a list of bad replicas.

 **Example request**:

 .. sourcecode:: http

    POST /replicas/badreplicas/?$/badreplicas/?$ HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 400: 'ValueError': 'Cannot decode json parameter list'
 :statuscode 404: 'ReplicaNotFound': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]


