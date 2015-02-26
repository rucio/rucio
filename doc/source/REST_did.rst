==========
did.py
==========

.. http:get:: /dids/<scope>/$

        Return all data identifiers in the given scope.

 **Example request**:

 .. sourcecode:: http

    GET /dids/<scope>/$ HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 404: 'DataIdentifierNotFound': e.args[0][0]


.. http:get:: /dids/<scope>/dids/search

        List all data identifiers in a scope which match a given metadata.

 **Example request**:

 .. sourcecode:: http

    GET /dids/<scope>/dids/search HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 409: 'UnsupportedOperation': e.args[0][0]
 :statuscode 404: 'KeyNotFound': e.args[0][0]


.. http:post:: /dids

  No doc string

 **Example request**:

 .. sourcecode:: http

    POST /dids HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:



.. http:post:: /dids/attachments/attachments

  No doc string

 **Example request**:

 .. sourcecode:: http

    POST /dids/attachments/attachments HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:



.. http:get:: /dids/<scope>/<name>/status/(.+)/(.+)

        Retrieve a single data identifier.

 **Example request**:

 .. sourcecode:: http

    GET /dids/<scope>/<name>/status/(.+)/(.+) HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/json'

 :statuscode 404: 'ScopeNotFound': e.args[0][0]
 :statuscode 404: 'DataIdentifierNotFound': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]

.. http:post:: /dids/<scope>/<name>/status/(.+)/(.+)

        Create a new data identifier.

 **Example request**:

 .. sourcecode:: http

    POST /dids/<scope>/<name>/status/(.+)/(.+) HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter list'
 :statuscode 400: 'ValueError': str(e
 :statuscode 404: 'DataIdentifierNotFound': e.args[0][0]
 :statuscode 409: 'DuplicateContent': e.args[0][0]
 :statuscode 409: 'DataIdentifierAlreadyExists': e.args[0][0]
 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 409: 'UnsupportedOperation': e.args[0][0]
 :statuscode 500: 'DatabaseException': e.args
 :statuscode 500: e.__class__.__name__: e.args[0][0]

.. http:put:: /dids/<scope>/<name>/status/(.+)/(.+)

        Update data identifier status.

 **Example request**:

 .. sourcecode:: http

    PUT /dids/<scope>/<name>/status/(.+)/(.+) HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json data parameter'
 :statuscode 404: 'DataIdentifierNotFound': e.args[0][0]
 :statuscode 409: 'UnsupportedStatus': e.args[0][0]
 :statuscode 409: 'UnsupportedOperation': e.args[0][0]
 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]


.. http:get:: /dids/<scope>/<name>/dids

        Returns the contents of a data identifier.

 **Example request**:

 .. sourcecode:: http

    GET /dids/<scope>/<name>/dids HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 404: 'DataIdentifierNotFound': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]

.. http:post:: /dids/<scope>/<name>/dids

        Append data identifiers to data identifiers.

 **Example request**:

 .. sourcecode:: http

    POST /dids/<scope>/<name>/dids HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter list'
 :statuscode 404: 'DataIdentifierNotFound': e.args[0][0]
 :statuscode 409: 'DuplicateContent': e.args[0][0]
 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 409: 'UnsupportedOperation': e.args[0][0]
 :statuscode 404: 'RSENotFound': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0]

.. http:delete:: /dids/<scope>/<name>/dids

        Detach data identifiers from data identifiers.

 **Example request**:

 .. sourcecode:: http

    DELETE /dids/<scope>/<name>/dids HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter list'
 :statuscode 409: 'UnsupportedOperation': e.args[0][0]
 :statuscode 404: 'DataIdentifierNotFound': e.args[0][0]
 :statuscode 401: 'AccessDenied': e.args[0][0]


.. http:get:: /dids

  No doc string

 **Example request**:

 .. sourcecode:: http

    GET /dids HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:



.. http:get:: /dids/<scope>/<name>/files

 List all replicas of a data identifier.

 **Example request**:

 .. sourcecode:: http

    GET /dids/<scope>/<name>/files HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 404: 'DataIdentifierNotFound': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]


.. http:get:: /dids/<scope>/<name>/parents

 List all parents of a data identifier.

 **Example request**:

 .. sourcecode:: http

    GET /dids/<scope>/<name>/parents HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 404: 'DataIdentifierNotFound': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]


.. http:get:: /dids/<scope>/<name>/meta

        List all meta of a data identifier.

 **Example request**:

 .. sourcecode:: http

    GET /dids/<scope>/<name>/meta HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/json'

 :statuscode 404: 'DataIdentifierNotFound': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]

.. http:post:: /dids/<scope>/<name>/meta/<key>

        Add metadata to a data identifier.

 **Example request**:

 .. sourcecode:: http

    POST /dids/<scope>/<name>/meta/<key> HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter list'
 :statuscode 409: 'Duplicate': e[0][0]
 :statuscode 400: 'KeyNotFound': e[0][0]
 :statuscode 400: 'InvalidMetadata': e[0][0]
 :statuscode 400: 'InvalidValueForKey': e[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]


.. http:get:: /dids/<scope>/<name>/rules

        Return all rules of a given DID.

 **Example request**:

 .. sourcecode:: http

    GET /dids/<scope>/<name>/rules HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 404: 'RuleNotFound': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0]


.. http:get:: /dids/<scope>/<name>/associated_rules

        Return all associated rules of a file.

 **Example request**:

 .. sourcecode:: http

    GET /dids/<scope>/<name>/associated_rules HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 500: e.__class__.__name__: e.args[0]


.. http:get:: /dids/<guid>/guid

        Return the file associated to a GUID.

 **Example request**:

 .. sourcecode:: http

    GET /dids/<guid>/guid HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 404: 'DataIdentifierNotFound': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0]


