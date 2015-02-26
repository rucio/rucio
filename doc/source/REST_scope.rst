==========
scope.py
==========

.. http:get:: /scopes

        List all scopes.

 **Example request**:

 .. sourcecode:: http

    GET /scopes HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:



.. http:post:: /scopes

        Creates scope with given scope name.

 **Example request**:

 .. sourcecode:: http

    POST /scopes HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 409: 'Duplicate': e.args[0][0]
 :statuscode 404: 'AccountNotFound': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]



.. http:get:: /scopes

        List all scopes for an account.

 **Example request**:

 .. sourcecode:: http

    GET /scopes HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/json'

 :statuscode 404: 'AccountNotFound': e.args[0][0]
 :statuscode 404: 'ScopeNotFound': 'no scopes found for account ID \'%s\'' % account





