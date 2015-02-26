==========
account.py
==========


.. http:get:: /accounts/<account>/attr/

 list all attributes for an account.

 **Example request**:

 .. sourcecode:: http

    GET /accounts/<account>/attr/ HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/json'

 :statuscode 404: 'AccountNotFound': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]

.. http:post:: /accounts/<account>/attr/<key>

 Add attributes to an account.

 **Example request**:

 .. sourcecode:: http

    POST /accounts/<account>/attr/<key> HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'cannot decode json parameter dictionary'
 :statuscode 400: 'KeyError': '%s not defined' % str(e
 :statuscode 400: 'TypeError': 'body must be a json dictionary'
 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 409: 'Duplicate': e.args[0][0]
 :statuscode 404: 'AccountNotFound': e.args[0][0]

.. http:delete:: /accounts/<account>/attr/<key>

 disable account with given account name.

 **Example request**:

 .. sourcecode:: http

    DELETE /accounts/<account>/attr/<key> HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 404: 'AccountNotFound': e.args[0][0]


.. http:get:: /accounts/<account>/scopes/

 list all scopes for an account.

 **Example request**:

 .. sourcecode:: http

    GET /accounts/<account>/scopes/ HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/json'

 :statuscode 404: 'AccountNotFound': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]
 :statuscode 404: 'ScopeNotFound': 'no scopes found for account ID \'%s\'' % account

.. http:post:: /accounts/<account>/scopes/<scope>

 create scope with given scope name.

 **Example request**:

 .. sourcecode:: http

    POST /accounts/<account>/scopes/<scope> HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 409: 'Duplicate': e.args[0][0]
 :statuscode 404: 'AccountNotFound': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]


.. http:get:: /accounts/<account>

 get account information for given account name.

 **Example request**:

 .. sourcecode:: http

    GET /accounts/<account> HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/json'

 :statuscode 404: 'AccountNotFound': e.args[0][0]
 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]


.. http:post:: /accounts/<account>

 create account with given account name.

 **Example request**:

 .. sourcecode:: http

    POST /accounts/<account> HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'cannot decode json parameter dictionary'
 :statuscode 400: 'KeyError': '%s not defined' % str(e
 :statuscode 400: 'TypeError': 'body must be a json dictionary'
 :statuscode 409: 'Duplicate': e.args[0][0]
 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]

.. http:delete:: /accounts/<account>

 disable account with given account name.

 **Example request**:

 .. sourcecode:: http

    DELETE /accounts/<account> HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 404: 'AccountNotFound': e.args[0][0]


.. http:get:: /accounts/?$/?$

 list all rucio accounts.

 **Example request**:

 .. sourcecode:: http

    GET /accounts/?$/?$ HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'



.. http:get:: /accounts/<account>/limits/<rse=None>

 get the current limits for an account on a specific RSE

 **Example request**:

 .. sourcecode:: http

    GET /accounts/<account>/limits/<rse=None> HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/json'

 :statuscode 404: 'RSENotFound': e.args[0][0]





.. http:post:: /accounts/<account>/identities

 Grant an identity access to an account.

 **Example request**:

 .. sourcecode:: http

    POST /accounts/<account>/identities HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'cannot decode json parameter dictionary'
 :statuscode 400: 'KeyError': '%s not defined' % str(e
 :statuscode 400: 'TypeError': 'body must be a json dictionary'
 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 409: 'Duplicate': e.args[0][0]
 :statuscode 404: 'AccountNotFound': e.args[0][0]

.. http:get:: /accounts/<account>/identities

  No doc string

 **Example request**:

 .. sourcecode:: http

    GET /accounts/<account>/identities HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'



.. http:delete:: /accounts/<account>/identities

 Delete an account's identity mapping.

 **Example request**:

 .. sourcecode:: http

    DELETE /accounts/<account>/identities HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'cannot decode json parameter dictionary'
 :statuscode 400: 'KeyError': '%s not defined' % str(e
 :statuscode 400: 'TypeError': 'body must be a json dictionary'
 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 404: 'AccountNotFound': e.args[0][0]
 :statuscode 404: 'IdentityError': e.args[0][0]


.. http:get:: /accounts/<account>/rules

        Return all rules of a given account.

 **Example request**:

 .. sourcecode:: http

    GET /accounts/<account>/rules HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 404: 'RuleNotFound': e.args[0][0]





.. http:get:: /accounts/<account>/usage/

        Return the account usage of the account.

 **Example request**:

 .. sourcecode:: http

    GET /accounts/<account>/usage/ HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 404: 'AccountNotFound': e.args[0][0]
 :statuscode 401: 'AccessDenied': e.args[0][0]





.. http:get:: /accounts/<account>/usage/<rse>

        Return the account usage of the account.

 **Example request**:

 .. sourcecode:: http

    GET /accounts/<account>/usage/<rse> HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 404: 'AccountNotFound': e.args[0][0]
 :statuscode 404: 'RSENotFound': e.args[0][0]
 :statuscode 401: 'AccessDenied': e.args[0][0]





