==========
authentication.py
==========

.. http:options:: /auth/userpass/userpass

        HTTP Success:

 **Example request**:

 .. sourcecode:: http

    OPTIONS /auth/userpass/userpass HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:


.. http:get:: /auth/userpass/userpass

        HTTP Success:

 **Example request**:

 .. sourcecode:: http

    GET /auth/userpass/userpass HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 401: 'CannotAuthenticate': 'Cannot authenticate to account %(account
 :statuscode 500: e.__class__.__name__: e.args[0]
 :statuscode 401: 'CannotAuthenticate': 'Cannot authenticate to account %(account


.. http:options:: /auth/gss/gss

        HTTP Success:

 **Example request**:

 .. sourcecode:: http

    OPTIONS /auth/gss/gss HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:




.. http:options:: /auth/x509/x509_proxy/x509/x509_proxy

        HTTP Success:

 **Example request**:

 .. sourcecode:: http

    OPTIONS /auth/x509/x509_proxy/x509/x509_proxy HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:


.. http:get:: /auth/x509/x509_proxy/x509/x509_proxy

        HTTP Success:

 **Example request**:

 .. sourcecode:: http

    GET /auth/x509/x509_proxy/x509/x509_proxy HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 401: 'CannotAuthenticate': 'Cannot get DN'
 :statuscode 401: 'CannotAuthenticate': 'Cannot authenticate to account %(account
 :statuscode 401: 'CannotAuthenticate': 'No default account set for %(dn
 :statuscode 401: 'CannotAuthenticate': 'Cannot authenticate to account %(account


.. http:options:: /auth/validate/validate

        HTTP Success:

 **Example request**:

 .. sourcecode:: http

    OPTIONS /auth/validate/validate HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:


.. http:get:: /auth/validate/validate

        HTTP Success:

 **Example request**:

 .. sourcecode:: http

    GET /auth/validate/validate HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 401: 'CannotAuthenticate': 'Cannot authenticate to account %(account


