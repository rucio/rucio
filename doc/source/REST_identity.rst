==========
identity.py
==========

.. http:put:: /identities/<account>/x509

        Create a new identity and map it to an account.

 **Example request**:

 .. sourcecode:: http

    PUT /identities/<account>/x509 HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:



.. http:put:: /identities/<account>/gss

        Create a new identity and map it to an account.

 **Example request**:

 .. sourcecode:: http

    PUT /identities/<account>/gss HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:



