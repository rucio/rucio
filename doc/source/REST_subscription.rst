==========
subscription.py
==========

.. http:get:: /subscriptions

        Retrieve a subscription.

 **Example request**:

 .. sourcecode:: http

    GET /subscriptions HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 404: 'SubscriptionNotFound': e[0][0]

.. http:put:: /subscriptions

        Update an existing subscription.

 **Example request**:

 .. sourcecode:: http

    PUT /subscriptions HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter list'
 :statuscode 404: 'SubscriptionNotFound': e[0][0]
 :statuscode 400: 'InvalidObject': e[0][0]

.. http:post:: /subscriptions

        Create a new subscription.

 **Example request**:

 .. sourcecode:: http

    POST /subscriptions HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter list'
 :statuscode 409: 'SubscriptionDuplicate': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]
 :statuscode 400: 'InvalidObject': e[0][0]



.. http:get:: /subscriptions

        Return all rules of a given subscription id.

 **Example request**:

 .. sourcecode:: http

    GET /subscriptions HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 404: 'RuleNotFound': e.args[0][0]
 :statuscode 404: 'SubscriptionNotFound': e[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0]





.. http:get:: /subscriptions/<account>/<name=None>/Rules/States

        Return a summary of the states of all rules of a given subscription id.

 **Example request**:

 .. sourcecode:: http

    GET /subscriptions/<account>/<name=None>/Rules/States HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 500: e.__class__.__name__: e.args[0]


.. http:get:: /subscriptions

        Retrieve a subscription matching the given subscription id

 **Example request**:

 .. sourcecode:: http

    GET /subscriptions HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/json'

 :statuscode 404: 'SubscriptionNotFound': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0]


