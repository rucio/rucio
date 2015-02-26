==========
rule.py
==========


.. http:get:: /rules

 get rule information for given rule id.

 **Example request**:

 .. sourcecode:: http

    GET /rules HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/json'

 :statuscode 404: 'RuleNotFound': e.args[0][0]
 :statuscode 500: e.__class__.__name__: e.args[0]

.. http:put:: /rules

        Update the replication rules locked flag .

 **Example request**:

 .. sourcecode:: http

    PUT /rules HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 404: 'RuleNotFound': e.args[0][0]
 :statuscode 404: 'AccountNotFound': e.args[0][0]
 :statuscode 400: 'ValueError': 'Cannot decode json parameter list'
 :statuscode 500: e.__class__.__name__: e.args[0][0]

.. http:post:: /rules

        Create a new replication rule.

 **Example request**:

 .. sourcecode:: http

    POST /rules HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter list'
 :statuscode 409: 'InvalidReplicationRule': e.args[0][0]
 :statuscode 409: 'DuplicateRule': e.args[0]
 :statuscode 409: 'InsufficientTargetRSEs': e.args[0][0]
 :statuscode 409: 'InsufficientAccountLimit': e.args[0][0]
 :statuscode 409: 'InvalidRSEExpression': e.args[0][0]
 :statuscode 404: 'DataIdentifierNotFound': e.args[0][0]
 :statuscode 409: 'ReplicationRuleCreationTemporaryFailed': e.args[0][0]
 :statuscode 409: 'InvalidRuleWeight': e.args[0][0]
 :statuscode 409: 'StagingAreaRuleRequiresLifetime': e.args[0]
 :statuscode 409: 'InvalidObject': e.args[0]
 :statuscode 500: e.__class__.__name__: e.args[0][0]

.. http:delete:: /rules

        Delete a new replication rule.

 **Example request**:

 .. sourcecode:: http

    DELETE /rules HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type:

 :statuscode 400: 'ValueError': 'Cannot decode json parameter list'
 :statuscode 401: 'AccessDenied': e.args[0][0]
 :statuscode 404: 'RuleNotFound': e.args[0][0]


.. http:get:: /rules

 get locks for a given rule_id.

 **Example request**:

 .. sourcecode:: http

    GET /rules HTTP/1.1

 **Example response**:

 .. sourcecode:: http

  HTTP/1.1 200 OK
  Vary: Accept
  Content-Type: 'application/x-json-stream'

 :statuscode 500: e.__class__.__name__: e.args[0]


