..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

----------------
Add subscription
----------------

* Client adds a subscription without the retrofit option

  Due to the retrofit option not beeing enabled, the subscription is only
  registered and therefore only checked against future data.

.. sequence-diagram::

   HTTPClient::
   REST::
   Core::
   DB::

   HTTPClient:REST[a].POST subscriptions/
   REST[a]:Core[a].addSubscription(filter, action, retrofit=False)
   Core[a]:DB.SQL

* Client adds a subscription with the retrofit option

  Due to the retrofit option beeing enabled, the subscription must be matched
  against all existing data. 

.. sequence-diagram::

   HTTPClient::
   REST::
   Core::
   DB::
   JobServer::
   Worker::

   HTTPClient:REST[a].POST /subscriptions/
   REST[a]:Core[a].addSubscription(filter, action, retrofit=True)
   Core[a]:DB.SQL
   Core[a]:JobServer.executeRetroactiveSubscription(**)
   JobServer:>Worker.executeRetroactiveSubscription(**)
   Core:_
   REST:_
   HTTPClient:_
   Worker:Core[c].searchDatasets(**)
   Core[c]:DB.SQL
   [c loop or bulk]
     Worker:Core[b].setReplicationRules(**)
     Core[b]:DB.SQL
     Core[b]:Core.registerTransfers(**)
   [/c]



 

