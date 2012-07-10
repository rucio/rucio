..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

----------------
Add subscription
----------------

* Client adds a subscription without the retroactive option

  Due to the retroactive option not beeing enabled, the subscription is only
  registered and therefore only checked against future data.

.. sequence-diagram::

   client:PythonClient
   core:rucioserver "RucioServer"

   client:core.addSubscription(filter, action, retroactive=False)

* Client adds a subscription with the retroactive option

  Due to the retroactive option beeing enabled, the subscription must be matched
  against all existing data. 

.. sequence-diagram::

   client:PythonClient
   core:rucioserver "RucioServer"
   jobserver:jobserver "JobServer"
   worker:worker

   client:core[s].addSubscription(filter, action, retroactive=True)
   core[s]:jobserver.executeRetroactiveSubscription(**)
   #[c asynchronously]
   jobserver:>worker.executeRetroactiveSubscription(**)
   #[/c]
   core:_
   client:_
   worker:core.searchDatasets(**)
   worker:core[j].setReplicationRules(**)
   core[j]:core.registerTransfers(**)   

