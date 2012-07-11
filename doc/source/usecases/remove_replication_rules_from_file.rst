..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

----------------------------------
Remove replication rules from file
----------------------------------

.. sequence-diagram::

   HTTPClient::
   REST::
   Core::
   DB::

   HTTPClient:REST[a].DEL /?/
   REST[a]:Core.removeReplicationRules(**)
   Core:DB.SQL
