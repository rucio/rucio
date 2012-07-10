..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

---------------------------------
Upload file with replication rule
---------------------------------

.. sequence-diagram::

   client:PythonClient
   core:rucioserver "RucioCore"
   storage:? "Grid Storage"

   client:core.registerFileToLocation(**)
   client:storage.uploadFile(data)
   client:core.commitFileRegistration(**)

   client:core[s].setReplicationRules(**)
   core[s]:core.registerTransfers(**)

The *registerTransfers* method registers the transfers to the transfer service,
which will asynchronously transfer the files to the sites. 
