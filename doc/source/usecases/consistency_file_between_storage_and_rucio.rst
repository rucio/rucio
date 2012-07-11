..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

------------------------------------------------------------
Check the consistency between a file on storage and in Rucio
------------------------------------------------------------

Periodically retrieve the file metadata from the external storage system.

.. sequence-diagram::

    Storage::{locationName}
    Daemon::
    DB::

    [c:loop]
    Daemon:physical_file_metadata=Storage.stat({physicalFileName})
    Daemon:DB.store(physical_file_metadata)
    Daemon:Daemon.compareAndNotify()
    [/c]
