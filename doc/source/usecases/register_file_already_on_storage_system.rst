..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

---------------------------------------
Register file already on storage system
---------------------------------------

.. sequence-diagram::

  TZero:Actor
  REST::
  RSE::
  Protocol::
  StorageSystem::
  Core::

  TZero:REST[rest].registerExistingFile(filename)
    REST:[True, False]=RSE.fileExists(filename)
      RSE:[True, False]=Protocol.fileExists(filename)
        Protocol:[True, False]=StorageSystem.fileExists(filename)
    [c opt fileExists == True]
      REST:Core.regiserFile(filename, state='active')
      REST:Core.updateTracer(filename, 'registered existing file')
    [/c]
  REST[rest]:TZero.
