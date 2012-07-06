..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

--------
Usecases
--------

.. _usecases:

Usecases covered by Rucio
=========================


The following usecases are handled by Rucio and should be described with
sequence diagrams.

* Register account (Thomas)
* Add identity to an account  (Mario)
* Add scopes to an account  (Thomas)
* :doc:`usecases/authentication` (Mario)
* Register file already on storage system (Ralph)
* Re-upload a file after an failed upload (Ralph)
* Where are the replicas for a file (Thomas)
* Register a dataset with files (Angelos)
* :doc:`usecases/usecase_upload_file_into_rucio` (Ralph)
* Set a replication rule on a existing file (Martin)
* Upload file into rucio with replication rules (Martin/Ralp)
* Register a transfer request for a file and FTS (Mario)
* Close a dataset(Angelos)
* Declare file unwanted (Angelos)
* Declare dataset unwanted (Angelos)
* Declare file as lost (Angelos)
* List dataset parents (Angelos)
* Detect that a storage is closed to be full/reached the watermark (Mario)
* Select unwanted files (with no replication rules) for deletion on a storage which is full (Martin)
* Delete a file replica from a storage (Mario)
* Crosscheck if a file is still on disk and in the rucio catalog (Mario)
* Download files from rucio/storage (Ralph)
* Download all files in a dataset from rucio/storage (Ralph)
* Download all files from a given list of files from rucio/storage (Ralph)
* Download all files from a given list of file replicas from rucio/storage (Ralph)
* Where are the replicas for all files in dataset (Angelos)
* Add metadata to file (Mario)
* Add metadata to dataset (Mario)
* Obsolete a dataset (Mario)
* Search datasets with wildcard pattern, meta-data (Mario)
* Remove replication rules on a file (Martin)
* Subscribe automatically all blue files to a RSE DATADISKS (Martin)
* Generate the list of files at a site
* Tell how many files/how much space is used at a site
* Crosscheck that all files are still on disk and in the rucio catalog
* Send notifications when a transfer is done
* An user A should not be able to register a dataset in the scope of an user B
* Give how much data has an account
* Set a quota on an account
* etc.