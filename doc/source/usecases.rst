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

* :doc:`usecases/authentication`
* :doc:`usecases/search`
* :doc:`usecases/usecase_upload_file_into_rucio` (Ralph)
* :doc:`usecases/add_account_identity`
* Add metadata to dataset (Mario)
* Add metadata to file (Mario)
* Add scopes to an account  (Thomas)
* An user A should not be able to register a dataset in the scope of an user B
* Close a dataset(Angelos)
* Crosscheck if a file is still on disk and in the rucio catalog (Mario)
* Crosscheck that all files are still on disk and in the rucio catalog
* Declare dataset unwanted (Angelos)
* Declare file as lost (Angelos)
* Declare file unwanted (Angelos)
* Delete a file replica from a storage (Mario)
* Detect that a storage is closed to be full/reached the watermark (Mario)
* Download all files from a given list of file replicas from rucio/storage (Ralph)
* Download all files from a given list of files from rucio/storage (Ralph)
* Download all files in a dataset from rucio/storage (Ralph)
* Download files from rucio/storage (Ralph)
* Generate the list of files at a site
* Give how much data has an account
* List dataset parents (Angelos)
* Obsolete a dataset (Mario)
* Re-upload a file after an failed upload (Ralph)
* Register a dataset with files (Angelos)
* Register a transfer request for a file and FTS (Mario)
* Register account (Thomas)
* Register file already on storage system (Ralph)
* Remove replication rules on a file (Martin)
* Select unwanted files (with no replication rules) for deletion on a storage which is full (Martin)
* Send notifications when a transfer is done
* Set a quota on an account
* Set a replication rule on a existing file (Martin)
* Subscribe automatically all blue files to a RSE DATADISKS (Martin)
* Tell how many files/how much space is used at a site
* Upload file into rucio with replication rules (Martin/Ralp)
* Where are the replicas for a file (Thomas)
* Where are the replicas for all files in dataset (Angelos)
* etc.
