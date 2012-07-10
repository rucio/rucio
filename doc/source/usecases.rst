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
* :doc:`usecases/add_scope_to_account` (Thomas)
* An user A should not be able to register a dataset in the scope of an user B
* Close a dataset (Angelos)
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
* :doc:`usecases/register_account` (Thomas)
* Register file already on storage system (Ralph)
* :doc:`usecases/remove_replication_rules_from_file` (Martin)
* :doc:`usecases/select_unwanted_files_for_deletion` (Martin)
* Send notifications when a transfer is done
* Set a quota on an account
* :doc:`usecases/set_replication_rule_to_file` (Martin)
* :doc:`usecases/add_subscription` (Martin)
* Tell how many files/how much space is used at a site
* :doc:`usecases/upload_file_with_replication_rule` (Martin/Ralph)
* :doc:`usecases/where_are_the_replicas_for_a_file` (Thomas)
* Where are the replicas for all files in dataset (Angelos)
* etc.
