..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0i

===================
Rucio Client How To
===================

``General concepts``
--------------------

``Introduction``
----------------
The main command line interface is rucio. Type rucio without arguments to get a list of possible sub-commands. A rucio-admin tool also exists which is used for administrative purposes. This tool is not covered here.

The recommended set up is to use ATLAS Local Root Base. localSetupDQ2Clients also sets up Rucio clients.


``Rucio concepts``
------------------

``DIDs``
--------
Dataset identifiers (DIDs) are the core objects in Rucio. They may be files, datasets or containers. Many Rucio commands ask for a DID and can accept files, datasets or containers.

``Accounts``
------------

Your identity in Rucio is the Rucio account. When joining the ATLAS VO you must pick a nickname which is the same as your CERN login account - this is also your default Rucio account. When using the recommended set up above the account is set automatically and you do not need to do anything further. Under special circumstances you may need to use another Rucio account and it can be set with the RUCIO_ACCOUNT environment variable.

``Scopes``
----------

Scopes are a new concept in Rucio and are a way of partitioning the dataset and file namespace. Every DID has a scope and a name and the Rucio clients always display this as scope:name. When a command requires a DID argument it must be the full DID with scope:name. With the default Rucio account you may only create new DIDs in your own scope, user.username. Only special admin users can create DIDs in other scopes.

``Permissions``
---------------
As a regular user you are only permitted to upload data directly to SCRATCHDISK sites or at your LOCALGROUPDISK. SCRATCHDISKs is also where the outputs of your jobs normally go. Data on SCRATCHDISK has a lifetime of 15 days. The lifetime of the data on LOCALGROUPDISKs can be infinite.

    - Datasets and files
        Mario
    - Dataset Containers
        Mario
    - Physics Containers
        Ralph
    - Replicas
        Ralph
    - Sites, mass storage systems and SRM
        Joaquin
    - When to use dq2-get or DDM subscriptions
        Wen
    - Few informations about DDM subscriptions
        Mario

``Installing/Initializing dq2 commands``
----------------------------------------
    - Installing dq2 commands
        Thomas
    - Initializing dq2 commands
        Wen

``User Identity``
-----------------
``Querying``
------------
    - List all DDM sites
        Martin
    - Find a dataset
        Ralph
    - List the contents of a dataset
        Cedric
    - List the replica locations of a dataset
        Cedric
    - List the datasets at a site
        Cedric
    - List the files in a dataset
        Cedric
    - List the files in a dataset existing at a site
        Cedric
    - List the physical filenames in a dataset
        Cedric
    - List the file paths of a dataset replica at a site
        Cedric
    - List the dataset(s) where a particular file belongs
        Martin
    - Create a Pool File Catalogue with files on a site
        Joaquin
    - Create a Pool File Catalogue and let the system guess the PFN
        Martin
    - Create a Pool File Catalogue in a Tier-3
        Thomas

``Retrieving data``
-------------------
    - Download a full dataset
        Cedric
    - Download specific files from a dataset
        Thomas
    - Download a sample of n random files from a dataset
        Thomas
    - Download a dataset from a specific site
        Martin
    - Download with datasets/files given in an inputfile
        Ralph
    - Download datasets from tape
        Wen
    - Restrictions to access datasets on tape
        Vincent

``Creating data``
-----------------
    - General Workflow for creating data
        Cedric
    - Which name should I give to my files and dataset
        Cedric
    - Where my dataset/files will be stored with dq2-put ?
        Cedric
    - Where my dataset/files should be finally stored ?
        Mario
    - Maximum number of files in a dataset
        Joaquin
    - Create a dataset from files on my local disk
        Joaquin
    - Create a dataset from files on CASTOR at CERN
        Thomas
    - Create a dataset from files on my site's DPM
        Ralph
    - Write a dataset/files in a specific DDM site
        Wen
    - Create a dataset from files already in other datasets
        Wen
    - Add files to a dataset
        Mario
    - What to do after creating a dataset?
        Mario
    - Close a dataset
        Martin
    - Re-open a dataset
        Martin
    - Freeze a dataset
        Martin

``Policy implemented centrally on datasets``
--------------------------------------------
    - Automatic freezing of user/group datasets
        Ralph
    - Lifetime of datasets on SCRATCHDISK
        Mario
    - Dataset deletion from 'aborted' or 'obsolete' tasks (central or group production)
        Vincent
    - Central deletion policy on DDM sites
        Wen

``Dataset Container commands``
------------------------------
    - Create a Dataset Container and include datasets
        Mario
    - List the locations of a container
        Vincent
    - Remove datasets from a Dataset Container
        Ralph
    - List datasets in a Dataset Container
        Joaquin
    - Erase a container
        Wen
    - Commands to manipulate files in Dataset Containers
        Thomas
    - FAQ
        - 'Freezing' a container
            Thomas
        - Naming convention
            Wen
        - Container of containers
            Thomas

``Advanced uses``
-----------------
    - What to do after my distributed analysis jobs create a dataset?
        Joaquin
    - Replicate a dataset to another DDM site
        Martin
    - Check if a file is corrupted
        Wen
    - Know the size of the dataset
        Joaquin
    - Delete a dataset replica from a site - delete a dataset from DDM catalog
        Vincent
    - Remove files from a dataset
        Joaquin
    - Create a dataset from files already in other datasets
        Wen
    - Verify local files with registered attributes
        Joaquin
    - More advanced uses
        Ralph

``Known problems``
------------------
    - Dataset complete in siteA but dq2-ls -f provides no physical files
        Ralph

``Links to external applications creating datasets``
----------------------------------------------------
    - Group production through Production system
        Thomas