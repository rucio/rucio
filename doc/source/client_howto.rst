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

    - Datasets and files
    - Versions
    - Dataset Containers
    - Physics Containers
    - Replicas
    - Sites, mass storage systems and SRM
    - When to use dq2-get or DDM subscriptions
        - Few informations about DDM subscriptions

``Installing/Initializing dq2 commands``
----------------------------------------
    - Installing dq2 commands
    - Initializing dq2 commands

``User Identity``
-----------------
``Querying``
------------
    - list all DDM sites
    - find a dataset
    - list the contents of a dataset
    - list the replica locations of a dataset
    - list the datasets at a site
    - list the files in a dataset
    - list the files in a dataset existing at a site
    - list the physical filenames in a dataset
    - list the file paths of a dataset replica at a site
    - list the dataset(s) where a particular file belongs
    - create a Pool File Catalogue with files on a site
    - create a Pool File Catalogue and let the system guess the PFN
    - create a Pool File Catalogue in a Tier-3

``Retrieving data``
-------------------
    - download a full dataset
    - download specific files from a dataset
    - download a sample of n random files from a dataset
    - download a dataset from a specific site
    - download with datasets/files given in an inputfile
    - download datasets from tape
      - Restrictions to access datasets on tape

``Creating data``
-----------------
    - General Workflow for creating data
    - Which name should I give to my files and dataset
    - Where my dataset/files will be stored with dq2-put ?
    - Where my dataset/files should be finally stored ?
    - Maximum number of files in a dataset
    - create a dataset from files on my local disk
    - create a dataset from files on CASTOR at CERN
    - create a dataset from files on my site's DPM
    - write a dataset/files in a specific DDM site
    - create a dataset from files already in other datasets
    - add files to a dataset
    - What to do after creating a dataset?
    - close a dataset
    - re-open a dataset
    - freeze a dataset

``Policy implemented centrally on datasets``
--------------------------------------------
    - Automatic freezing of user/group datasets
    - Lifetime of datasets on SCRATCHDISK
    - Dataset deletion from 'aborted' or 'obsolete' tasks (central or group production)
    - Central deletion policy on DDM sites

``Dataset Container commands``
------------------------------
    - create a Dataset Container and include datasets
    - list the locations of a container
    - Remove datasets from a Dataset Container
    - List datasets in a Dataset Container
    - Erase a container
    - Commands to manipulate files in Dataset Containers
    - FAQ
        - 'Freezing' a container
        - Naming convention
        - Container of containers

``Advanced uses``
-----------------
    - What to do after my distributed analysis jobs create a dataset?
    - replicate a dataset to another DDM site
    - check if a file is corrupted
    - know the size of the dataset
    - delete a dataset replica from a site - delete a dataset from DDM catalog
    - Remove files from a dataset
    - Create a dataset from files already in other datasets
    - Verify local files with registered attributes
    - more advanced uses

``Known problems``
------------------
    - Dataset complete in siteA but dq2-ls -f provides no physical files

``Links to external applications creating datasets``
----------------------------------------------------
    - Group production through Production system
