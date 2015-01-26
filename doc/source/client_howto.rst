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
    - List the files in a dataset
The content of a dataset can be listed with list-files. Mandatory parameters are <scope>:<name>.::

    $> rucio list-files mc12_14TeV:mc12_14TeV.167817.Sherpa_CT10_ZtautauMassiveCBPt140_280_CVetoBVeto.merge.log.e2445_p1614_tid01596380_00
    mc12_14TeV:log.01596380._000026.job.log.tgz.1
    mc12_14TeV:log.01596380._000050.job.log.tgz.1
    mc12_14TeV:log.01596380._000082.job.log.tgz.1
    mc12_14TeV:log.01596380._000091.job.log.tgz.1
    mc12_14TeV:log.01596380._000130.job.log.tgz.1
    mc12_14TeV:log.01596380._000131.job.log.tgz.1
    mc12_14TeV:log.01596380._000134.job.log.tgz.1
    mc12_14TeV:log.01596380._000142.job.log.tgz.1
    mc12_14TeV:log.01596380._000156.job.log.tgz.1
    mc12_14TeV:log.01596380._000170.job.log.tgz.1
    mc12_14TeV:log.01596380._000192.job.log.tgz.1
    mc12_14TeV:log.01596380._000215.job.log.tgz.1

This command can also be used to list the content of a container.

    - List the replica locations of a dataset
It can be done with the list-replicas command and option --list_collections. Mandatory parameters are <scope>:<name>.::
    $> rucio list-replicas --list_collections mc12_14TeV:mc12_14TeV.167817.Sherpa_CT10_ZtautauMassiveCBPt140_280_CVetoBVeto.merge.log.e2445_p1614_tid01596380_00
    RSE                                      Found  Total
    ------------------------------------------------------
    IN2P3-CC_DATADISK                            12     12

It returns all the locations of the dataset, the number of files on each of these locations and the total number of files.

    - List the datasets at a site
        Cedric. CLI not implemented yet
    - List the files in a dataset existing at a site
        Cedric. CLI not implemented yet
    - List the physical filenames in a dataset
It can be done with the list-replicas command. Mandatory parameters are <scope>:<name>.::

    $> rucio list-replicas mc12_14TeV:mc12_14TeV.167817.Sherpa_CT10_ZtautauMassiveCBPt140_280_CVetoBVeto.merge.log.e2445_p1614_tid01596380_00
    Scope   Name                    Filesize        adler32 Replicas
    mc12_14TeV      log.01596380._000026.job.log.tgz.1      700680  52bb0e00        IN2P3-CC_DATADISK       :       https://ccdcatli013.in2p3.fr:2880/atlasdatadisk/rucio/mc12_14TeV/5b/d9/log.01596380._000026.job.log.tgz.1
    mc12_14TeV      log.01596380._000050.job.log.tgz.1      538783  14979047        IN2P3-CC_DATADISK       :       https://ccdcatli013.in2p3.fr:2880/atlasdatadisk/rucio/mc12_14TeV/13/94/log.01596380._000050.job.log.tgz.1
    mc12_14TeV      log.01596380._000082.job.log.tgz.1      539690  8c4c69a7        IN2P3-CC_DATADISK       :       https://ccdcatli013.in2p3.fr:2880/atlasdatadisk/rucio/mc12_14TeV/ea/7d/log.01596380._000082.job.log.tgz.1
    mc12_14TeV      log.01596380._000091.job.log.tgz.1      548126  7fd2e951        IN2P3-CC_DATADISK       :       https://ccdcatli013.in2p3.fr:2880/atlasdatadisk/rucio/mc12_14TeV/22/d0/log.01596380._000091.job.log.tgz.1
    mc12_14TeV      log.01596380._000130.job.log.tgz.1      537886  ee702106        IN2P3-CC_DATADISK       :       https://ccdcatli013.in2p3.fr:2880/atlasdatadisk/rucio/mc12_14TeV/0c/54/log.01596380._000130.job.log.tgz.1
    mc12_14TeV      log.01596380._000131.job.log.tgz.1      540323  e8a222f8        IN2P3-CC_DATADISK       :       https://ccdcatli013.in2p3.fr:2880/atlasdatadisk/rucio/mc12_14TeV/4b/93/log.01596380._000131.job.log.tgz.1
    mc12_14TeV      log.01596380._000134.job.log.tgz.1      546319  f0d257e1        IN2P3-CC_DATADISK       :       https://ccdcatli013.in2p3.fr:2880/atlasdatadisk/rucio/mc12_14TeV/8e/5c/log.01596380._000134.job.log.tgz.1
    mc12_14TeV      log.01596380._000142.job.log.tgz.1      525845  347c45cf        IN2P3-CC_DATADISK       :       https://ccdcatli013.in2p3.fr:2880/atlasdatadisk/rucio/mc12_14TeV/c4/0b/log.01596380._000142.job.log.tgz.1
    mc12_14TeV      log.01596380._000156.job.log.tgz.1      702544  fb020a40        IN2P3-CC_DATADISK       :       https://ccdcatli013.in2p3.fr:2880/atlasdatadisk/rucio/mc12_14TeV/78/e9/log.01596380._000156.job.log.tgz.1
    mc12_14TeV      log.01596380._000170.job.log.tgz.1      530714  37d44ab9        IN2P3-CC_DATADISK       :       https://ccdcatli013.in2p3.fr:2880/atlasdatadisk/rucio/mc12_14TeV/50/77/log.01596380._000170.job.log.tgz.1
    mc12_14TeV      log.01596380._000192.job.log.tgz.1      506128  5d47209c        IN2P3-CC_DATADISK       :       https://ccdcatli013.in2p3.fr:2880/atlasdatadisk/rucio/mc12_14TeV/47/dd/log.01596380._000192.job.log.tgz.1
    mc12_14TeV      log.01596380._000215.job.log.tgz.1      534603  04de7f9f        IN2P3-CC_DATADISK       :       https://ccdcatli013.in2p3.fr:2880/atlasdatadisk/rucio/mc12_14TeV/2c/b7/log.01596380._000215.job.log.tgz.1

The command return the TURLs (Transport URLs) in the protocol that is defined as primary at the site. To obtain the TURLs for a given protocol, the option --protocols can be used as shown below.::
    rucio list-replicas --protocols srm mc12_14TeV:mc12_14TeV.167817.Sherpa_CT10_ZtautauMassiveCBPt140_280_CVetoBVeto.merge.log.e2445_p1614_tid01596380_00
    Scope   Name                    Filesize        adler32 Replicas
    mc12_14TeV      log.01596380._000026.job.log.tgz.1      700680  52bb0e00        IN2P3-CC_DATADISK       :       srm://ccsrm.in2p3.fr:8443/srm/managerv2?SFN=/pnfs/in2p3.fr/data/atlas/atlasdatadisk/rucio/mc12_14TeV/5b/d9/log.01596380._000026.job.log.tgz.1
    mc12_14TeV      log.01596380._000050.job.log.tgz.1      538783  14979047        IN2P3-CC_DATADISK       :       srm://ccsrm.in2p3.fr:8443/srm/managerv2?SFN=/pnfs/in2p3.fr/data/atlas/atlasdatadisk/rucio/mc12_14TeV/13/94/log.01596380._000050.job.log.tgz.1
    mc12_14TeV      log.01596380._000082.job.log.tgz.1      539690  8c4c69a7        IN2P3-CC_DATADISK       :       srm://ccsrm.in2p3.fr:8443/srm/managerv2?SFN=/pnfs/in2p3.fr/data/atlas/atlasdatadisk/rucio/mc12_14TeV/ea/7d/log.01596380._000082.job.log.tgz.1
    mc12_14TeV      log.01596380._000091.job.log.tgz.1      548126  7fd2e951        IN2P3-CC_DATADISK       :       srm://ccsrm.in2p3.fr:8443/srm/managerv2?SFN=/pnfs/in2p3.fr/data/atlas/atlasdatadisk/rucio/mc12_14TeV/22/d0/log.01596380._000091.job.log.tgz.1
    mc12_14TeV      log.01596380._000130.job.log.tgz.1      537886  ee702106        IN2P3-CC_DATADISK       :       srm://ccsrm.in2p3.fr:8443/srm/managerv2?SFN=/pnfs/in2p3.fr/data/atlas/atlasdatadisk/rucio/mc12_14TeV/0c/54/log.01596380._000130.job.log.tgz.1
    mc12_14TeV      log.01596380._000131.job.log.tgz.1      540323  e8a222f8        IN2P3-CC_DATADISK       :       srm://ccsrm.in2p3.fr:8443/srm/managerv2?SFN=/pnfs/in2p3.fr/data/atlas/atlasdatadisk/rucio/mc12_14TeV/4b/93/log.01596380._000131.job.log.tgz.1
    mc12_14TeV      log.01596380._000134.job.log.tgz.1      546319  f0d257e1        IN2P3-CC_DATADISK       :       srm://ccsrm.in2p3.fr:8443/srm/managerv2?SFN=/pnfs/in2p3.fr/data/atlas/atlasdatadisk/rucio/mc12_14TeV/8e/5c/log.01596380._000134.job.log.tgz.1
    mc12_14TeV      log.01596380._000142.job.log.tgz.1      525845  347c45cf        IN2P3-CC_DATADISK       :       srm://ccsrm.in2p3.fr:8443/srm/managerv2?SFN=/pnfs/in2p3.fr/data/atlas/atlasdatadisk/rucio/mc12_14TeV/c4/0b/log.01596380._000142.job.log.tgz.1
    mc12_14TeV      log.01596380._000156.job.log.tgz.1      702544  fb020a40        IN2P3-CC_DATADISK       :       srm://ccsrm.in2p3.fr:8443/srm/managerv2?SFN=/pnfs/in2p3.fr/data/atlas/atlasdatadisk/rucio/mc12_14TeV/78/e9/log.01596380._000156.job.log.tgz.1
    mc12_14TeV      log.01596380._000170.job.log.tgz.1      530714  37d44ab9        IN2P3-CC_DATADISK       :       srm://ccsrm.in2p3.fr:8443/srm/managerv2?SFN=/pnfs/in2p3.fr/data/atlas/atlasdatadisk/rucio/mc12_14TeV/50/77/log.01596380._000170.job.log.tgz.1
    mc12_14TeV      log.01596380._000192.job.log.tgz.1      506128  5d47209c        IN2P3-CC_DATADISK       :       srm://ccsrm.in2p3.fr:8443/srm/managerv2?SFN=/pnfs/in2p3.fr/data/atlas/atlasdatadisk/rucio/mc12_14TeV/47/dd/log.01596380._000192.job.log.tgz.1
    mc12_14TeV      log.01596380._000215.job.log.tgz.1      534603  04de7f9f        IN2P3-CC_DATADISK       :       srm://ccsrm.in2p3.fr:8443/srm/managerv2?SFN=/pnfs/in2p3.fr/data/atlas/atlasdatadisk/rucio/mc12_14TeV/2c/b7/log.01596380._000215.job.log.tgz.1

The protocols currently supported are SRM, GSIFTP, HTTPS/WebDAV, xrootd.

    - List the file paths of a dataset replica at a site
        Cedric. TBD Need a new option --rse in the CLI to only get the PFNs at a specific RSE.
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
It can be done with the download command. Mandatory parameters are <scope>:<name>, but it supports many options::
    $> rucio download user.serfon:user.serfon.test.08012015.2
    2015-01-23 09:15:23,789 INFO [Starting download for user.serfon:user.serfon.test.08012015.2]
    2015-01-23 09:15:23,790 DEBUG [Getting the list of replicas]
    2015-01-23 09:15:23,899 DEBUG [Choosing RSE]
    2015-01-23 09:15:23,999 DEBUG [Getting file user.serfon:file1.80e66841eaf248829c7a22a601e8d257 from LRZ-LMU_SCRATCHDISK]
    File downloaded. Will be validated
    File validated
    2015-01-23 09:15:26,320 INFO [File user.serfon:file1.80e66841eaf248829c7a22a601e8d257 successfully downloaded from LRZ-LMU_SCRATCHDISK]
    2015-01-23 09:15:26,321 DEBUG [Choosing RSE]
    2015-01-23 09:15:26,321 DEBUG [Getting file user.serfon:file2.80e66841eaf248829c7a22a601e8d257 from LRZ-LMU_SCRATCHDISK]
    File downloaded. Will be validated
    File validated
    2015-01-23 09:15:28,621 INFO [File user.serfon:file2.80e66841eaf248829c7a22a601e8d257 successfully downloaded from LRZ-LMU_SCRATCHDISK]
    2015-01-23 09:15:28,622 DEBUG [Choosing RSE]
    2015-01-23 09:15:28,623 DEBUG [Getting file user.serfon:file3.80e66841eaf248829c7a22a601e8d257 from LRZ-LMU_SCRATCHDISK]
    File downloaded. Will be validated
    File validated
    2015-01-23 09:15:30,934 INFO [File user.serfon:file3.80e66841eaf248829c7a22a601e8d257 successfully downloaded from LRZ-LMU_SCRATCHDISK]
    2015-01-23 09:15:30,939 INFO [Download operation for user.serfon:user.serfon.test.08012015.2 done]
    ----------------------------------
    Download summary
    DID user.serfon:user.serfon.test.08012015.2

The files are copied locally into a directory <scope>

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
There 2 ways to create data on the Grid.
- The first one is by using Panda. The Panda jobs will create output data that are copied to some temporary areas (they can be identified by their name that ends with SCRATHDISK, e.g. FZK-LCG2_SCRATCHDISK). Rucio ensures that the data are kept on this area for 2 weeks, but after that period they can disappear are anytime.
- The second method is to upload files with Rucio. The typical use case is that you produced locally some files, but want to share it with some other persons, or you want to run over these files using Distributed Analysis tools like Panda. For this you need to upload the files into a dataset on some Rucio Storage element (RSE). It can be done with rucio upload. Rucio will take care of registering the files into the rucio catalog and to physically upload the files on the Rucio Storage Element you choose. Once the dataset is successfully uploaded, you can use all the rucio features on it (transfer, deletion...). You can find below one example how to use rucio upload : 
TBD Cedric

    - Which name should I give to my files and dataset
If you create files into your own scope which is user.<account>, there is no restriction. You can give whatever name for your Data IDentifier (i.e. files/datasets/containers). But be carefull : once a name has been used for a Data IDentifier, it cannot be reused anymore even if you delete the original !
For official data, a specific nomanclature is used.
    - Where my dataset/files will be stored with rucio upload ?
You can decide to upload your datasets into 2 different storage areas :
- The first one is a temporary area, which is any SCRATCHDISK. The datasets uploaded there will be kept for 2 weeks, but after that period, they can disappear at anytime.
- The second place is a permanent area (the so called LOCALGROUPDISK). This areas are dedicated to local users and are managed by the cloud squads. Permissions are set according to the user nationality and/or institut. The retention policy and the quota on these endpoints are defined by the cloud squads. 
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
