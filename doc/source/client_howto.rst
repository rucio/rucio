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

``todolist``
------------

.. todolist::


``Introduction``
----------------
The main command line interface is ``rucio``. Type ``rucio`` without arguments to get a list of possible sub-commands. A ``rucio-admin`` tool also exists which is used for administrative purposes. This tool is not covered here.

The recommended set up is to use ATLAS Local Root Base. ``localSetupDQ2Clients`` also sets up the Rucio clients.


``Rucio concepts``
------------------

``DIDs``
--------
Dataset identifiers (DIDs) are the core objects in Rucio and are labelled with a unique ``scope:name`` pair. They may be files, datasets or containers. Many Rucio commands ask for a DID and can accept files, datasets or containers.

``Accounts``
------------

Your identity in Rucio is the Rucio account. When joining the ATLAS VO you must pick a nickname which is the same as your CERN login account - this is also your default Rucio account. When using the recommended set up above the account is set automatically and you do not need to do anything further. Under special circumstances you may need to use another Rucio account and it can be set with the ``RUCIO_ACCOUNT`` environment variable.

``Scopes``
----------

Scopes are a new concept in Rucio and are a way of partitioning the dataset and file namespace. Every DID has a unique scope and a name and the Rucio clients always display this as ``scope:name``. When a command requires a DID argument it must be the full DID with ``scope:name``. With the default Rucio account you may only create new DIDs in your own scope, ``user.<RUCIO_ACCOUNT>``. Only special admin users can create DIDs in other scopes.

``RSE (Rucio Storage Element)``
-------------------------------
A Rucio Storage Element is a site or part of the site that allows to store datasets and files in. There are several types of RSEs. The most important are DATADISK, SCRATCHDISK, and LOCALGROUPDISK.

``Permissions``
---------------
As a regular user you are only permitted to upload data directly to SCRATCHDISK sites or at your LOCALGROUPDISK. SCRATCHDISK is also where the outputs of your jobs normally go. Data on SCRATCHDISK has a lifetime of 15 days. The lifetime of the data on LOCALGROUPDISKs can be infinite.


    - Datasets and files
     - Datasets
      - A dataset is a logical entity with an arbitrary name that must follow the naming convention.
      - A dataset consists of logically referencable, grid-enabled files; and depending on the state of the dataset it may be replicated to multiple sites.
      - Datasets can be open or closed. If it is open, then new files can be added at any time. If it is closed, no new files can be opened anymore.
     - Files
      - A file is a physical entity with an arbitrary name that exists within Rucio. Together with the scope, it forms a unique Data Identifier.
      - Files are immutable, once they get registered to Rucio.
      - POOL files (files named as '*.pool.root.*') should contain its own unique identifier (GUID) in the file itself.
      - Files have an adler32 checksum or md5 checksum stored in Rucio.
      - Files have their size stored in the DQ2 catalog.
      - Files have additional metadata stored in the Rucio catalog.
    - Dataset Containers
     - Dataset containers are logical objects which contain one or many dataset (datasets contain files). They have been introduced to manipulate group of datasets. The production system gathers in a container the datasets with a common physics content. The users just have to deal with the container. For example, MC containers contain the files belonging to the tid datasets (containing _tidxxxx with xxxx as task number).
     - Previously, in DQ2, the convention is that containers finish with a /. This is not the case anymore in Rucio.
     - Previously, in DQ2, it was not possible to make containers of containers. With Rucio this is possible.
     - Dataset Containers can be open or closed.
      - Open : Datasets can be added at any time.
      - Closed : No more datasets can be added. Re-opening container is not possible.
     - Replica Locations
      - Dataset containers have no replicas, and thus no locations.
      - The replica locations of the contained datasets define where the data of a container are available. The contained datasets might spread over multiple grid sites, or even over multiple clouds.
      - Rules on containers will be made at the time of execution. If the container is modified later, the rule will be automatically reevaluated.
    - Physics Containers

      See `Physics Containers <https://twiki.cern.ch/twiki/bin/view/AtlasProtected/PhysicsContainers>`_.

    - Replicas

      Replicas are the instances of datasets (or files) that you access.
      A dataset can be distributed among sites (see below),
      thus replicas. In DDM, we do not distinguish the 'original' and 'copies'; a dataset is a registered entry in the DDM catalog, 
      and a replica is a physical entity that you use in your jobs.

        * A dataset replica contains physical files of the dataset, but not necessarily all of them.
        * A replica has a location (a DDM site name; see below)
        * When a replica has all the files of the dataset, it is "complete".
        * When a replica has only a part of the files of the dataset, it is marked as "incomplete". This indicate either;

          * the dataset is not frozen
          * its replication is on-going
          * there was a problem in its replication


        The files are stored at a storage element in a hierarchical namespace. The classic naming conventions stores files in a path derived from the name of the dataset::

          srm://atlassrm-fzk.gridka.de/pnfs/gridka.de/atlas/atlasdatatape/data12_8TeV/DESDM_TRACK/r4487_p1476/data12_8TeV.00214651.physics_HadDelayed.merge.DESDM_TRACK.r4487_p1476_tid01254244_00/DESDM_TRACK.01254244._000001.pool.root.14

        The new (Rucio) naming convention uses more random distribution of files in directories (the same file from the same dataset but belonging to a replica at a different site)::

          srm://ccsrm.in2p3.fr/pnfs/in2p3.fr/data/atlas/atlasdatadisk/rucio/data12_8TeV/9f/3b/DESDM_TRACK.01254244._000001.pool.root.14

        More details about Rucio naming convention (motivation, pros and cons) were presented at `ATLAS weekly <https://indico.cern.ch/contributionDisplay.py?confId=156444&contribId=2>`_ and is described on `DDMRucioPhysicalFileName <https://twiki.cern.ch/twiki/bin/view/AtlasComputing/DDMRucioPhysicalFileName>`_.

    - RSEs, mass storage systems and SRM
        DDM sites (RSEs)

        - A site is a managed logical entity, described in TiersOfATLAS
        - A site is serving datasets.
        - A site has one or more mass storage systems, which store the constituent replicated files of datasets.

        Datasets in a DDM site

        - A dataset is considered locally replicated to a site, if there are files in the mass storage system of the site.
        - A dataset is considered complete at a site, once all constituent files are replicated there; otherwise incomplete.

        Accessing datasets in a DDM site

        - At the contrary as in dq2- client, there is no default RSE in rucio to search for local replicas. You will always need to specify the RSE.
    - When to use rucio download or rules
     - Both rucio download and Rucio rules will access ONLY files registered in Rucio.
     - rucio download creates "local" copies of files, which will not be known to DDM and will not be accessible with rucio commands. The Grid/Rucio informations of the files will not be kept in the local files. If you plan to publish these data on the Grid later from the target storage, add a rule.
     - Rucio rules will copy all the files belonging to the dataset to a storage known by Rucio. The files at the destination will be registered to Rucio and accessible by rucio commands.
    - Few informations about rules
     - Rucio will try to enforce the minimum placement, and thus transfers, that is necessary to satisfy all rules, over all ATLAS users.
     - Rules where such transfers are impossible will be marked stuck.
     - Rules where transfers repeatedly fail will be marked stuck.
     - The status of rules can be monitored on the Rucio UI https://rucio-ui.cern.ch/
      1. Select "Monitoring" in the title bar.
      2. Select "Subscription & Rules" to get an overview.
      3. From there, you can navigate through all available rules, and see their status and progress.


``Installing/Initializing Rucio commands``
----------------------------------------
Start with a clean environment
(Some GRID or python environment might screw up the setups.)
::
    $ export ATLAS_LOCAL_ROOT_BASE=/cvmfs/atlas.cern.ch/repo/ATLASLocalRootBase
    $ source ${ATLAS_LOCAL_ROOT_BASE}/user/atlasLocalSetup.sh
    $ localSetupEmi
    $ localSetupDQ2Clients
    $ voms-proxy-init -voms atlas




    $ setupATLAS
Type localSetupAGIS to setup AGIS
Type localSetupDQ2Wrappers to setup DQ2Wrappers
Type localSetupRucioClients to setup rucio-clients
Type localSetupSFT to setup SFT packages

``User Identity``
-----------------
Is possible to get information about the current account the users is using with the following command:
::
    jbogadog@lxplus0157:~$ rucio whoami
    status  : ACTIVE
    account : jbogadog
    account_type : USER
    created_at : 2014-08-25T18:19:42
    suspended_at : None
    updated_at : 2014-08-25T18:19:42
    deleted_at : None
    email   : None

This account will use the user certificate for authentication automatically. The user DN can be mapped to different accounts (meaning, some users can have several identities associated to his/her DN) and is possible to change the account that the users is using setting the environment variable RUCIO_ACCOUNT. However, if your certificate is not mapped to the account you will receive an error.
::
    jbogadog@lxplus0157:~$ RUCIO_ACCOUNT=root
    jbogadog@lxplus0157:~$ rucio whoami
    Traceback (most recent call last):

    rucio.common.exception.CannotAuthenticate: Cannot authenticate.
    Details: Cannot authenticate to account root with given credentials

``Querying``
------------
``List all DDM sites``
All RSEs in alphabetical order can be listed with list-rses::
    $> rucio list-rses
    AGLT2_CALIBDISK
    AGLT2_DATADISK
    AGLT2_LOCALGROUPDISK
    AGLT2_PERF-MUONS
    AGLT2_PHYS-HIGGS
    AGLT2_PHYS-SM
    AGLT2_PRODDISK
    AGLT2_SCRATCHDISK
    AGLT2_USERDISK
    AM-04-YERPHI_LOCALGROUPDISK

To use an RSE Expression to filter the results the option --expression <expression> can be used. See :doc:`replication_rules_examples` for more information.

``Scopes``
----------
List all scopes in Rucio
    $> rucio list-scopes
    ...
    user.vfilimon
    user.vgallo
    user.vgaronne
    user.vgiangio
    user.vgjika
    ...
    data13
    data13_1beam
    data13_2p76TeV
    data13_8TeV
    data13_calib
    data13_calocomm
    data13_comm
    data13_cos
    ...
    group.det-muon
    group.det-slhc
    group.det-tile
    group.perf-egamma
    group.perf-flavtag
    ...

User scopes always have the prefix ‘user.’ followed by the account name.


``Find a dataset``
-----------------
List all the datasets and containers for a scope
::
    $> rucio list-dids data13_hip
or
::
    $> rucio list-dids data13_hip:

and also
::
    $> rucio list-dids data13_hip:*

Search by pattern:
::
    $> rucio list-dids mc12_14TeV:mc12_14TeV.167817.Sherpa_CT10_ZtautauMassiveCBPt140_280_CVetoBVeto.merge.log.e2445_p1614_tid01596380_00*
    mc12_14TeV:mc12_14TeV.167817.Sherpa_CT10_ZtautauMassiveCBPt140_280_CVetoBVeto.merge.log.e2445_p1614_tid01596380_00 [COLLECTION]

Search by meta-data:
::
    $> rucio list-dids mc12_14TeV:*  --filter datatype=AOD | head
    mc12_14TeV:mc12_14TeV.159000.ParticleGenerator_nu_E50.recon.AOD.e1564_s1762_s1777_r6030_tid04659335_00_sub0202463592 [COLLECTION]
    mc12_14TeV:mc12_14TeV.147807.PowhegPythia8_AU2CT10_Zmumu.recon.AOD.e1564_s1762_s1777_r6030_tid04659337_00_sub0202481445 [COLLECTION]
    mc12_14TeV:mc12_14TeV.147807.PowhegPythia8_AU2CT10_Zmumu.recon.AOD.e1564_s1762_s1777_r6025_tid04658484_00_sub0202361579 [COLLECTION]
    mc12_14TeV:mc12_14TeV.107218.ParticleGenerator_mu_Pt20.recon.AOD.e2023_s1762_s1777_r6028_tid04659431_00_sub0202438551 [COLLECTION]
    mc12_14TeV:mc12_14TeV.159072.ParticleGenerator_mu_Pt100.recon.AOD.e2023_s1762_s1777_r6028_tid04659428_00_sub0202439480 [COLLECTION]

Search by type:
You can filter the results for `file`, `dataset`, `container`, `collection` (dataset or container) or `all`.
::
    $> rucio list-dids mc12_14TeV:*  --filter type=dataset | head
    mc12_14TeV:mc12_14TeV.159000.ParticleGenerator_nu_E50.recon.AOD.e1564_s1762_s1777_r6030_tid04659335_00_sub0202463592 [DATASET]
    mc12_14TeV:mc12_14TeV.147807.PowhegPythia8_AU2CT10_Zmumu.recon.AOD.e1564_s1762_s1777_r6030_tid04659337_00_sub0202481445 [DATASET]
    mc12_14TeV:mc12_14TeV.147807.PowhegPythia8_AU2CT10_Zmumu.recon.AOD.e1564_s1762_s1777_r6025_tid04658484_00_sub0202361579 [DATASET]
    mc12_14TeV:mc12_14TeV.107218.ParticleGenerator_mu_Pt20.recon.AOD.e2023_s1762_s1777_r6028_tid04659431_00_sub0202438551 [DATASET]
    mc12_14TeV:mc12_14TeV.159072.ParticleGenerator_mu_Pt100.recon.AOD.e2023_s1762_s1777_r6028_tid04659428_00_sub0202439480 [DATASET]



If the results are not as you spect, you should escape the wildcard in order to bypass globbing:
::
    $> rucio list-dids 'scope:my_dataset*'

Otherwise you will not find anything with zsh or you may find only a single dataset if you have a directory with the dataset name in bash.

``List the files in a dataset``
-------------------------------
The content of a dataset can be listed with list-files. Mandatory parameters are <scope>:<name>.
::
    $> rucio list-files mc12_14TeV:mc12_14TeV.167817.Sherpa_CT10_ZtautauMassiveCBPt140_280_CVetoBVeto.merge.log.e2445_p1614_tid01596380_00
    mc12_14TeV:log.01596380._000026.job.log.tgz.1    700680    52bb0e00    AC39C3DE6B8A4BD3B27BC77DDC26AE7A
    mc12_14TeV:log.01596380._000050.job.log.tgz.1    538783    14979047    8C511D9D63C048648BC7EE2194793654
    mc12_14TeV:log.01596380._000082.job.log.tgz.1    539690    8c4c69a7    AA6E75F579564128B7FE1079FE9EAD9E
    mc12_14TeV:log.01596380._000091.job.log.tgz.1    548126    7fd2e951    D4C051251A1F4022B9B17D30084514B3
    mc12_14TeV:log.01596380._000130.job.log.tgz.1    537886    ee702106    A84676B20E964DB58C23970ED8919372
    mc12_14TeV:log.01596380._000131.job.log.tgz.1    540323    e8a222f8    A867E909F4BB4C0D9A67123F44B1224E
    mc12_14TeV:log.01596380._000134.job.log.tgz.1    546319    f0d257e1    983048962F3C4179978630661848F484
    mc12_14TeV:log.01596380._000142.job.log.tgz.1    525845    347c45cf    252F61AC8D9447919F9AD12A995EF6B6
    mc12_14TeV:log.01596380._000156.job.log.tgz.1    702544    fb020a40    D1B8A2579DBD45FDB8BDF8F8DACBB509
    mc12_14TeV:log.01596380._000170.job.log.tgz.1    530714    37d44ab9    325F5C1F7B84445C94DD824F5AC7EE9B


This command can also be used to list the content of a container.

Also, yo can use `rucio list-dids` command. If you specify one dataset or container, the command will list it's content.
::
    $> rucio list-files mc12_14TeV:mc12_14TeV.167817.Sherpa_CT10_ZtautauMassiveCBPt140_280_CVetoBVeto.merge.log.e2445_p1614_tid01596380_00
    |    |- mc12_14TeV:log.01596380._000026.job.log.tgz.1    [FILE]
    |    |- mc12_14TeV:log.01596380._000050.job.log.tgz.1    [FILE]
    |    |- mc12_14TeV:log.01596380._000082.job.log.tgz.1    [FILE]
    |    |- mc12_14TeV:log.01596380._000091.job.log.tgz.1    [FILE]
    |    |- mc12_14TeV:log.01596380._000130.job.log.tgz.1    [FILE]
    |    |- mc12_14TeV:log.01596380._000131.job.log.tgz.1    [FILE]
    |    |- mc12_14TeV:log.01596380._000134.job.log.tgz.1    [FILE]
    |    |- mc12_14TeV:log.01596380._000142.job.log.tgz.1    [FILE]
    |    |- mc12_14TeV:log.01596380._000156.job.log.tgz.1    [FILE]
    |    |- mc12_14TeV:log.01596380._000170.job.log.tgz.1    [FILE]



``List the replica locations of a dataset``
-------------------------------------------
It can be done with the `rucio list-dataset-replicas <scope>:<name>`.
::
        $> rucio list-dataset-replicas mc12_14TeV:mc12_14TeV.167817.Sherpa_CT10_ZtautauMassiveCBPt140_280_CVetoBVeto.merge.log.e2445_p1614_tid01596380_00
        RSE                                      Found  Total
        ------------------------------------------------------
        IN2P3-CC_DATADISK                            12     12

It returns all the locations of the dataset, the number of files on each of these locations and the total number of files. If the scope and name belongs to a file, then the output will be empty.

``List the datasets at a site``
-------------------------------
    See dumps

``List the replicas of file``
-----------------------------
The command `rucio list-file-replicas <scope>:<filename>` will show the physical location of the file.
::
    $> rucio list-file-replicas mc12_14TeV:ESD.01332706._000181.pool.root.1
    Scope   Name                    Filesize        adler32 Replicas
    mc12_14TeV      ESD.01332706._000181.pool.root.1        1175213672      3f51b03d        CERN-PROD_DATADISK      :       gsiftp://eosatlassftp.cern.ch:2811/eos/atlas/atlasdatadisk/rucio/mc12_14TeV/58/4f/ESD.01332706._000181.pool.root.1

It's possible to filter the results by site with the argument --rse <RSE-NAME>

``List the datasets where a particular file belongs``
-----------------------------------------------------
The command `rucio list-parent-dids <scope>:<name>` will show the datasets containing the file.
::
    $> rucio list-parent-dids mc12_14TeV:HITS.04640638._001016.pool.root.1
    mc12_14TeV:mc12_14TeV.119996.Pythia8_A2MSTW2008LO_minbias_inelastic_high.merge.HITS.e1133_s2079_s1964_tid04640638_00 [DATASET]
    mc12_14TeV:mc12_14TeV.119996.Pythia8_A2MSTW2008LO_minbias_inelastic_high.merge.HITS.e1133_s2079_s1964_tid04640638_00_sub0201868877 [DATASET]

``Retrieving data``
-------------------
``Download a full dataset``
---------------------------
It can be done with `rucio download <scope>:<name>`
::
    $> rucio download mc14_13TeV:mc14_13TeV.169153.PowhegPythia8_AU2CT10_VBFH600NWA_WWlepnuqq.recon.log.e3292_s1982_s2008_r5787_tid04606738_00_sub0201586236
    2015-02-04 13:49:17,867 INFO [Starting download for mc14_13TeV:mc14_13TeV.169153.PowhegPythia8_AU2CT10_VBFH600NWA_WWlepnuqq.recon.log.e3292_s1982_s2008_r5787_tid04606738_00_sub0201586236]
    [++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++]    100/100
    File downloaded. Will be validated
    File validated
    2015-02-04 13:49:18,554 INFO [File mc14_13TeV:log.04606738._000047.job.log.tgz.1 successfully downloaded from FZK-LCG2_DATADISK]
    [++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++]    100/100
    File downloaded. Will be validated
    File validated
    2015-02-04 13:49:18,923 INFO [File mc14_13TeV:log.04606738._000048.job.log.tgz.1 successfully downloaded from FZK-LCG2_DATADISK]
    [++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++]    100/100
    File downloaded. Will be validated
    File validated
    2015-02-04 13:49:19,325 INFO [File mc14_13TeV:log.04606738._000049.job.log.tgz.1 successfully downloaded from FZK-LCG2_DATADISK]
    2015-02-04 13:49:19,325 INFO [Download operation for mc14_13TeV:mc14_13TeV.169153.PowhegPythia8_AU2CT10_VBFH600NWA_WWlepnuqq.recon.log.e3292_s1982_s2008_r5787_tid04606738_00_sub0201586236 done]
    ----------------------------------
    Download summary
    ----------------------------------------
    DID mc14_13TeV:mc14_13TeV.169153.PowhegPythia8_AU2CT10_VBFH600NWA_WWlepnuqq.recon.log.e3292_s1982_s2008_r5787_tid04606738_00_sub0201586236
    Downloaded files :                            3
    Files already found locally :                 0
    Files that cannot be downloaded :             0

The files are copied locally into a directory <scope>

The download command support --rse <RSE-NAME>, which allows to download a dataset from an spefic site and --protocol <PROTOCOL> to use a specific transfer protocol. Note that however, the dataset could not be available to download in a particular site or the protocol could not be supported by the rse.


``Download specific files from a dataset``
------------------------------------------
This operation is still not supported by rucio, but will be available soon.

``Download a sample of n random files from a dataset``
------------------------------------------------------
This operation is still not supported by rucio, but will be available soon.

``Download with datasets/files given in an inputfile``
------------------------------------------------------
Not supported by Rucio, but similar functionality can be achieved by
::
  $> rucio download `cat input.txt`

where the input file (``input.txt``) contains one DID per line, e.g.
::
  user.dcameron:test66
  user.dcameron:test8

``Download datasets from tape``
-------------------------------
Users cannot download files from DDM sites associated to TAPE (xxx_MCTAPE and xxx_DATATAPE, CERN-PROD_TZERO and CERN-PROD_DAQ). To access data from TAPE, one should request a replication of the dataset to DISK storage through DDM request.
If you need the whole dataset, choose the DATADISK of the same site as the destination.

``Creating data``
-----------------
There 2 ways to create data on the Grid.
The first one is by using Panda. The Panda jobs will create output data that are copied to some temporary areas (they can be identified by their name that ends with SCRATCHDISK, e.g. FZK-LCG2_SCRATCHDISK). Rucio ensures that the data are kept on this area for 2 weeks, but after that period they can disappear are anytime.

The second method is to upload files with Rucio. The typical use case is that you produced locally some files, but want to share it with some other persons, or you want to run over these files using Distributed Analysis tools like Panda. For this you need to upload the files into a dataset on some Rucio Storage element (RSE). It can be done with rucio upload. Rucio will take care of registering the files into the rucio catalog and to physically upload the files on the Rucio Storage Element you choose. Once the dataset is successfully uploaded, you can use all the rucio features on it (transfer, deletion...).

``Which name should I give to my files and dataset``
----------------------------------------------------
If you create files into your own scope which is user.<account>, there is no restriction. You can give whatever name for your Data IDentifier (i.e. files/datasets/containers). But be carefull : once a name has been used for a Data IDentifier, it cannot be reused anymore even if you delete the original!
For official data, a specific nomanclature is used.

``Where my dataset/files will be stored with rucio upload ?``
-------------------------------------------------------------
You can decide to upload your datasets into 2 different storage areas :
    - The first one is a temporary area, which is any SCRATCHDISK. The datasets uploaded there will be kept for 2 weeks, but after that period, they can disappear at anytime.
    - The second place is a permanent area (the so called LOCALGROUPDISK). This areas are dedicated to local users and are managed by the cloud squads. Permissions are set according to the user nationality and/or institut. The retention policy and the quota on these endpoints are defined by the cloud squads.

``Where my dataset/files should be finally stored ?``
-----------------------------------------------------
    - Long term storage for user datasets

      On the Grid managed by DDM, the final destination for user datasets should be LOCALGROUPDISK. This area is not pledged, its size is defined by the site and its access is restricted to local users (technically to users from the same country). Datasets in this area are deleted only if the dataset was produced centrally (mc* or data*) and the associated task is declared aborted (usually meaning that the task was bugged). To send your dataset there, request the replication by setting a rule. There is no such storage at CERN. Outside the Grid or for Grid storage not declared in DDM, the storage managment is done by the site with its own tools. Currently, files can be replicated to this area through ``dq2-get`` / ``rucio download``. There is non-Grid storage at CERN with quotas per user (to be documented).

    - Long term storage for group datasets

      The group datasets are user (possible that this user is working for a group) datasets replicated in group areas. Only the data manager of the group can request the replication of datasets.

    - Short term storage

      The dataset can be stored or replicated in SCRATCHDISK. SCRATCHDISK is the place for analysis output (except in US where _USERDISK is the place for pathena output) or ``dq2-put`` / ``rucio upload``. The deletion policy for datasets in SCRATCHDISK is defined. Using LOCALGROUPDISK as the ouput location for analysis jobs is not recommended by the DDM team.

    - Exceptions in US

      Because of temporary limitations in xrootd sites (SLACXRD and SWT2_SPB), the DDM sites SCRATCHDISK and LOCALGROUPDISK could not be created. Users are asked to send their datasets to GROUPDISK.

``Create a dataset from files on my local disk``
------------------------------------------------
To upload local files to Rucio Catalog, the rucio upload command must be used.
::
    $> rucio upload --rse MY_SCRATCHDISK file1 file2 file3

Rucio will try to guess the scope for the files based on the user account being used. If this fails or a different scope is needed, it can be specified by the --scope argument.
::
    $> rucio upload --rse MY_SCRATCHDISK file1 file2 file3 --scope user.jbogadog

Rucio also support upload files within a directory. This command however is not recursive and only the files in the directory will be added.  If the only file in “directory” is  “my_file”, the following command will upload the file under user.account:my_file.
::
    $> rucio upload --rse MY_SCRATCHDISK directory/

Also, if a scope:name is specified, it will be interpreted as a dataset name. All the files to upload will be automatically attached to this dataset. If the dataset exist already, the files will be added, if not, the dataset will be created first.
::
    $> rucio upload --rse MY_SCRATCHDISK user.name:mydataset file1 file2 file3 directory/

Again, you can specify a different scope for the files with --scope
::
    $> rucio upload --rse MY_SCRATCHDISK  user.name:mydataset file1 file2 file3 directory/ --scope user.other_name

`Important note`: The names of files and datasets must be unique for a given scope. Otherwise, the rucio command will end in an error. Also the name of the files must be different that the one given for the dataset.

``Create a dataset from files already in other datasets``
---------------------------------------------------------
To create a dataset from files in other datasets, you can follow these steps:

 Step 0: List files in the source datasets::

  $> rucio list-dids  user.wguan:user.wguan.test.upload
  |    |- user.wguan:setup_dev.sh [FILE]
  |    |- user.wguan:setup_dq2.sh [FILE]
  |    |- user.wguan:testMulProcess.py [FILE]
  |    |- user.wguan:testcatalog.py [FILE]

 Step 1: Add destination dataset::

  $> rucio add-dataset user.wguan:user.wguan.test.upload1
  Added user.wguan:user.wguan.test.upload1

 Step 2: Add files to destination dataset::

  $> rucio add-files-to-dataset --to user.wguan:user.wguan.test.upload1 user.wguan:setup_dev.sh user.wguan:setup_dq2.sh

 Step 3: List the destination dataset to check the result::

  $> rucio list-dids  user.wguan:user.wguan.test.upload1
  |    |- user.wguan:setup_dev.sh [FILE]
  |    |- user.wguan:setup_dq2.sh [FILE]

Add files to a dataset::

    rucio attach <DATASET> <FILE_1>  <FILE_2> ...  <FILE_n>

``What to do after creating a dataset?``
----------------------------------------
 - You should "close" the dataset. If the dataset is not closed, matching rules will have to constantly reevaluate your dataset and possibly generate transfers.
 - If you want to add another set of files after a while, think about using containers.
 - If you want to keep the possibility to add files to this dataset, do not close the dataset.
 - By default, user datasets are created on SCRATCHDISK at the site where the jobs run.
 - All the datasets on SCRATCHDISK are to be deleted after a certain period (minimum 7 days). See the section Lifetime of data on SCRATCHDISK.
 - To retrieve your output files, you should either
  - Set a rule. The output files will stay as a dataset on Grid.
  - Download onto your local disk using `dq2-get` \ `rucio download`. The output files will not be available via DDM after the dataset on the SCRATCHDISK is deleted. If the files are Athena files (POOL files), you will not be able to re-register the files. If you see a possibility to use them on Grid, you should think about setting rules.
 - After retrieving the data from the SCRATCHDISK, you are encouraged to request early deletion of the original replicas in SCRATCHDISK.

``Close a dataset``
-------------------
To close a dataset the command rucio close has to be used::
    $> rucio close user.barisits:test-dataset
    user.barisits:test-dataset has been closed.

``Re-open a dataset``
---------------------
This is only possible for privileged accounts using the Rucio Python clients.

``Freeze a dataset``
--------------------
Freezing a dataset is not possible in Rucio. Closing the dataset is sufficient.

