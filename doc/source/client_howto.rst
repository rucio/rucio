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
        Ralph
    - Replicas
        Ralph
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
    - Installing Rucio commands
        - :doc:`installing_clients`
        - :doc:`installing_atlas_clients`
    - Initializing Rucio commands
     - Step 0: Start with a clean environment
         Some GRID or python environment might screw up the setups.
     - Step 1: Grid environment::

        $ export ATLAS_LOCAL_ROOT_BASE=/cvmfs/atlas.cern.ch/repo/ATLASLocalRootBase
        $ source ${ATLAS_LOCAL_ROOT_BASE}/user/atlasLocalSetup.sh
        $ localSetupEmi
        $ voms-proxy-init -voms atlas

     - Step 2: Rucio enviroment::

        $> export ATLAS_LOCAL_ROOT_BASE=/cvmfs/atlas.cern.ch/repo/ATLASLocalRootBase
        $> source ${ATLAS_LOCAL_ROOT_BASE}/user/atlasLocalSetup.sh
        $> localSetupRucioClients


``User Identity``
-----------------
``Querying``
------------
    - List all DDM sites

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

      To use an RSE Expression to filter the results the option --expression <expression> can be used.

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
The command list-datasets-site with option --rse <rse> can be used.::
        $> rucio list-datasets-site --rse LRZ-LMU_DATADISK
        data11_2p76TeV:data11_2p76TeV.00178163.physics_MinBias.merge.AOD.r4408_p1468_tid01234284_00
        data11_2p76TeV:data11_2p76TeV.00178229.physics_MinBias.merge.AOD.r4408_p1468_tid01234266_00
        data11_7TeV:data11_7TeV.00178047.physics_Standby.recon.ESD.r2603_tid495757_00
        data11_7TeV:data11_7TeV.00180124.physics_ZeroBias.merge.AOD.r2603_p659_tid497281_00
        data11_7TeV:data11_7TeV.00180212.physics_Standby.merge.AOD.r2603_p659_tid497021_00
        data11_7TeV:data11_7TeV.00180636.physics_Background.merge.AOD.r2603_p659_tid496550_00
        data11_7TeV:data11_7TeV.00180710.physics_Egamma.merge.AOD.r2603_p659_tid496573_00
        data11_7TeV:data11_7TeV.00182161.physics_Muons.merge.AOD.f379_m849
        data11_7TeV:data11_7TeV.00182424.physics_Muons.merge.AOD.f381_m861
        data11_7TeV:data11_7TeV.00182456.physics_JetTauEtmiss.merge.AOD.r2603_p659_tid496207_00
        data11_7TeV:data11_7TeV.00183045.physics_Muons.merge.AOD.r2603_p659_tid493607_00

TBD : Add --filter option

    - List the files in a dataset existing at a site
The command list-replicas with option --rse <rse> can be used.::
        rucio list-replicas  --rse BNL-OSG2_DATADISK --protocol srm mc14_13TeV:mc14_13TeV.129194.Pythia8B_AU2CTEQ6L1_bbToJpsie3e8.recon.AOD.e2743_s2044_s2008_r5988_tid04606956_00
        $> Scope   Name                    Filesize        adler32 Replicas
        mc14_13TeV      AOD.04606956._000001.pool.root.1        146285426       c140b17a        BNL-OSG2_DATADISK       :       srm://dcsrm.usatlas.bnl.gov:8443/srm/managerv2?SFN=/pnfs/usatlas.bnl.gov/BNLT0D1/rucio/mc14_13TeV/52/1d/AOD.04606956._000001.pool.root.1
        mc14_13TeV      AOD.04606956._000002.pool.root.1        194963494       d1f0a425        BNL-OSG2_DATADISK       :       srm://dcsrm.usatlas.bnl.gov:8443/srm/managerv2?SFN=/pnfs/usatlas.bnl.gov/BNLT0D1/rucio/mc14_13TeV/0b/6e/AOD.04606956._000002.pool.root.1
        mc14_13TeV      AOD.04606956._000003.pool.root.1        224301101       99f07fe4        BNL-OSG2_DATADISK       :       srm://dcsrm.usatlas.bnl.gov:8443/srm/managerv2?SFN=/pnfs/usatlas.bnl.gov/BNLT0D1/rucio/mc14_13TeV/48/a0/AOD.04606956._000003.pool.root.1
        mc14_13TeV      AOD.04606956._000004.pool.root.1        249912271       f1c1eb1f        BNL-OSG2_DATADISK       :       srm://dcsrm.usatlas.bnl.gov:8443/srm/managerv2?SFN=/pnfs/usatlas.bnl.gov/BNLT0D1/rucio/mc14_13TeV/53/44/AOD.04606956._000004.pool.root.1
        mc14_13TeV      AOD.04606956._000005.pool.root.1        280050015       9a3bdc26        BNL-OSG2_DATADISK       :       srm://dcsrm.usatlas.bnl.gov:8443/srm/managerv2?SFN=/pnfs/usatlas.bnl.gov/BNLT0D1/rucio/mc14_13TeV/75/91/AOD.04606956._000005.pool.root.1
        mc14_13TeV      AOD.04606956._000006.pool.root.1        309249992       e6bcf77f        BNL-OSG2_DATADISK       :       srm://dcsrm.usatlas.bnl.gov:8443/srm/managerv2?SFN=/pnfs/usatlas.bnl.gov/BNLT0D1/rucio/mc14_13TeV/09/e5/AOD.04606956._000006.pool.root.1
        mc14_13TeV      AOD.04606956._000077.pool.root.1        152151303       1aff742e        BNL-OSG2_DATADISK       :       srm://dcsrm.usatlas.bnl.gov:8443/srm/managerv2?SFN=/pnfs/usatlas.bnl.gov/BNLT0D1/rucio/mc14_13TeV/4a/92/AOD.04606956._000077.pool.root.1
        mc14_13TeV      AOD.04606956._000078.pool.root.1        188347733       01908bd8        BNL-OSG2_DATADISK       :       srm://dcsrm.usatlas.bnl.gov:8443/srm/managerv2?SFN=/pnfs/usatlas.bnl.gov/BNLT0D1/rucio/mc14_13TeV/b4/ac/AOD.04606956._000078.pool.root.1
        mc14_13TeV      AOD.04606956._000079.pool.root.1        223638483       1a6d87a5        BNL-OSG2_DATADISK       :       srm://dcsrm.usatlas.bnl.gov:8443/srm/managerv2?SFN=/pnfs/usatlas.bnl.gov/BNLT0D1/rucio/mc14_13TeV/88/0d/AOD.04606956._000079.pool.root.1

You can use the option --protocol <protocol> to get the TURLs at the site for a given protocol.

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


        $> rucio list-replicas --protocols srm mc12_14TeV:mc12_14TeV.167817.Sherpa_CT10_ZtautauMassiveCBPt140_280_CVetoBVeto.merge.log.e2445_p1614_tid01596380_00
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

    - List the dataset(s) where a particular file belongs

      The command rucio list-parent-dids <scope>:<name> has to be used for this::

        $> rucio list-parent-dids mc12_14TeV:HITS.04640638._001016.pool.root.1
        mc12_14TeV:mc12_14TeV.119996.Pythia8_A2MSTW2008LO_minbias_inelastic_high.merge.HITS.e1133_s2079_s1964_tid04640638_00 [DATASET]
        mc12_14TeV:mc12_14TeV.119996.Pythia8_A2MSTW2008LO_minbias_inelastic_high.merge.HITS.e1133_s2079_s1964_tid04640638_00_sub0201868877 [DATASET]

    - Create a Pool File Catalogue with files on a site
        Joaquin
    - Create a Pool File Catalogue and let the system guess the PFN

      Martin; I don't think this works in Rucio. Any idea?

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
        .. todo:: TDB
    - Download a sample of n random files from a dataset
        .. todo:: TBD
    - Download a dataset from a specific site
        Martin; I don't think this works, does it?
    - Download with datasets/files given in an inputfile
        Ralph
    - Download datasets from tape
        Users cannot download files from DDM sites associated to TAPE (xxx_MCTAPE and xxx_DATATAPE, CERN-PROD_TZERO and CERN-PROD_DAQ). To access data from TAPE, one should request a replication of the dataset to DISK storage through DDM request.
        If you need the whole dataset, choose the DATADISK of the same site as the destination.

    - Restrictions to access datasets on tape
        .. todo:: TBD: Restrictions to access datasets on tape

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

     - Long term storage for user datasets

       On the Grid managed by DDM, the final destination for user datasets should be LOCALGROUPDISK. This area is not pledged, its size is defined by the site and its access is restricted to local users (technically to users from the same country). Datasets in this area are deleted only if the dataset was produced centrally (mc* or data*) and the associated task is declared aborted (usually meaning that the task was bugged). To send your dataset there, request the replication by setting a rule. There is no such storage at CERN. Outside the Grid or for Grid storage not declared in DDM, the storage managment is done by the site with its own tools. Currently, files can be replicated to this area through ``dq2-get`` / ``rucio download``. There is non-Grid storage at CERN with quotas per user (to be documented).

     - Long term storage for group datasets

       The group datasets are user (possible that this user is working for a group) datasets replicated in group areas. Only the data manager of the group can request the replication of datasets.

     - Short term storage

       The dataset can be stored or replicated in SCRATCHDISK. SCRATCHDISK is the place for analysis output (except in US where _USERDISK is the place for pathena output) or ``dq2-put`` / ``rucio upload``. The deletion policy for datasets in SCRATCHDISK is defined. Using LOCALGROUPDISK as the ouput location for analysis jobs is not recommended by the DDM team.

     - Exceptions in US

       Because of temporary limitations in xrootd sites (SLACXRD and SWT2_SPB), the DDM sites SCRATCHDISK and LOCALGROUPDISK could not be created. Users are asked to send their datasets to GROUPDISK.

    - Maximum number of files in a dataset
        For technical reasons, it is strongly recommended to limit the number of files per dataset to 10k. Above this threshold, the time to scan the Rucio Catalog for transfers is becoming problematic. If more than 10k files are manipulated, create many datasets of 10k files and group them in a container.
    - Create a dataset from files on my local disk::

            rucio upload --rse RSE_NAME --files local/file1 local/file2 local/file3 --scope `account`--did scope:dataset_name

        It's possible to create a dataset without files with the command::

            rucio add-dataset scope:dataset_name

        And then, attach files to it::

            rucio attach --to scope:dataset_name scope:file1 scope:file2 scope:file3

        Note however than the files should be already in the catalog.

        ''Important note'': The names of files and datasets must be unique for a given scope. Otherwise, the rucio command will end in an error. Also the name of the files must be different that the one given for the dataset.

    - Create a dataset from files on CASTOR at CERN
        Thomas
    - Create a dataset from files on my site's DPM
        Ralph
    - Write a dataset/files in a specific DDM site::

        $> rucio upload --files <filepath1> <filepath2> --rse <RSEName> --did <scope>:<datasetname> --scope <scope>

       You can list all RSEName with the command::

        $> rucio list-rses

       Attention: You can ignore the WARNINGs, they are not ERRORs::

        $> rucio upload --files setup_dev.sh setup_dq2.sh --rse FZK-LCG2_SCRATCHDISK --did user.wguan:user.wguan.test.upload --scope user.wguan
        2015-01-26 14:07:07,661 DEBUG [Looping over the files]
        2015-01-26 14:07:07,661 DEBUG [Extracting filesize (746) and checksum (f3c7fa78) for file user.wguan:setup_dev.sh]
        2015-01-26 14:07:07,662 DEBUG [Extracting filesize (331) and checksum (c3de6c45) for file user.wguan:setup_dq2.sh]
        2015-01-26 14:07:07,978 DEBUG [Using account wguan]
        2015-01-26 14:07:08,301 INFO [Dataset successfully creat]
        2015-01-26 14:07:08,356 INFO [Adding replicas in Rucio catalog]
        2015-01-26 14:07:08,538 INFO [Replicas successfully added]
        2015-01-26 14:07:08,538 INFO [Adding replication rule on RSE FZK-LCG2_SCRATCHDISK for the file user.wguan:setup_dev.sh]
        2015-01-26 14:07:19,591 INFO [File user.wguan:setup_dev.sh successfully uploaded on the storage]
        2015-01-26 14:07:19,812 WARNING [Failed to attach file {'adler32': 'c3de6c45', 'name': 'setup_dq2.sh', 'bytes': 331, 'state': 'C', 'meta': {'guid': '6e3f326efe4d4268a2aec524e2958071'}, 'scope': 'user.wguan'} to the dataset]
        2015-01-26 14:07:19,812 WARNING [Data identifier not found.
        Details: Data identifier 'user.wguan:setup_dq2.sh' not found]
        2015-01-26 14:07:19,813 WARNING [Continuing with the next one]
        2015-01-26 14:07:19,969 INFO [Adding replicas in Rucio catalog]
        2015-01-26 14:07:20,133 INFO [Replicas successfully added]
        2015-01-26 14:07:20,133 INFO [Adding replication rule on RSE FZK-LCG2_SCRATCHDISK for the file user.wguan:setup_dq2.sh]
        2015-01-26 14:07:30,480 INFO [File user.wguan:setup_dq2.sh successfully uploaded on the storage]
        2015-01-26 14:07:30,569 WARNING [Failed to attach file {'adler32': 'f3c7fa78', 'name': 'setup_dev.sh', 'bytes': 746, 'state': 'C', 'meta': {'guid': 'e95d53297bab4cb0b3426c94659fa32b'}, 'scope': 'user.wguan'} to the dataset]
        2015-01-26 14:07:30,570 WARNING [The file already exists.
        Details: (('(IntegrityError) ORA-00001: unique constraint (ATLAS_RUCIO.CONTENTS_PK) violated\n',),)]
        2015-01-26 14:07:30,570 WARNING [Continuing with the next one]
        2015-01-26 14:07:30,950 INFO [Will update the file replicas states]
        2015-01-26 14:07:31,116 INFO [File replicas states successfully updated]

    - Create a dataset from files already in other datasets
        To create a dataset from files in other datasets, you can follow these steps:

     - Step 0: List files in the source datasets::

        $> rucio list-dids  user.wguan:user.wguan.test.upload
        |    |- user.wguan:setup_dev.sh [FILE]
        |    |- user.wguan:setup_dq2.sh [FILE]
        |    |- user.wguan:testMulProcess.py [FILE]
        |    |- user.wguan:testcatalog.py [FILE]

     - Step 1: Add destination dataset::

        $> rucio add-dataset user.wguan:user.wguan.test.upload1
        Added user.wguan:user.wguan.test.upload1

     - Step 2: Add files to destination dataset::

        $> rucio add-files-to-dataset --to user.wguan:user.wguan.test.upload1 user.wguan:setup_dev.sh user.wguan:setup_dq2.sh

     - Step 3: List the destination dataset to check the result::

        $> rucio list-dids  user.wguan:user.wguan.test.upload1
        |    |- user.wguan:setup_dev.sh [FILE]
        |    |- user.wguan:setup_dq2.sh [FILE]

    - Add files to a dataset::

       rucio add-files-to-dataset --to <DATASET> <FILE_1> <FILE_2> ... <FILE_n>

      or::

       rucio attach --to <DATASET> <FILE_1>  <FILE_2> ...  <FILE_n>

    - What to do after creating a dataset?
     - You should "close" the dataset. If the dataset is not closed, matching rules will have to constantly reevaluate your dataset and possibly generate transfers.
     - If you want to add another set of files after a while, think about using containers.
     - If you want to keep the possibility to add files to this dataset, do not close the dataset.
     - By default, user datasets are created on SCRATCHDISK at the site where the jobs run.
     - All the datasets on SCRATCHDISK are to be deleted after a certain period (minimum 7 days). See the section Lifetime of data on SCRATCHDISK.
     - To retrieve your output files, you should either
      - Set a rule. The output files will stay as a dataset on Grid.
      - Download onto your local disk using ``dq2-get`` \ ``rucio download``. The output files will not be available via DDM after the dataset on the SCRATCHDISK is deleted. If the files are Athena files (POOL files), you will not be able to re-register the files. If you see a possibility to use them on Grid, you should think about setting rules.
     - After retrieving the data from the SCRATCHDISK, you are encouraged to request early deletion of the original replicas in SCRATCHDISK.

    - Close a dataset

      To close a dataset the command rucio close has to be used::

        $> rucio close user.barisits:test-dataset
        user.barisits:test-dataset has been closed.

    - Re-open a dataset

      This is only possible for privileged accounts using the Rucio Python clients.

    - Freeze a dataset

      Freezing a dataset is not possible in Rucio. Closing the dataset is sufficient.

``Policy implemented centrally on datasets``
--------------------------------------------
    - Automatic freezing of user/group datasets
        Ralph
    - Lifetime of datasets on SCRATCHDISK
     The files on SCRATCHDISK have a lifetime of 7 days, or possibly larger depending on the free space (see the announcement to https://groups.cern.ch/group/hn-atlas-gridAnnounce/Lists/Archive/Flat.aspx?RootFolder=%2fgroup%2fhn-atlas-gridAnnounce%2fLists%2fArchive%2fLifetime%20of%20files%20on%20SCRATCHDISK&FolderCTID=0x01200200B0EE6A3A1528A6438E8AA50D12F94E5C&TopicsView=https%3A%2F%2Fgroups.cern.ch%2Fgroup%2Fhn-atlas-gridAnnounce%2Fdefault.aspx). The deletion of the oldest datasets is triggered when the site is almost full. In the near future, it will also depend on your personal usage in that specific SCRATCHDISK and also all the SCRATCHDISKs over the whole grid.

     To save your datasets before deletion, many possibilities are provided, depending on your final storage of dataset:
      - Set a rule on your favorite site on LOCALGROUPDISK through the Rucio UI https://rucio-ui.cern.ch/ It will take a few hours up to a few days to satisfy the rule.
      - If you do not want to store on a Grid disk or a disk which is not known by DDM, you can use ``dq2-get`` / ``rucio download``
      - The last possibility is to write directly your output to LOCALGROUPDISK.

    - Dataset deletion from 'aborted' or 'obsolete' tasks (central or group production)
        Vincent
    - Central deletion policy on DDM sites
        .. todo:: TBD: Central deletion policy on DDM sites

``Dataset Container commands``
------------------------------

    - Create a Dataset Container and include datasets::

       rucio add-container <CONTAINER>
       rucio add-dataset-to-container --to <CONTAINER> <DATASET_1> <DATASET_2> ... <DATASET_n>

      or::

       rucio attach --to <DATASET|CONTAINER> <FILE_1|DATASET_1>  <FILE_2|DATASET_2> ...  <FILE_n|DATASET_n>

    - List the locations of a container::


      $ rucio list-replicas --list_collections  {scope}:{container_name}

      Example::

        $ rucio list-replicas --list_collections data13_8TeV:data13_8TeV.00218048.express_express.merge.HIST.r5108_p1620
        RSE                                      Found  Total
        ------------------------------------------------------
        FZK-LCG2_DATADISK                            12     12

    .. todo:: Explain how to list scopes

    - Remove datasets from a Dataset Container
        Ralph
    - List datasets in a Dataset Container
        To list the datasets in a container:::

            rucio list-dids scope:container_name

        It's also possible to list the contents recursively with the `--recursive` option: ::

            rucio list-dids --recursive scope:container_name

        The output of this command can be large.

    - Erase a container
        Rucio Client has not implemented delete operations on dids(file, dataset, container). Rucio will automatically delete expired dids.

    - Commands to manipulate files in Dataset Containers
        Thomas
    - FAQ
        - 'Freezing' a container
            Thomas
        - Naming convention
            Rucio doesn't store the file replica path(except Tape files). The path can be directly obtained from LFN via a deterministric function.

            For example::

            $> hstr = hashlib.md5('%s:%s' % (scope, name)).hexdigest()
            $> if scope.startswith('user') or scope.startswith('group'):
            $>    scope = scope.replace('.', '/')
            $> commonPath = 'rucio/%s/%s/%s/%s' % (scope, hstr[0:2], hstr[2:4], name)
            $> pfn = os.path.join(<site-prefix>, commonPath)

        - Container of containers
            Thomas

``Advanced uses``
-----------------
    - What to do after my distributed analysis jobs create a dataset?
        Joaquin
    - Replicate a dataset to another DDM site

      Replication in Rucio is exclusively done via replication rules. To replica a dataset to another DDM site the user just has to create a replication rule for it, specifying the did, the number of copies and an RSE-Expression, which can just be the name of the RSE::

        $> rucio add-rule user.barisits:test-dataset 1 CERN-PROD_SCRATCHDISK
        09292C75957FF882E05317938A894A13

      The return value of the command is the Replication rule ID of the created rule.

    - Check if a file is corrupted
        To check whether a file is corrupted, we can compare the checksum.
     - Step 0: Get the checksum metadata of the file::

        $> rucio get-metadata user.wguan:setup_dev.sh|grep adler32
        adler32: f3c7fa78

     - Step 1: List the replica path of the file::

        $> rucio list-replicas --protocols srm user.wguan:setup_dev.sh
        Scope   Name                    Filesize        adler32 Replicas
        user.wguan      setup_dev.sh    746     f3c7fa78        FZK-LCG2_SCRATCHDISK    :       srm://atlassrm-fzk.gridka.de:8443/srm/managerv2?SFN=/pnfs/gridka.de/atlas/disk-only/atlasscratchdisk/rucio/user/wguan/fe/65/setup_dev.sh

     - Step 2: Check the checksum of this replica::

        $> gfal-sum srm://atlassrm-fzk.gridka.de:8443/srm/managerv2?SFN=/pnfs/gridka.de/atlas/disk-only/atlasscratchdisk/rucio/user/wguan/fe/65/setup_dev.sh adler32
        srm://atlassrm-fzk.gridka.de:8443/srm/managerv2?SFN=/pnfs/gridka.de/atlas/disk-only/atlasscratchdisk/rucio/user/wguan/fe/65/setup_dev.sh f3c7fa78

    - Know the size of the dataset
        Joaquin
    - Delete a dataset replica from a site::

      $ rucio delete-rule {rule_id}


        Deleting a dataset replica in Rucio is the same
        as removing the replication rule on a dataset at a site.

        .. todo:: Explain how to retrieve a rule_id for a dataset, site, account

    - delete a dataset from DDM catalog
        Command not implemented in Rucio yet.
    - Delete a dataset replica from a site - delete a dataset from DDM catalog
        Vincent
    - Remove files from a dataset (detach)::

            rucio detach --from scope:dataset_name scope:file_name1 scope:file_name2

        Notice however that this will not remove the file from the catalog.

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
        https://twiki.cern.ch/twiki/bin/view/AtlasProtected/AtlasGroupProduction
