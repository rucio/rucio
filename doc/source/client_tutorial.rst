..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0i

==================
Rucio CLI tutorial
==================


``Configuration check with 'rucio ping'``
-------------------
This command connect to server to get the version running on the server. Actually, if there is a configuration problem, this command will fail. In order to everything else in this tutorial works, this command should run smoothly.::

    $> rucio ping
    0.1.33

You will probably need to check your etc/rucio.cfg file if the output is more like this::

    $> rucio ping
    Traceback (most recent call last):
      File "/usr/local/bin/rucio", line 1568, in <module>
        result = command(args)
      File "/usr/local/bin/rucio", line 108, in ping
        ca_cert=args.ca_certificate, timeout=args.timeout)
      File "/usr/local/lib/python2.7/dist-packages/rucio/client/pingclient.py", line 24, in __init__
        super(PingClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout)
      File "/usr/local/lib/python2.7/dist-packages/rucio/client/baseclient.py", line 157, in __init__
        self.__authenticate()
      File "/usr/local/lib/python2.7/dist-packages/rucio/client/baseclient.py", line 484, in __authenticate
        self.__get_token()
      File "/usr/local/lib/python2.7/dist-packages/rucio/client/baseclient.py", line 394, in __get_token
        if not self.__get_token_x509():
      File "/usr/local/lib/python2.7/dist-packages/rucio/client/baseclient.py", line 341, in __get_token_x509
        raise exc_cls(exc_msg)
    rucio.common.exception.CannotAuthenticate: Cannot authenticate.
    Details: Cannot authenticate to account testuser with given credentials

.. It should be a link to a doc page about configuration over here.

``List available RSEs``
-----------------------
Whenever you need to locate, upload, download or delete a replica, often you will need the name of the endpoint affected. To get the list of all the available RSEs, you can try::

    $> rucio list-rses
    AGLT2_CALIBDISK
    AGLT2_DATADISK
    AGLT2_LOCALGROUPDISK
    AGLT2_PERF-MUONS
    AGLT2_PHYS-HIGGS
    ... output omited ...
    ZA-UJ_PRODDISK
    ZA-UJ_SCRATCHDISK
    ZA-WITS-CORE_LOCALGROUPDISK
    ZA-WITS-CORE_PRODDISK
    ZA-WITS-CORE_SCRATCHDISK

You can filter the type of the endpoint just greping the output. For example, to the see all the available scratch disks, this should work::

    $> rucio list-rses | grep SCRATCHDISK
    AGLT2_SCRATCHDISK
    AM-04-YERPHI_SCRATCHDISK
    ANLASC_SCRATCHDISK
    AUSTRALIA-ATLAS_SCRATCHDISK
    ... output omited ...
    WEIZMANN-LCG2_SCRATCHDISK
    WUPPERTALPROD_SCRATCHDISK
    ZA-UJ_SCRATCHDISK
    ZA-WITS-CORE_SCRATCHDISK

``Add a replica for a file``
---------------------------
To upload a replica for a file, you will need the name of the endpoint (RSE name) and the scope (usually, user.<your_login_name>) and the local name of the file.::

    $> rucio upload --files halpha-spectre.dat --rse PRAGUELCG2-RUCIOTEST_SCRATCHDISK --scope user.jbogadog
    2014-09-10 15:40:29,714 DEBUG [Looping over the files]
    2014-09-10 15:40:29,716 DEBUG [Extracting filesize (27562) and checksum (73cc55fe) for file user.jbogadog:halpha-spectre.dat]
    2014-09-10 15:40:29,955 DEBUG [Using account jbogadog]
    2014-09-10 15:40:29,956 INFO [Adding replicas in Rucio catalog]
    2014-09-10 15:40:30,090 INFO [Replicas successfully added]
    2014-09-10 15:40:30,090 INFO [Adding replication rule on RSE PRAGUELCG2-RUCIOTEST_SCRATCHDISK for the list of file]
    2014-09-10 15:40:54,257 INFO [Upload operation for [{'adler32': '73cc55fe', 'scope': 'user.jbogadog', 'state': 'C', 'bytes': 27562, 'name': 'halpha-spectre.dat'}] done]
    2014-09-10 15:40:57,509 INFO [Will update the file replicas states]
    2014-09-10 15:40:59,523 INFO [File replicas states successfully updated]
    2014-09-10 15:40:59,523 INFO [Upload successfull]

The scope:name pair is called DID. This is a unique identifier for every file or dataset in Rucio Catalog.

``Download a replica``
----------------------
To download a replica, you will need the scope and the name of the replica.::

    $ rucio download user.jbogadog:halpha-spectre.dat
    File downloaded. Will be validated
    File validated
    download operation for user.jbogadog:halpha-spectre.dat done

The downloaded file will be in $RUCIO_HOME/<your_scope>. In the example, *$RUCIO_HOME/user.jbogadog/halpha-spectre.dat*

``Create a dataset and add files to it``
----------------------------------------
In Rucio, you can create, upload and download Datasets. A Dataset is a container for several files. You can create a Dataset with the following command.::

    $> rucio add-dataset user.jbogadog:mydataset
    Added user.jbogadog:mydataset

Note that you always need to refer to the Dataset by scope:name, where 'scope' usually is user.<your_login_name> and 'name' is the name of the Dataset. The previous command creates an open empty Dataset in the Rucio Catalog. You now can add files to it in the following way::

    $> rucio add-files-to-dataset --to user.jbogadog:mydataset user.jbogadog:hbeta-spectre.dat user.jbogadog:na-spectre.dat user.jbogadog:halpha-spectre.dat

All the files you want to add to a dataset must be previously uploaded to Rucio Catalog.

Now you can see the content of a dataset with the command::

    $> rucio list-dids user.jbogadog:mydataset
    user.jbogadog:halpha-spectre.dat [FILE]
    user.jbogadog:hbeta-spectre.dat [FILE]
    user.jbogadog:na-spectre.dat [FILE]

``List files belonging to a scope and it's properties``
-----------------------------------
You can see all the files that belongs to your scope, invoking the command list-dids::

    $> rucio list-dids
    user.jbogadog:halpha-spectre.dat [FILE]
    user.jbogadog:hbeta-spectre.dat [FILE]
    user.jbogadog:na-spectre.dat [FILE]
    user.jbogadog:mydataset [DATASET]

Also, you can see the properties of a files using get-metadata command::

    $> rucio get-metadata user.jbogadog:halpha-spectre.dat
    campaign: None
    is_new: None
    is_open: None
    guid: None
    availability: None
    deleted_at: None
    panda_id: None
    version: None
    scope: user.jbogadog
    hidden: False
    md5: None
    events: None
    adler32: 73cc55fe
    complete: None
    monotonic: False
    updated_at: 2014-09-10 13:40:34
    obsolete: False
    did_type: FILE
    suppressed: False
    expired_at: None
    stream_name: None
    account: jbogadog
    run_number: None
    name: halpha-spectre.dat
    task_id: None
    datatype: None
    created_at: 2014-09-10 13:40:30
    bytes: 27562
    project: None
    length: None
    prod_step: None

``Adding rules for replication``
--------------------------------
In Rucio, you can add rules to automatically replicate files and datasets. In order to create a new rule for a file or dataset, you can try this::

    $> rucio add-rule user.jbogadog:halpha-spectre.dat 2 'spacetoken=ATLASSCRATCHDISK'

This will add a rule that makes 2 copies of the file 'user.jbogadog:halpha-spectre.dat'. The expression between quotes is a boolean one, that returns a list of possible RSEs in which the files or datasets can be copied. Rucio will automatically select the best option that satisfy the criterion. Other possible expressions are *'tier=3'*, *'cloud=DE'*, *'country=Argentina'*, etc. To see what properties can you use to filter an endpoint, you can run::

    $> rucio-admin rse get-attribute 'PRAGUELCG2-RUCIOTEST_SCRATCHDISK'
    DETIER2S: True
    ALL: True
    DETIER2DS: True
    physgroup: None
    country: Czech Republic
    spacetoken: ATLASSCRATCHDISK
    site: praguelcg2
    PRAGUELCG2-RUCIOTEST_SCRATCHDISK: True
    cloud: DE
    TIER2DS: True
    tier: 2
    FZKSITES: True
    stresstestweight: 1.0
    istape: False

For more information on rules and how to combine it, you can read the `Replication Rules Syntax`_ section.

.. _`Replication Rules Syntax`: ./replication_rules_examples.html

You can also see all the rules for your files with::

    $> rucio list-rules --account jbogadog
    ID (account) SCOPE:NAME: STATE [LOCKS_OK/REPLICATING/STUCK], RSE_EXPRESSION, COPIES
    ===================================================================================
    2d6472897cb4414786f66c80b7b857d5 (jbogadog) user.jbogadog:halpha-spectre.dat: REPLICATING[0/2/0], "tier=3", 2
    980fcfae20244f3ca147b0d368d800e5 (jbogadog) user.jbogadog:hbeta-spectre.dat: REPLICATING[0/1/0], "PRAGUELCG2-RUCIOTEST_SCRATCHDISK", 1
    a86be72f7b5c4cfeb9bd700e7a7462cc (jbogadog) user.jbogadog:na-spectre.dat: REPLICATING[0/1/0], "PRAGUELCG2-RUCIOTEST_SCRATCHDISK", 1
    530e46584b5048b093b97f1d3007fc6b (jbogadog) user.jbogadog:halpha-spectre.dat: REPLICATING[0/1/0], "PRAGUELCG2-RUCIOTEST_SCRATCHDISK", 1
    c356af4fec964f9582ec2c3d6360eded (jbogadog) user.jbogadog:halpha-spectre.dat: REPLICATING[1/1/0], "spacetoken=ATLASSCRATCHDISK", 2

And you can see information about the rule status with::

    $> rucio rule-info c356af4fec964f9582ec2c3d6360eded
    Id:                         c356af4fec964f9582ec2c3d6360eded
    Account:                    jbogadog
    Scope:                      user.jbogadog
    Name:                       halpha-spectre.dat
    RSE Expression:             spacetoken=ATLASSCRATCHDISK
    Copies:                     2
    State:                      REPLICATING
    Locks OK/REPLICATING/STUCK: 1/1/0
    Grouping:                   DATASET
    Expires at:                 None
    Locked:                     False
    Weight:                     None
    Created at:                 2014-09-15 11:06:21
    Updated at:                 2014-09-15 11:06:21
    Error:                      None
    Subscription Id:            None

Whenever you delete a rule, if is the only rule over a file, the file is marked to be deleted and eventually will. However, until the file is effectively deleted, will no longer appear in the list-rules nor in the list-dids outputs.::

    $> rucio delete-rule 980fcfae20244f3ca147b0d368d800e5
    Removed Rule
    $> rucio list-rules --account jbogadog
    ID (account) SCOPE:NAME: STATE [LOCKS_OK/REPLICATING/STUCK], RSE_EXPRESSION, COPIES
    ===================================================================================
    2d6472897cb4414786f66c80b7b857d5 (jbogadog) user.jbogadog:halpha-spectre.dat: REPLICATING[0/2/0], "tier=3", 2
    a86be72f7b5c4cfeb9bd700e7a7462cc (jbogadog) user.jbogadog:na-spectre.dat: REPLICATING[0/1/0], "PRAGUELCG2-RUCIOTEST_SCRATCHDISK", 1
    530e46584b5048b093b97f1d3007fc6b (jbogadog) user.jbogadog:halpha-spectre.dat: REPLICATING[0/1/0], "PRAGUELCG2-RUCIOTEST_SCRATCHDISK", 1

If there are other rules over a file, then only the rule is deleted but not the file itself, as you can see in the following example::

    $> rucio delete-rule 530e46584b5048b093b97f1d3007fc6b
    Removed Rule
    $> rucio list-rules --account jbogadog
    ID (account) SCOPE:NAME: STATE [LOCKS_OK/REPLICATING/STUCK], RSE_EXPRESSION, COPIES
    ===================================================================================
    2d6472897cb4414786f66c80b7b857d5 (jbogadog) user.jbogadog:halpha-spectre.dat: REPLICATING[0/2/0], "tier=3", 2
    a86be72f7b5c4cfeb9bd700e7a7462cc (jbogadog) user.jbogadog:na-spectre.dat: REPLICATING[0/1/0], "PRAGUELCG2-RUCIOTEST_SCRATCHDISK", 1
