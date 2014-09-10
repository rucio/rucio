==================
Rucio CLI tutorial
==================


``Configuration check with 'rucio ping'``
-------------------
This command connect to server to get the version running on the server. Actually, if there is a configuration problem, this command will fail. In order to everything else in this tutorial works, this command should run smoothly.::

    $> rucio ping
    0.1.32

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

You can filter the type of the endpoint just greping the output. For example, to the all the available scratch disks, this should work::

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

``Download a replica``
----------------------
To download a replica, you will need the scope and the name of the replica.::

    $ rucio download user.jbogadog:halpha-spectre.dat
    File downloaded. Will be validated
    File validated
    download operation for user.jbogadog:halpha-spectre.dat done

``Create a dataset and add files to it``
----------------------------------------
In Rucio, you can create, upload and download Datasets. A Dataset is a container for several files. You can create a Dataset with the following command.::

    $> rucio add-dataset user.jbogadog:mydataset
    Added user.jbogadog:mydataset

Note that you always need to refer to the Dataset by scope:name, where 'scope' usually is user.<your_login_name> and 'name' is the name of the scope. The previous command creates an open empty Dataset in the Rucio Catalog. You now can add files to it in the following way::

    $> rucio add-files-to-dataset --to user.jbogadog:mydataset user.jbogadog:hbeta-spectre.dat user.jbogadog:na-spectre.dat user.jbogadog:halpha-spectre.dat

All the files you want to add to a dataset must be previously uploaded to Rucio Catalog.

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


