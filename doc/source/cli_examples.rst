=========
Rucio CLI
=========


Rucio provides several command for the end-users::

  $ rucio 
  usage: rucio [-h] [--version] [--verbose] [-H ADDRESS] [--auth-host ADDRESS]
               [-a ACCOUNT] [-S AUTH_STRATEGY] [-T TIMEOUT] [--robot]
               [--user-agent USER_AGENT] [-u USERNAME] [-pwd PASSWORD]
               [--certificate CERTIFICATE] [--ca-certificate CA_CERTIFICATE]
               
               {ping,whoami,list-file-replicas,list-dataset-replicas,add-dataset,add-container,attach,detach,ls,list-dids,list-parent-dids,list-parent-datasets,list-scopes,close,reopen,stat,erase,list-files,list-content,list-content-history,upload,get,download,get-metadata,set-metadata,list-rse-usage,list-account-usage,list-account-limits,add-rule,delete-rule,rule-info,list-rules,list-rules-history,update-rule,move-rule,list-rses,list-rse-attributes,list-datasets-rse,test-server,touch}
               ...
  
  positional arguments:
    {ping,whoami,list-file-replicas,list-dataset-replicas,add-dataset,add-container,attach,detach,ls,list-dids,list-parent-dids,list-parent-datasets,list-scopes,close,reopen,stat,erase,list-files,list-content,list-content-history,upload,get,download,get-metadata,set-metadata,list-rse-usage,list-account-usage,list-account-limits,add-rule,delete-rule,rule-info,list-rules,list-rules-history,update-rule,move-rule,list-rses,list-rse-attributes,list-datasets-rse,test-server,touch}
      ping                Ping Rucio server.
      whoami              Get information about account whose token is used.
      list-file-replicas  List the replicas of a DID and it's PFNs.
      list-dataset-replicas
                          List the dataset replicas.
      add-dataset         Add a dataset to Rucio Catalog.
      add-container       Add a container to Rucio Catalog.
      attach              Attach a list of DIDs to a parent DID.
      detach              Detach a list of DIDs from a parent DID.
      ls                  List the data identifiers matching some metadata
                          (synonym for list-dids).
      list-dids           List the data identifiers matching some metadata
                          (synonym for ls).
      list-parent-dids    List parent DIDs for a given DID
      list-parent-datasets
                          List parent DIDs for a given DID
      list-scopes         List all available scopes.
      close               Close a dataset or container.
      reopen              Reopen a dataset or container (only for privileged
                          users).
      stat                List attributes and statuses about data identifiers.
      erase               Delete a data identifier.
      list-files          List DID contents
      list-content        List the content of a collection.
      list-content-history
                          List the content history of a collection.
      upload              Upload method.
      get                 Download method (synonym for download)
      download            Download method (synonym for get)
      get-metadata        Get metadata for DIDs.
      set-metadata        set-metadata method
      list-rse-usage      Shows the total/free/used space for a given RSE. This
                          values can differ for different RSE source.
      list-account-usage  Shows the space used, the quota limit and the quota
                          left for an account for every RSE where the user have
                          quota.
      list-account-limits
                          List quota limits for an account in every RSEs.
      add-rule            Add replication rule.
      delete-rule         Delete replication rule.
      rule-info           Retrieve information about a rule.
      list-rules          List replication rules.
      list-rules-history  List replication rules history for a DID.
      update-rule         Update replication rule.
      move-rule           Move a replication rule to another RSE.
      list-rses           Show the list of all the registered Rucio Storage
                          Elements (RSEs).
      list-rse-attributes
                          List the attributes of an RSE.
      list-datasets-rse   List all the datasets at a RSE
      test-server         Test Server
      touch               Touch one or more DIDs and set the last accessed date
                          to the current date
  
  optional arguments:
    -h, --help            show this help message and exit
    --version             show program's version number and exit
    --verbose, -v         Print more verbose output.
    -H ADDRESS, --host ADDRESS
                          The Rucio API host.
    --auth-host ADDRESS   The Rucio Authentication host.
    -a ACCOUNT, --account ACCOUNT
                          Rucio account to use.
    -S AUTH_STRATEGY, --auth-strategy AUTH_STRATEGY
                          Authentication strategy (userpass, x509, ssh ...)
    -T TIMEOUT, --timeout TIMEOUT
                          Set all timeout values to seconds.
    --robot, -R           All output in bytes and without the units. This output
                          format is preferred by parsers and scripts.
    --user-agent USER_AGENT, -U USER_AGENT
                          Rucio User Agent
    -u USERNAME, --user USERNAME
                          username
    -pwd PASSWORD, --password PASSWORD
                          password
    --certificate CERTIFICATE
                          Client certificate file.
    --ca-certificate CA_CERTIFICATE
                          CA certificate to verify peer against (SSL).



Getting user information
========================

The first thing you might try is to check who you are::

  $ rucio whoami
  status     : ACTIVE
  account    : jdoe
  account_type : SERVICE
  created_at : 2014-01-17T07:52:18
  updated_at : 2014-01-17T07:52:18
  suspended_at : None
  deleted_at : None
  email      : jdoe@blahblah.com


You can switch between different accounts by setting the RUCIO_ACCOUNT variable::

  $ export RUCIO_ACCOUNT=root
  $ rucio whoami
  status     : ACTIVE
  account    : jdoe
  account_type : SERVICE
  created_at : 2014-01-17T07:51:59
  updated_at : 2014-01-17T07:51:59
  suspended_at : None
  deleted_at : None
  email      : root@blahblah.com

If you try to authenticate with a account that is not mapped with your credentials::

  $ export RUCIO_ACCOUNT=janedoe
  $ rucio whoami
  cannot get auth_token
   2018-01-30 16:50:08,554 ERROR   Cannot authenticate.
   Details: x509 authentication failed
   2018-01-30 16:50:08,554 ERROR   Please verify that your proxy is still valid and renew it if needed.



Querrying basic information about RSEs
======================================

You can query the list of available RSEs::

  $ rucio list-rses
  SITE1_DISK
  SITE1_TAPE
  SITE2_DISK
  SITE2_SCRATCH
  SITE3_TAPE


If the RSEs are tagged with attributes you can built RSE expressions and query the sites matching this expression::

  $ rucio list-rses --expression "tier=1&disk=1"
  SITE1_DISK
  SITE2_DISK


Querying information about DIDs
================================

To list all the possible scopes::

  $ rucio list-scopes
  mc
  data
  user.jdoe
  user.janedoe

You can query the DIDs matching a certain pattern. It always requires to specify the scope in which you want to search::

  $ rucio list-dids user.jdoe:*
  +-------------------------------------------+--------------+
  | SCOPE:NAME                                | [DID TYPE]   |
  |-------------------------------------------+--------------|
  | user.jdoe:user.jdoe.test.container.1234.1 | CONTAINER    |
  | user.jdoe:user.jdoe.test.container.1234.2 | CONTAINER    |
  | user.jdoe:user.jdoe.test.dataset.1        | DATASET      |
  | user.jdoe:user.jdoe.test.dataset.2        | DATASET      |
  | user.jdoe:test.file.1                     | FILE         |
  | user.jdoe:test.file.2                     | FILE         |
  | user.jdoe:test.file.3                     | FILE         |
  |-------------------------------------------+--------------|

You can filter by key/value, e.g.::

  $ rucio list-dids --filter type=CONTAINER
  +-------------------------------------------+--------------+
  | SCOPE:NAME                                | [DID TYPE]   |
  |-------------------------------------------+--------------|
  | user.jdoe:user.jdoe.test.container.1234.1 | CONTAINER    |
  | user.jdoe:user.jdoe.test.container.1234.2 | CONTAINER    |
  |-------------------------------------------+--------------|

If you want to resolve a collection (CONTAINER or DATASET) into the list of its constituents::

  $ rucio list-content user.jdoe:user.jdoe.test.container.1234.1
  +------------------------------------+--------------+
  | SCOPE:NAME                         | [DID TYPE]   |
  |------------------------------------+--------------|
  | user.jdoe:user.jdoe.test.dataset.1 | DATASET      |
  | user.jdoe:user.jdoe.test.dataset.2 | DATASET      |
  +------------------------------------+--------------+



You can resolve also the collections (CONTAINER or DATASET) into the list of files::

  $ rucio list-content user.jdoe:user.jdoe.test.container.1234.1
  +-----------------------+--------------------------------------+-------------+------------+----------+
  | SCOPE:NAME            | GUID                                 | ADLER32     | FILESIZE   | EVENTS   |
  |-----------------------+--------------------------------------+-------------+------------+----------|
  | user.jdoe:test.file.1 | 9DF32550-D0D1-4482-9A26-0FBC46D6902A | ad:56fb0723 | 39.247 kB  |          |
  | user.jdoe:test.file.2 | 67E8CF14-F953-45F3-B3F5-E6143F89915F | ad:e3e573b5 | 636.075 kB |          |
  | user.jdoe:test.file.3 | 32CD7F8E-944B-4EA4-83E3-BABE48DB5751 | ad:22849380 | 641.427 kB |          |
  +-----------------------+--------------------------------------+-------------+------------+----------+
  Total files : 3
  Total size : 1.316 MB:


Rules operations
================
You can create a new rule like this::

  $ rucio add-rules --lifetime 1209600 user.jdoe:user.jdoe.test.container.1234.1 1 "tier=1&disk=1"
  a12e5664555a4f12b3cc6991db5accf9

The command returns the rule_id of the rule.


You can list the rules for a particular DID:: 

  $ rucio list-rules user.jdoe:user.jdoe.test.container.1234.1
  ID                                ACCOUNT    SCOPE:NAME                                 STATE[OK/REPL/STUCK]    RSE_EXPRESSION        COPIES  EXPIRES (UTC)
  --------------------------------  ---------  -----------------------------------------  ----------------------  ------------------  --------  -------------------
  a12e5664555a4f12b3cc6991db5accf9  jdoe       user.jdoe:user.jdoe.test.container.1234.1  OK[3/0/0]               tier=1&disk=1       1         2018-02-09 03:57:46
  b0fcde2acbdb489b874c3c4537595adc  janedoe    user.jdoe:user.jdoe.test.container.1234.1  REPLICATING[4/1/1]      tier=1&tape=1       2
  4a6bd85c13384bd6836fbc06e8b316d7  mc         user.jdoe:user.jdoe.test.container.1234.1  OK[3/0/0]               tier=1&tape=1       2

The state indicate how many locks (physical replicas of the files) are OK, Replicating or Stuck

Accessing files
===============

The command to download DIDs locally is called rucio download. It supports various sets of option. You can invoke it like this::

  # rucio download user.jdoe:user.jdoe.test.container.1234.1
  2018-02-02 15:13:08,450 INFO    Thread 1/3 : Starting the download of user.jdoe:test.file.2
  2018-02-02 15:13:08,451 INFO    Thread 2/3 : Starting the download of user.jdoe:test.file.3
  2018-02-02 15:13:08,451 INFO    Thread 3/3 : Starting the download of user.jdoe:test.file.1
  2018-02-02 15:13:08,503 INFO    Thread 1/3 : File user.jdoe:test.file.2 trying from SITE1_DISK
  2018-02-02 15:13:08,549 INFO    Thread 2/3 : File user.jdoe:test.file.3 trying from SITE2_DISK
  2018-02-02 15:13:08,551 INFO    Thread 3/3 : File user.jdoe:test.file.1 trying from SITE1_DISK
  2018-02-02 15:13:10,399 INFO    Thread 3/3 : File user.jdoe:test.file.1 successfully downloaded from SITE1_DISK
  2018-02-02 15:13:10,415 INFO    Thread 2/3 : File user.jdoe:test.file.3 successfully downloaded from SITE2_DISK
  2018-02-02 15:13:10,420 INFO    Thread 3/3 : File user.jdoe:test.file.1 successfully downloaded. 39.247 kB in 1.85 seconds = 0.02 MBps
  2018-02-02 15:13:10,537 INFO    Thread 2/3 : File user.jdoe:test.file.3 successfully downloaded. 641.427 kB in 1.87 seconds = 0.34 MBps
  2018-02-02 15:13:10,614 INFO    Thread 1/3 : File user.jdoe:test.file.2 successfully downloaded from SITE1_DISK
  2018-02-02 15:13:10,633 INFO    Thread 1/3 : File user.jdoe:test.file.2 successfully downloaded. 636.075 kB in 2.11 seconds = 0.3 MBps
  ----------------------------------
  Download summary
  ----------------------------------------
  DID user.jdoe:user.jdoe.test.container.1234.1
  Total files :                                 3
  Downloaded files :                            3
  Files already found locally :                 0
  Files that cannot be downloaded :             0

