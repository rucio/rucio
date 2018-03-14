Rucio demo
==========

Prerequisites
~~~~~~~~~~~~~

The only prerequesite is to install docker and docker-compose.


Starting a Rucio demo instance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The instructions can be found in : https://github.com/rucio/rucio/tree/master/etc/docker/demo

The bootstrap script creates a Rucio instance with 2 accounts (root and jdoe) and 2 local RSEs (SITE1_DISK, SITE2_DISK) mounted on the /tmp partition. Once everything is ready you can log into the container and start playing around with rucio::

  $ docker exec -i -t demo_rucio_1 /bin/bash

  [root@3a6d4527e1f6 rucio]# rucio whoami
  status     : ACTIVE
  account    : root
  account_type : SERVICE
  created_at : 2018-02-08T15:37:26
  suspended_at : None
  updated_at : 2018-02-08T15:37:26
  deleted_at : None
  email      : None
  [root@ad03d8dc3b4a rucio]# rucio list-scopes
  test
  user.jdoe

Testing dataset upload and creation of rules
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are no datasets created yet. To generate datasets and copy them to one of the RSEs, you can use a daemon called automatix::


  [root@3a6d4527e1f6 rucio]# /usr/bin/rucio-automatix --run-once --input-file /opt/rucio/etc/automatix.json
  ...
  2018-02-19 13:47:07,532 277     DEBUG   https://localhost:443 "POST /dids/tests/test.24659.automatix_stream.recon.AOD.917/dids HTTP/1.1" 201 None
  2018-02-19 13:47:07,533 277     INFO    Thread [1/1] : Upload operation for tests:test.24659.automatix_stream.recon.AOD.917 done
  2018-02-19 13:47:07,534 277     INFO    Thread [1/1] : Run with once mode. Exiting
  2018-02-19 13:47:07,541 277     INFO    Thread [1/1] : Graceful stop requested
  2018-02-19 13:47:07,541 277     INFO    Thread [1/1] : Graceful stop done

The daemon has created and uploaded a new dataset in the tests scope. One can list all the DIDs in this scope:: 


  [root@3a6d4527e1f6 rucio]# rucio list-dids tests:*
  +-------------------------------------------------+--------------+
  | SCOPE:NAME                                      | [DID TYPE]   |
  |-------------------------------------------------+--------------|
  | tests:AOD.a9753781316c4b2f8bd88c60e9dd3570      | FILE         |
  | tests:AOD.fc50eb5e2b1949919880f8218bf62108      | FILE         |
  | tests:test.24659.automatix_stream.recon.AOD.917 | DATASET      |
  +-------------------------------------------------+--------------+

And one can list the content of the dataset::

  [root@3a6d4527e1f6 rucio]# rucio list-files tests:test.24659.automatix_stream.recon.AOD.917        
  +--------------------------------------------+--------------------------------------+-------------+------------+----------+
  | SCOPE:NAME                                 | GUID                                 | ADLER32     | FILESIZE   | EVENTS   |
  |--------------------------------------------+--------------------------------------+-------------+------------+----------|
  | tests:AOD.a9753781316c4b2f8bd88c60e9dd3570 | 32C89A5A-F0BD-43F6-A958-099C46954C7F | ad:480900d5 | 1.000 MB   |          |
  | tests:AOD.fc50eb5e2b1949919880f8218bf62108 | 1937B5B8-BFE3-4AE0-B5CE-28AFE964F5F8 | ad:32bf834e | 1.000 MB   |          |
  +--------------------------------------------+--------------------------------------+-------------+------------+----------+
  Total files : 2
  Total size : 2.000 MB


Now if you list the rule for this dataset, you will see that there are no files listed on SITE1_DISK::

   [root@3a6d4527e1f6 rucio]# rucio list-rules tests:test.24659.automatix_stream.recon.AOD.917
   ID                                ACCOUNT    SCOPE:NAME                                       STATE[OK/REPL/STUCK]    RSE_EXPRESSION      COPIES  EXPIRES (UTC)    CREATED (UTC)
   --------------------------------  ---------  -----------------------------------------------  ----------------------  ----------------  --------  ---------------  -------------------
   7744c0e0dcce4243b906a2afbc8bc87f  root       tests:test.24659.automatix_stream.recon.AOD.917  OK[0/0/0]               SITE1_DISK               1                   2018-02-19 13:47:06

The information needs to be updated by another daemon called the judge. To run it once::

  [root@3a6d4527e1f6 rucio]# /usr/bin/rucio-judge-evaluator --run-once
  2018-02-19 13:47:37,943 328     DEBUG   re_evaluator[0/0] index query time 0.003242 fetch size is 1
  2018-02-19 13:47:37,951 328     INFO    Re-Evaluating did tests:test.24659.automatix_stream.recon.AOD.917 for ATTACH
  2018-02-19 13:47:38,010 328     DEBUG   Creating locks and replicas for rule 7744c0e0dcce4243b906a2afbc8bc87f [0/0/0]
  2018-02-19 13:47:38,011 328     DEBUG   Creating OK Lock tests:AOD.a9753781316c4b2f8bd88c60e9dd3570 for rule 7744c0e0dcce4243b906a2afbc8bc87f
  2018-02-19 13:47:38,011 328     DEBUG   Creating OK Lock tests:AOD.fc50eb5e2b1949919880f8218bf62108 for rule 7744c0e0dcce4243b906a2afbc8bc87f
  2018-02-19 13:47:38,030 328     DEBUG   Rule 7744c0e0dcce4243b906a2afbc8bc87f  [2/0/0] queued 0 transfers
  2018-02-19 13:47:38,031 328     DEBUG   queue requests
  2018-02-19 13:47:38,031 328     DEBUG   Finished creating locks and replicas for rule 7744c0e0dcce4243b906a2afbc8bc87f [2/0/0]
  2018-02-19 13:47:38,045 328     DEBUG   re_evaluator[0/0]: evaluation of tests:test.24659.automatix_stream.recon.AOD.917 took 0.101811

After this one can see that the 2 files from the dataset are located at SITE1_DISK::

  [root@3a6d4527e1f6 rucio]# rucio list-rules tests:test.24659.automatix_stream.recon.AOD.917
  ID                                ACCOUNT    SCOPE:NAME                                       STATE[OK/REPL/STUCK]    RSE_EXPRESSION      COPIES  EXPIRES (UTC)    CREATED (UTC)
  --------------------------------  ---------  -----------------------------------------------  ----------------------  ----------------  --------  ---------------  -------------------
  7744c0e0dcce4243b906a2afbc8bc87f  root       tests:test.24659.automatix_stream.recon.AOD.917  OK[2/0/0]               SITE1_DISK               1                   2018-02-19 13:47:06

One can then create another rule::

  [root@3a6d4527e1f6 rucio]# rucio add-rule tests:test.24659.automatix_stream.recon.AOD.917 1 SITE2_DISK
  [root@3a6d4527e1f6 rucio]# rucio list-rules tests:test.24659.automatix_stream.recon.AOD.917
  ID                                ACCOUNT    SCOPE:NAME                                       STATE[OK/REPL/STUCK]    RSE_EXPRESSION      COPIES  EXPIRES (UTC)    CREATED (UTC)
  --------------------------------  ---------  -----------------------------------------------  ----------------------  ----------------  --------  ---------------  -------------------
  7744c0e0dcce4243b906a2afbc8bc87f  root       tests:test.24659.automatix_stream.recon.AOD.917  OK[2/0/0]               SITE1_DISK               1                   2018-02-19 13:47:06
  f528e0681ebd404c90d534b7f7a254be  root       tests:test.24659.automatix_stream.recon.AOD.917  REPLICATING[0/2/0]      SITE2_DISK               1                   2018-02-19 13:51:42


Then you can download with::

  [root@3a6d4527e1f6 rucio]# rucio download tests:test.24659.automatix_stream.recon.AOD.917   
  2018-02-19 19:32:22,868 INFO    Thread 1/2 : Starting the download of tests:AOD.a9753781316c4b2f8bd88c60e9dd3570
  2018-02-19 19:32:22,869 INFO    Thread 2/2 : Starting the download of tests:AOD.fc50eb5e2b1949919880f8218bf62108
  2018-02-19 19:32:22,922 INFO    Thread 1/2 : File tests:AOD.a9753781316c4b2f8bd88c60e9dd3570 trying from SITE1_DISK
  2018-02-19 19:32:22,922 INFO    Thread 2/2 : File tests:AOD.fc50eb5e2b1949919880f8218bf62108 trying from SITE1_DISK
  ...
  2018-02-19 19:32:23,410 INFO    Thread 1/2 : File tests:AOD.a9753781316c4b2f8bd88c60e9dd3570 successfully downloaded. 1.000 MB in 0.11 seconds = 9.09 MBps
  2018-02-19 19:32:23,410 1032    INFO    Thread 1/2 : File tests:AOD.a9753781316c4b2f8bd88c60e9dd3570 successfully downloaded. 1.000 MB in 0.11 seconds = 9.09 MBps
  ----------------------------------
  Download summary
  ----------------------------------------
  DID tests:test.24659.automatix_stream.recon.AOD.917
  Total files :                                 2
  Downloaded files :                            2
  Files already found locally :                 0
  Files that cannot be downloaded :             0

To delete the rule::

  [root@3a6d4527e1f6 rucio]# rucio update-rule --lifetime -7200 f528e0681ebd404c90d534b7f7a254be
  Updated Rule

  [root@3a6d4527e1f6 rucio]# /usr/bin/rucio-judge-cleaner --run-once                            
  2018-02-19 19:59:16,258 1388    DEBUG   rule_cleaner[0/0] index query time 0.008735 fetch size is 1
  2018-02-19 19:59:16,258 1388    INFO    rule_cleaner[0/0]: Deleting rule f528e0681ebd404c90d534b7f7a254be with expression SITE2_DISK
  2018-02-19 19:59:16,273 1388    DEBUG   Deleting lock tests:AOD.a9753781316c4b2f8bd88c60e9dd3570 for rule f528e0681ebd404c90d534b7f7a254be
  2018-02-19 19:59:16,281 1388    DEBUG   Deleting lock tests:AOD.fc50eb5e2b1949919880f8218bf62108 for rule f528e0681ebd404c90d534b7f7a254be
  2018-02-19 19:59:16,359 1388    DEBUG   rule_cleaner[0/0]: deletion of f528e0681ebd404c90d534b7f7a254be took 0.100267

  [root@3a6d4527e1f6 rucio]# rucio list-rules tests:test.24659.automatix_stream.recon.AOD.917   
  ID                                ACCOUNT    SCOPE:NAME                                       STATE[OK/REPL/STUCK]    RSE_EXPRESSION      COPIES  EXPIRES (UTC)    CREATED (UTC)
  --------------------------------  ---------  -----------------------------------------------  ----------------------  ----------------  --------  ---------------  -------------------
  7744c0e0dcce4243b906a2afbc8bc87f  root       tests:test.24659.automatix_stream.recon.AOD.917  OK[2/0/0]               SITE1_DISK               1                   2018-02-19 13:47:06



