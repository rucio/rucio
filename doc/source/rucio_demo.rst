..  Copyright 2018 CERN for the benefit of the ATLAS collaboration.
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

     Unless required by applicable law or agreed to in writing, software
     distributed under the License is distributed on an "AS IS" BASIS,
     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
     See the License for the specific language governing permissions and
     limitations under the License.

     Authors:
   - Thomas Beermann <thomas.beermann@cern.ch>, 2018
   - Cedric Serfon <cedric.serfon@cern.ch>, 2018
   - Vincent Garonne <vgaronne@gmail.com>, 2018

Rucio demo
==========

Starting a Rucio demo instance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The instructions can be found in `Setting up a Rucio demo environment <http://rucio.readthedocs.io/installing_demo.html>`_

Boostrap the Rucio demo
~~~~~~~~~~~~~~~~~~~~~~~

Once everything is ready you can log into the container and start playing around with rucio::

  $ docker exec -i -t demo_rucio_1 /bin/bash

The bash tab completion is by default enabled for the Rucio CLIs.
The rucio configuration file is located in `/opt/rucio/etc/rucio.cfg`.
The clients are configured to talk to the local server instance::

  $ cat /opt/rucio/etc/rucio.cfg
  ...
  [client]
  rucio_host = https://localhost:443
  auth_host = https://localhost:443
  ...

In this demo, an apache server runs and the log files are located in  ´/var/log/rucio/´
To query the Rucio server, you can ping it with::

  $ curl -k https://localhost/ping
   {"version": "1.14.9.post1"}

In the corresponding apache log file, you can see the access log entry::

  $ tail -f  /var/log/rucio/httpd_access_log
    localhost - - [27/Feb/2018:11:57:59 +0000] "GET /ping HTTP/1.1" 200 27

The equivalent command exists with the rucio CLI::

  $ rucio ping
  cannot get auth_token
  2018-02-27 13:22:54,297	ERROR	Cannot authenticate.
  Details: userpass authentication failed

But it fails since the command also authenticates with Rucio and this Rucio instance is not configured.


Configuring Rucio
~~~~~~~~~~~~~~~~~

A bootstrap script is provided at `/setup_data.py`. This script creates the database tables and creates 2 accounts: `root` and `jdoe` and 2 local Rucio storage elements (RSEs): `SITE1_DISK`, `SITE2_DISK` mounted on the /tmp partition.

This example script uses the Rucio python client module.To execute it::

 $ /setup_data.py

By default, it will create a MySQL database as specified in the configuration::

 $ cat /opt/rucio/etc/rucio.cfg
  ...
  [database]
  default = mysql://rucio:rucio@mysql/rucio
  ...

To create a different one like sqlite, you need to change this section, e.g.,::

 $ cat /opt/rucio/etc/rucio.cfg
  ...
  [database]
  default = sqlite:////tmp/rucio.db
  ...

Execute the script and restart apache::

 $ /setup_data.py
 $  httpd -k restart

Rucio supports mysql, mariadb, oracle and postgresql.

`rucio ping` now works::

 $ rucio ping
 1.14.9.post1

The token is stored in `/tmp/root/.rucio_root/auth_token_root`.

The equivalent can be done with the Rucio python clients::

 $ python
  ...
  >>> from rucio.client import Client
  >>> rucio_client = Client()
  >>> rucio_client.ping()
  {u'version': u'1.14.9.post1'}

You can also check your account::

  [root@3a6d4527e1f6 rucio]# rucio whoami
  status     : ACTIVE
  account    : root
  account_type : SERVICE
  created_at : 2018-02-08T15:37:26
  suspended_at : None
  updated_at : 2018-02-08T15:37:26
  deleted_at : None
  email      : None

To list the RSEs::

 $ rucio list-rses
 SITE1_DISK
 SITE2_DISK

We can add some RSE attributes::

 $ rucio-admin rse set-attribute  --rse SITE1_DISK --key zone --value eu-west-3
 Added new RSE attribute for SITE1_DISK: zone-eu-west-3

 $ rucio-admin rse set-attribute  --rse SITE2_DISK --key zone --value us-west-1
 Added new RSE attribute for SITE2_DISK:  rucio list-rses --expression 'zone=us-west-1'

 $ rucio list-rses --expression 'zone=eu-west-3'
    SITE1_DISK

To list the accounts::

 $ # rucio-admin account list
 jdoe
 root

Testing dataset upload, creation of dataset and rules
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

