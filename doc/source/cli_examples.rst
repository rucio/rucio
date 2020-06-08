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
   - Cedric Serfon <cedric.serfon@cern.ch>, 2018
   - Vincent Garonne <vgaronne@gmail.com>, 2018
   - Patrick Austin <patrick.austin@stfc.ac.uk>, 2020

===================
Rucio CLI: Examples
===================

Rucio provides several commands for the end-user. See `man pages <man/rucio.html>`_.

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

If you try to authenticate with an account that is not mapped with your credentials::

  $ export RUCIO_ACCOUNT=janedoe
  $ rucio whoami
  cannot get auth_token
   2018-01-30 16:50:08,554 ERROR   Cannot authenticate.
   Details: x509 authentication failed
   2018-01-30 16:50:08,554 ERROR   Please verify that your proxy is still valid and renew it if needed.

If you're running a multi-VO instance of Rucio, then the VO to authenticate against is set in the configuration file. However you can specify a different VO as a CLI argument if your credentials map to an account there too::

  $ rucio whoami
  status     : ACTIVE
  account    : jdoe
  account_type : SERVICE
  created_at : 2014-01-17T07:52:18
  updated_at : 2014-01-17T07:52:18
  suspended_at : None
  deleted_at : None
  email      : jdoe@normalvo.com
  $ rucio --vo abc --account root whoami
  status     : ACTIVE
  account    : root
  account_type : SERVICE
  created_at : 2014-01-17T07:51:59
  updated_at : 2014-01-17T07:51:59
  suspended_at : None
  deleted_at : None
  email      : root@abc.com



Open ID Connect authentication examples
=======================================

There are 3 CLI login methods. Two were introduced in order to avoid typing the password in the Rucio CLI. The default Identity Provider (IdP)/issuer is configured on the side of Rucio server. In case multiple IdPs are supported, user can specify which one he desires to use by ``--oidc-issuer=<IdP nickname>`` option (where IdP nickname is the key under which issuers are configured on Rucio server side in the `idpsecrets.json` file). In the following examples we assume that user does not want to use the rucio account name specified in the rucio.cfg file on the client side (if so ``-a`` parameter can be omitted). If `auth_type`` is specified to be "oidc" in the rucio.cfg file, ``-S`` can be omitted as well. Furthermore, we use the same default issuer as configured on Rucio server side.

1. Login via user's browser + fetch code::

  rucio -a=<rucio_account_name> -S=OIDC -v whoami

2. Login via user's browser + polling Rucio auth server::

  rucio -a=<rucio_account_name> -S=OIDC --oidc-polling -v whoami

3. Automatic login::

  rucio -a=<rucio_account_name> -S=OIDC --oidc-user=<idp_username> --oidc-password=<idp_password> --oidc-auto -v whoami

We strongly discourage this approach, typing your password in CLI does not comply with OAuth2/OIDC standard !


Options for automatic token refresh: Assuming the rucio-oauth-manager daemon is running on the Rucio server side, one can also grant Rucio a refresh token and specify the time for which Rucio should act on behalf of the user (in hours) using the ``--refresh-lifetime`` option::

  rucio -a=<rucio_account_name> -S=OIDC --oidc-scope="openid profile offline_access" --oidc-refresh-lifetime=24 -v whoami

If Rucio Server is granted a user both valid access and refresh tokens, it is also possible to configure Rucio Client to ask Rucio Server for token refresh. Assuming user used one of the 3 CLI authentication methods above + requested offline_access in the scope, rucio.cfg file can be configured with the following parameters in the [client] section::

  [client]
  auth_oidc_refresh_active true
  auth_oidc_refresh_before_exp 20

``auth_oidc_refresh_active`` is false by default. If set to true, the Rucio Client will be following up token expiration timestamp. As soon as the current time gets to ``auth_oidc_refresh_before_exp`` minutes (20 min default) before token expiration, Rucio Client will ask Rucio Server for token refresh with every command. If the token has been refreshed in the recent 5 min already once, the same one will be returned (protection on the Rucio Server side). If the presented token has been refreshed automatically on the Rucio Server side by a oauth_manager daemon run, it will return this existing new token. If the presented token is invalid/expired/does not have refresh token in the DB, no refresh will be attempted.

Example of rucio.cfg file configuration with automatic token refresh::

  [client]
  rucio_host = https://<rucio_host>:443
  auth_host = https://<rucio_auth_host>:443
  auth_type = oidc
  account = <rucio_account_name>
  oidc_audience = rucio
  oidc_scope = openid profile offline_access
  oidc_issuer = wlcg
  auth_oidc_refresh_active true
  auth_oidc_refresh_before_exp 20

Then, you should be able to do simply::

  rucio -v whoami

and follow the instruction for first log-in with your browser. New token will be requested before the current expires if a user types a rucio command within ``auth_oidc_refresh_before_exp`` minutes before the expiry. Note: If user does not use Rucio Client within ``auth_oidc_refresh_before_exp`` minutes before token expires, it will be necessary to re-authenticate asking for a new offline_access token.


If a user wishes to authenticate with Rucio using a JSON web token not issued via the Rucio login mechanisms (CLI, WebUI), one has to make sure that::

* the token scope claim is no less than the minimum scope (e.g. 'openid profile') required by the Rucio Auth server (configured there in the rucio.cfg file).
* same as above is true for the use of audience claim
* token issuer is known to Rucio Authentication server
* the identity of the token ("SUB=<user sub claim>, ISS=<issuer url>") is assigned to an existing Rucio account (pre-provisioned)

If so, one can directly present the token to the Rucio REST endpoint in the 'X-Rucio-Auth-Token' header, e.g.::

  $ python
  $ import requests
  $ s=requests.session()
  $ your_token=<your JWT access token string>
  $ headers={'X-Rucio-Auth-Token': your_token}
  $ address='https://<Rucio Auth Server Name>/accounts/guenther'
  $ result=s.get(address, headers=headers, verify=False)
  $ result.text
  >>> u'{"status": "ACTIVE", "account": "guenther", "account_type": "USER", "created_at": "2019-11-13T13:01:58", "suspended_at": null, "updated_at": "2019-11-13T13:01:58", "deleted_at": null, "email": "jaroslav.guenther@gmail.com"}'

There is also an option to specify a ``auth_token_file_path`` in the ``[client]`` section of the rucio.cfg file. Rucio Client will then store and search for user's token saved in such file::

  [client]
  auth_token_file_path = /path/to/token/file



Querrying basic information about RSEs
======================================

You can query the list of available RSEs::

  $ rucio list-rses
  SITE1_DISK
  SITE1_TAPE
  SITE2_DISK
  SITE2_SCRATCH
  SITE3_TAPE


If the RSEs are tagged with attributes you can build RSE expressions and query the sites matching these expressions::

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

  $ rucio list-files user.jdoe:user.jdoe.test.container.1234.1
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

The state indicates how many locks (physical replicas of the files) are OK, Replicating or Stuck

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
