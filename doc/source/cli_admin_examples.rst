..
      Copyright European Organization for Nuclear Research (CERN)

      Licensed under the Apache License, Version 2.0 (the "License");
      You may not use this file except in compliance with the License.
      You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

========================
Rucio Admin CLI Examples
========================

The syntax of the Rucio admin command line interface is: rucio-admin <ressource> <command> [args], where ressource can be account,identity,rse,scope,meta.

The --help argument can be used to know the syntax of each commands.


Account
^^^^^^^
``rucio-admin account add``
---------------------------
Add an account::

   $> rucio-admin account add vgaronne
   Added new account: vgaronne

``rucio-admin account del``
---------------------------
Delete an account::

   $> rucio-admin account del vgaronne
   Deleted account: vgaronne
``rucio-admin account list``
----------------------------
List accounts::

   $> rucio-admin account list
   root
   vgaronne
``rucio-admin account show``
----------------------------
List account details::

   $> rucio-admin account show vgaronne
   status     : active
   account    : vgaronne
   deleted    : False
   created_at : 2012-10-16T14:30:04
   updated_at : 2012-10-16T14:30:04
   deleted_at : None
   type       : user
   
``rucio-admin account set-limits``
----------------------------------
Set account limits::

   $> rucio-admin account set-limits --account vgaronne --rse_expr "GROUPDISK AND tier=1" --value 1000000
   Added new limits to account: vgaronne
   
``rucio-admin account get-limits``
----------------------------------
Get account limits::

   $> rucio-admin account get-limits vgaronne
``rucio-admin account del-limits``
----------------------------------
Del account limits::

   $> rucio-admin account del-limits --account vgaronne --rse_expr "GROUPDISK AND tier=1"
Identity
^^^^^^^^
``rucio-admin identity add``
----------------------------
Grant a {userpass|x509|gss|proxy} identity access to an account::

   $> rucio-admin identity add --account vgaronne --id vgaronne@CERN.CH --type gss
   Added new identity to account: vgaronne@CERN.CH-vgaronne

``rucio-admin list-identities``
-------------------------------
List all identities on an account::

   $> rucio-admin account list-identities vgaronne
   Identity: vgaronne@CERN.CH,	type: gss

Rucio Storage Element (RSE)
^^^^^^^^^^^^^^^^^^^^^^^^^^^
``rucio-admin rse add``
-----------------------
Add a RSE::

   $> rucio-admin rse add MOCK
   Added new RSE: MOCK

``rucio-admin rse list``
------------------------
List RSEs::

   $> rucio-admin rse list
   MOCK
   MOCK1
   MOCK2
   
``rucio-admin rse set-attr``
----------------------------
Set RSE attribute::

   $> rucio-admin rse set-attr --rse MOCK --key tier  --value 1
   Added new RSE attribute for MOCK: tier-1 
   
Set RSE a tag (attribute with value=True)::

   $> rucio-admin rse set-attr --rse MOCK2 --key GROUPDISK  --value True
   Added new RSE attribute for MOCK2: GROUPDISK-True 

``rucio-admin rse get-attr``
----------------------------
Get RSE attribute::

   $> rucio-admin rse get-attr MOCK
   tier: 1
   
``rucio-admin rse del-attr``
----------------------------
Delete RSE attribute::

   $> rucio-admin rse del-attr --rse MOCK2 --key CLOUD --value CERN
   Deleted RSE attribute for MOCK2: CLOUD-CERN 
   
Scope
^^^^^
``rucio-admin scope add``
-------------------------
Add scope to an account::

   $> rucio-admin scope add --account vgaronne --scope vgaronne
   Added new scope to account: vgaronne-vgaronne
   
``rucio-admin scope list``
--------------------------
List scopes::

   $> rucio-admin scope list
   vgaronne
   
Meta-data
^^^^^^^^^
``rucio-admin metadata add``
----------------------------
Create a new allowed key(with default values if specified)::

   $> rucio-admin metadata add --key --value --type --DItypes
``rucio-admin metadata del``
----------------------------
Delete an allowed key or key/value::

   $> rucio-admin metadata del --key --value --type --DItypes
``rucio-admin metadata list``
-----------------------------
List all allowed keys with their default values::

   $> rucio-admin metadata list
