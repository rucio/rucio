========================
Rucio administration CLI
========================


Rucio provides a CLI for administrative tasks.. The get methods can be executed by any users, but the set methods require some admin privileges::

  $ rucio-admin 
  usage: rucio-admin [-h] [--version] [--verbose] [-H ADDRESS]
                     [--auth_host ADDRESS] [-a ACCOUNT] [-S AUTH_STRATEGY]
                     [-T TIMEOUT] [-u USERNAME] [-pwd PASSWORD]
                     [--certificate CERTIFICATE]
                     [--ca-certificate CA_CERTIFICATE]
                     {account,identity,rse,scope,config,subscription,replicas}
                     ...
  
  positional arguments:
    {account,identity,rse,scope,config,subscription,replicas}
      account             Account methods
      identity            Identity methods
      rse                 RSE (Rucio Storage Element) methods
      scope               Scope methods
      config              Configuration methods
      subscription        Subscription methods
      replicas            Replica methods
  
  optional arguments:
    -h, --help            show this help message and exit
    --version             show program's version number and exit
    --verbose, -v         Print more verbose output
    -H ADDRESS, --host ADDRESS
                          The Rucio API host
    --auth_host ADDRESS   The Rucio Authentication host
    -a ACCOUNT, --account ACCOUNT
                          Rucio account to use
    -S AUTH_STRATEGY, --auth-strategy AUTH_STRATEGY
                          Authentication strategy (userpass, x509, ssh ...)
    -T TIMEOUT, --timeout TIMEOUT
                          Set all timeout values to SECONDS
    -u USERNAME, --user USERNAME
                          username
    -pwd PASSWORD, --password PASSWORD
                          password
    --certificate CERTIFICATE
                          Client certificate file
    --ca-certificate CA_CERTIFICATE
                          CA certificate to verify peer against (SSL)

Account and identity methods
============================

To create a new account::

  $ rucio-admin account add --type USER --email jdoe@blahblih.com jdoe

You can choose different types in the list USER, GROUP, SERVICE. Different policies/permissions can be set dependending on the account type.  Once the account is created, you need to create and attach an identity to this account::

  $ rucio-admin identity add --type X509 --id "/DC=blah/DC=blih/OU=Organic Units/OU=Users/CN=jdoe" --email jdoe@blahblih.com --account jdoe

The list of possible identity types is X509, GSS, USERPASS, SSH::

  $ rucio-admin account list-identities jdoe
  Identity: /DC=blah/DC=blih/OU=Organic Units/OU=Users/CN=jdoe,        type: X509

You can set attributes to the users::

  $ rucio-admin account add-attribute --key country --value xyz jdoe

And list these attributes::

  $ rucio-admin account list-attributes jdoe
  +---------+-------+
  | Key     | Value |
  |---------+-------|
  | country | xyz   |
  +---------+-------+

You can also list all the accounts matching a certain attribute using the filter option::

  $ rucio-admin account list --filters "country=xyz"
  jdoe


To set the quota for one account on a given RSE::

  $ rucio-admin account set-limits jdoe SITE2_SCRATCH 10000000000000
  Set account limit for account jdoe on RSE SITE2_SCRATCH: 10.000 TB
  $ rucio-admin account get-limits dcameron SITE2_SCRATCH
  Quota on SITE2_SCRATCH for jdoe : 10 TB


Scope methods
=============

To create a new scope::

  $ rucio-admin scope add --account jdoe --scope user.jdoe

Only the owner of the scope or privileged users can write into the scope.

To list all the scopes::
  $ rucio-admin scope list
  user.janedoe
  user.jdoe


RSE methods
===========

To create a new RSE::

  $ rucio-admin rse add SITE2_SCRATCH

To add a RSE attribute::

  $ rucio-admin rse set-attribute --rse SITE2_SCRATCH --key country --value xyz
  $ rse get-attribute SITE2_SCRATCH
  country: xyz

 
Replica methods
===============

To declare bad (i.e. corrupted or lost replicas)::

  $ rucio-admin replicas declare-bad --reason "File corrupted" https//path/to/lost/file

