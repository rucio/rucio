Multi-VO Rucio
==============

This section provides an overview of using Rucio for multiple virtual organizations (VOs) on a single instance with the "Multi-VO" feature. Rather than each VO having to set up
an entire instance by themselves, they can share the same server and database which are run by a central "super_root", and continue to use Rucio as they would a normal or 
"Single-VO" instance. Their accounts, scopes and RSEs are associated with their VO which ensures all rules and replicas are kept separate from other VOs using the instance. 


Changes to the Client
^^^^^^^^^^^^^^^^^^^^^

At the CLI and client level there are few changes to how Rucio is used. These cases, such as optional arguments for VO, are covered in documentation for the affected function. The
main change is the addition of two options in the ``rucio.cfg`` file, one to flag that the instance is being run in M-VO mode and another to specify the VO the users belong to::

  [common]
  ...
  multi_vo = True

  [client]
  ...
  vo = abc

``multi_vo`` should also be set in the other config files for the server, daemons etc. However, ``vo`` should not be set in these cases as these parts of Rucio are not associated
with a single VO. If ``multi_vo`` is not set, or set to False, then Rucio will operate normally.


Role of the super_root
^^^^^^^^^^^^^^^^^^^^^^

While root accounts still retain their administrative role within a VO, for example adding RSEs and accounts, functions relating to the creation and management of VOs is handled
by the super_root account, a concept introduced with M-VO Rucio. It is worth noting that the super_root account **cannot** be used to perform individual VO administration; the
roles of super_root and root are distinct.


Access of super_root Functions
------------------------------

As the super_root functions aren't intended for use by normal users of admins, they do not have an implementation in the client or CLI. They can be accessed from the core or the
:ref:`vo-rest-api`, however the latter will require the VO endpoint to be added to the aliases file used when setting up the server as it is disabled by default. 


Starting a M-VO Instance
------------------------

When bootstrapping the database as part of the Rucio installation, if M-VO is enabled in ``rucio.cfg`` then the super_root account is created automatically. The default VO "def"
is also created, and the super_root acccount is associated with it. The identity used to access this account can be managed in the usual way.


Creating VOs
------------

When creating a new VO with the ``add_vo`` function you need to specify the three digit identifier for the new VO, which can contain letters and numbers. This must be unique for
the instance. A more complete description can also be optionally included, along with an email to use for the root of this new VO. In addition to creating the new VO, a root
account is also created for this VO, and has all identities associated with super_root added to it. The identities for the new root can then be configured as usual.


Managing VOs
------------

In addition to creating VOs, the description and email for a VO can be altered using ``update_vo``. If the root user of a VO loses access to their account, the super_root can
associate a new identity with it using ``recover_vo_root_identity``. Finally, a list of current VOs and their descriptions is accessible via ``list_vos``.


Converting Existing Instances
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

As opposed to starting a new M-VO instance from scratch, it may be desirable to
convert the database for an existing (S-VO) Rucio instance into a M-VO instance
so that additional VOs can be added without disrupting the original VO or
needing to create a second instance. Conversely, one VO within a M-VO instance may
grow to the point where it needs its own dedicated instance, and so converting
data from M-VO to S-VO may also be desirable. These operations can be performed
using utility functions included with Rucio.

As mentioned above, in order to configure a M-VO instance of Rucio only the
config file needs to change. However for an existing instance any entries already
in the database will not be associated with a VO (or associated with their old
one if previously in M-VO mode). In order to change these, direct operations on
the database are required. These commands are generated using SQLAlchemy, and
can either be run directly on the database or printed out and run manually.

Practicalities
--------------

Before attempting to convert existing data, it is recommended that a backup of
the database is taken in case an issue arises. Furthermore, of the databases
supported by Rucio, only PostgreSQL has been tested on real data. Based on this
test (which was performed on a machine with 64GB memory and four Intel Xeon E5-2430 v2),
the tables with 2 columns that needed updating were converted at a rate of 5GB
of data per hour. However many tables do not need any changes, so the process
will likely be faster than this in practice. Another approach to speed up the
conversion is to skip the "history" tables, as these can be very large. Unlike
other tables these do not have foreign key constraints set, and so do not need
to be updated in order to use the database. While the history will be
inaccessible from the new VO, it will still exist in the database and could be
accessed using the ``super_root`` account if needed.

S-VO to M-VO
------------

Before starting, ensure that ``multi_vo`` is set to ``True`` in the config file.
The SQL commands needed to convert the database involve dropping foreign key
constraints that affect accounts/scopes, then altering the relevant columns,
before re-adding the constraints. The 3 character identifier for the VO, a full
description and an admin email should be provided::

  $ tools/convert_database_vo.py convert_to_mvo new "New VO for existing data" rucio@email.com
  ALTER TABLE account_limits DROP CONSTRAINT "ACCOUNT_LIMITS_ACCOUNT_FK";
  ...
  UPDATE account_limits SET account=(split_part(account_limits.account, '@', 1) || CAST('@new' AS CHAR(4))) WHERE split_part(account_limits.account, '@', 2) = '';
  ...
  ALTER TABLE account_limits ADD CONSTRAINT "ACCOUNT_LIMITS_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account);

In this example, no changes will be made to the database by running the script,
and so the SQL will need to be run manually. After running the commands, a 
``super_root`` account should be setup to allow administrative functions like
adding more VOs::

  $ python
  >>> from rucio.db.sqla.util import create_root_account
  >>> create_root_account(create_counters=False)

Alternatively by specifying ``--commit_changes`` the script will attempt to
modify the database as it runs, however this requires the account used by the
Rucio instance to access the database to be the owner of the the tables. In
this case, the ``super_root`` account can be added as part of the script by
passing the argument ``--create_super_root``. If there is an error during the
conversion, then none of the changes will be committed.

  $ tools/convert_database_vo.py --commit_changes convert_to_mvo new "New VO for existing data" rucio@email.com --create_super_root

Finally, there is the option to skip the (potentially very large) tables of
historical data using ``--skip_history``. In this case the commands to alter
those tables are omitted::

  $ tools/convert_database_vo.py --skip_history convert_to_mvo new "New VO for existing data" rucio@email.com


M-VO to S-VO
------------

Before starting, ensure that ``multi_vo`` is set to ``True`` in the config file
(this option can be removed after completing the conversion). The first stage
of the conversion is the same as before, dropping foreign key constraints and
renaming the entries that were associated with the old VO. The name of this VO
is the only required argument::

  $ tools/convert_database_vo.py convert_to_svo old
  ALTER TABLE account_limits DROP CONSTRAINT "ACCOUNT_LIMITS_ACCOUNT_FK";
  ...
  UPDATE account_limits SET account=split_part(account_limits.account, '@', 1) WHERE split_part(account_limits.account, '@', 2) = 'old';
  ...
  ALTER TABLE account_limits ADD CONSTRAINT "ACCOUNT_LIMITS_ACCOUNT_FK" FOREIGN KEY(account) REFERENCES accounts (account);

By default data associated with any other VOs is left in the database, but will be
inaccessible to Rucio users. By setting pass the argument ``--delete_vos``, these
entries will be deleted from the database completely::

  $ tools/convert_database_vo.py convert_to_svo old --delete_vos
  ...
  DELETE FROM account_limits WHERE split_part(account_limits.account, '@', 2) = 'xyz';
  ...
  DELETE FROM account_limits WHERE split_part(account_limits.account, '@', 2) = '123';
  ...

Once again, historical tables skipped with ``--skip_history``, and the commands
can be run directly against the database using the ``--commit_changes`` argument;
if this is not set then the ``super_root`` account should be manually deleted
after running the SQL::

  $ python
  >>> from rucio.common.types import InternalAccount
  >>> from rucio.core.account import del_account
  >>> del_account(InternalAccount('super_root', vo='def'))
