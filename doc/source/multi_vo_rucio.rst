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
