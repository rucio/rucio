-------------------------
Replication rule examples
-------------------------

Replica management is based on replication rules defined on data identifiers. A
replication rule gets resolved and issues replica locks on the physical
replicas.

A replication rule consists (besides other parameters) of a factor representing
the numbers of replicas wanted and a Rucio Storage Element Expression that allows
to select a set of probable RSEs to store the replicas.

The `RSE Expression`_ gets resolved into a set of RSEs, which are
possible destination RSEs for the number of replicas the user wants to create.

Is possible to find detailed information and examples about how to write RSE Expressions `here`_.

.. _RSE Expression: RSE_Expressions.html
.. _here: RSE_Expressions.html

^^^^^^^^^
Example 1
^^^^^^^^^

*I want to have 2 replicas of first_dataset and second_datset on Tier 1 RSEs*

The number 2 *second_dataset* is the number of copies expected. At the end, the RSE Expression select all the Tier 1 RSEs as possible targets to store the replicas.::

    username@host:~$ rucio add-rule scope:first_dataset scope:second_dataset 2 'tier=1'

To see all the possible targets, **rucio list-rses** command can be used::

    username@host:~$ rucio list-rses --expression 'tier=1'



^^^^^^^^^
Example 2
^^^^^^^^^

*I want to have 2 replicas on whatever T2 RSEs in the UK but it shouldn't be Glasgow*::

    username@host:~$ rucio add-rule scope:first_dataset scope:second_dataset 2 'country=uk\site=GLASGOW'
