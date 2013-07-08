------------------------------
Replication Rules Architecture
------------------------------

^^^^^^^^^^^^^^^^^^^^^
Architecture Overview
^^^^^^^^^^^^^^^^^^^^^

The replication rules are managed by two components in Rucio.

* Rules Core module

  The rules core module offers functions which are directly called by the API or
  other core components. The main functionality offered are creating, listing
  and deleting replication rules.

* Rules daemon: Rucio-Judge

  The rules daemon is responsible for making sure that replication rules are
  correct when datasets/containers are changed. The judge also takes care of the
  deletion of expired rules and re-evaluates replication rules which are in the
  STUCK state.

^^^^^^^^^^^^^^^
Database Schema
^^^^^^^^^^^^^^^

There are two tables which hold the information concerning all replication rules
and locks.

**Rules**

.. include:: ../../lib/rucio/db/models.py
             :code:
             :start-after: #                   ForeignKeyConstraint(['rse_id', 'scope', 'name'], ['replica_locks.rse_id', 'replica_locks.scope', 'replica_locks.name'], name='REPLICAS_RULES_FK'),
             :end-before: class ReplicaLock(BASE, ModelBase):

**Locks**

.. include:: ../../lib/rucio/db/models.py
             :code:
             :start-after: UniqueConstraint('scope', 'name', 'account', 'rse_expression', 'copies', name='RULES_UQ'),)
             :end-before: class Request(BASE, ModelBase):

Also relevant are the **DataIdentifier** table, holding all data identifiers, the **DataIdentifierAssociation** table, expressing the relation between child and parent dids as well as the **RSEFileAssociation** table, which is the catalog of all physical replicas.

^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Relevant System interactions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Besides listing and searching replication rules, there are 6 Rucio interactions which are relevant for the rule component.

* Creating a replication rule

  A replication rule is always created for a specific did (file, dataset, container). When the rule is created it is evaluated immediately, thus creating all replica locks and, if necessary, file transfers. This action is directly linked to the core method:

  .. py:function:: rucio.core.rule.add_replication_rule(dids, account, ...)


* Deleting a replication rule

  Replication rules can be deleted by their owner (or an privileged
  account). The removal of the rule and it's associated locks is done by the
  core function:

  .. py:function:: rucio.core.rule.delete_replication_rule(rule_id, ...)

* Adding a did to a parent did

  Attaching a data identifier to a dataset or container has to trigger a rule
  evaluation, as all parent rules have to be applied to the new children as
  well. The method flags the did for re-evaluation in the DID table. This re-evaluation is done asynchronously by the Rucio-Judge. The action is directly linked to the core method:

  .. py:function:: rucio.core.did.attach_identifier(scope, name, dids, ...)

* Removing a did from a parent did

  When removing dids from a dataset or container, the previously matching rules
  may not match anymore. Thus the respective locks have to be removed from the
  files. The method flags the did for re-evaluation in the DID table. This is done asynchronously by the Rucio-Judge. This action is linked to the core method:

  .. py:function:: rucio.core.did.detach_identifier(scope, name, dids, ...)

* Successfully finishing a transfer

  When a transfer finishes the state of all affected locks (one new replica can affect many locks) and rules have to be
  updated. This action is linked to the core method:

  .. py:function:: rucio.core.rule.successful_transfer(scope, name, rse_id)

* Failing a transfer

  When a transfer fails the state of all affected locks and rules has to be
  updated, so that the Rucio-Judge can make new decisions to repair the
  rule. This action is linked to the core method:

  .. py:function:: rucio.core.rule.failed_transfer(scope, name, rse_id)

^^^^^^^^^^^^^^^^
General Workflow
^^^^^^^^^^^^^^^^

.. _adding_replication_rules:

""""""""""""""""""""""""
Adding replication rules
""""""""""""""""""""""""

This section describes the general workflow when adding replication rules. There
are basically three different cases that have to be considered. Rules added to a
file, dataset or container.

.. graphviz::

   digraph E1 {
       label="Rule on file";
       rule1 [shape=diamond, label="Rule", style=filled,color="lightblue"];
       file1 [label="File"];
       rule1:sw -> file1:ne [color=darkgreen, label="add", fontcolor=darkgreen];
   }

.. graphviz::

   digraph E2 {
       label="Rule on dataset";
       rule2 [shape=diamond, label="Rule", style=filled,color="lightblue"];
       dataset2 [shape=box, label="Dataset"];
       files2_1 [label="File1"];
       files2_2 [label="File2"];
       files2_3 [label="File3"];
       dataset2 -> files2_1;
       dataset2 -> files2_2;
       dataset2 -> files2_3;
       rule2:sw -> dataset2:ne [color=darkgreen, label="add", fontcolor=darkgreen];
   }

.. graphviz::

    digraph E3 {
       label="Rule on container";
       rule3 [shape=diamond, label="Rule", style=filled,color="lightblue"];
       container3[shape=house, label="Container"];
       dataset3[shape=box, label="Dataset"];
       files3_1 [label="File1"];
       files3_2 [label="File2"];
       files3_3 [label="File3"];
       container3 -> dataset3;
       dataset3 -> files3_1;
       dataset3 -> files3_2;
       dataset3 -> files3_3;
       rule3:sw -> container3:ne [color=darkgreen, label="add", fontcolor=darkgreen];
    }

The general workflow when adding a rule is described as follows: (Ignore lines
2, 6, 7 and 9 for the moment)

.. code-block:: none
    :linenos:
    :emphasize-lines: 2, 6, 7, 9

    Create a DB transaction
    Row-Lock the did in the did table
    Resolve the RSE expression to a list of potential RSEs
    Get the current quota/usage values of the account for each RSE
    Create the replication rule in the ReplicationRule table
    if did.type==CONTAINER:
           Row-Lock all child datasets and containers in the did table
    Resolve the did to it's files and get all associated ReplicaLocks
    Row-Lock all these ReplicaLocks (Actually done in the same query as 8.)
    if grouping==NONE:
        for each file:
            Pick N rses for the file considering filesize, quota, weights and existing locks of the file
    if grouping==ALL:
        Calculate size of all files
        Calculate the current coverage (in bytes) of the files on the rses
        Pick n rses considering the sum-size, quota, weights and rse coverage
    if grouping==DATASET:
        for each dataset:
            Calculate the size of all files in the dataset
            Calculate the current coverage (in bytes) of the files in the dataset on rses
            Pick n rses considering the dataset-size, quota, weights and rse coverage
    Create the locks in the database
    Create the necessary transfers
    Commit the DB transaction

.. 2.  Row-Lock the did in the did table (More about this later)
.. 6.  if did.type==CONTAINER:
.. 7.      Row-Lock all child datasets and containers in the did table (More about this later)
.. 9.  Row-Lock all these ReplicaLocks (Actually done in the same query as 8.)

Right now, the decisions in line 12, 16 and 21 where to create the new replica locks are done as follows:

1. Exclude all potential RSEs which do not have enough quota to hold the file/dataset/container.
2. If the RSEs already hold replica locks of the concerned replicas, sort these RSEs by number of replica locks.
3. Pick the first N RSEs out of the list.
4. If RSEs hold the same amount of replica locks (or no locks at all) pick N RSEs according to the RSE weights.

Example::

  DatasetA = [File0, ..., File9] with 100 MB per file
  potential RSEs:
      RSEA ... 1300 MB quota, 3 replicas of DatasetA, weight=0.1
      RSEB ... 400 MB quota, 5 replicas of DatasetA, weight=10
      RSEC ... 4000 MB quota, 0 replicas of DatasetA, weight=100
      RSED ... 3000 MB quota, 0 replicas of DatasetA, weight=50
  Rule: 2 replicas, DATASET grouping

1. Exclude all potential RSEs which do not have enough quota (RSE B gets excluded); potential RSEs = [RSEA, RSEC, RSED].
2. RSEA already holds replicas, put RSEA to priority List; priorityRSEs = [RSEA].
3. Pick the first 2 RSEs out of the priorityRSEs list; (There is only 1 entry); RSEA is picked, 1 remaining RSE to pick.
4. RSEC and RSED left in potential RSE list; Pick according to weights; (Random pick according to weights) RSEC gets picked.

Result: Put replica locks on RSEA and RSEC.

.. _deleting_replication_rules:

""""""""""""""""""""""""""
Deleting replication rules
""""""""""""""""""""""""""

This section describes the general workflow when deleting replication rules.

.. graphviz::

   digraph E1 {
       label="Rule on file";
       rule1 [shape=diamond, label="Rule", style=filled,color="lightblue"];
       file1 [label="File"];
       rule1:sw -> file1:ne [color=red, label="del", fontcolor=red];
   }

.. graphviz::

   digraph E2 {
       label="Rule on dataset";
       rule2 [shape=diamond, label="Rule", style=filled,color="lightblue"];
       dataset2 [shape=box, label="Dataset"];
       files2_1 [label="File1"];
       files2_2 [label="File2"];
       files2_3 [label="File3"];
       dataset2 -> files2_1;
       dataset2 -> files2_2;
       dataset2 -> files2_3;
       rule2:sw -> dataset2:ne [color=red, label="del", fontcolor=red];
     }

.. graphviz::

   digraph E3 {
       label="Rule on container";
       rule3 [shape=diamond, label="Rule", style=filled,color="lightblue"];
       container3[shape=house, label="Container"];
       dataset3[shape=box, label="Dataset"];
       files3_1 [label="File1"];
       files3_2 [label="File2"];
       files3_3 [label="File3"];
       container3 -> dataset3;
       dataset3 -> files3_1;
       dataset3 -> files3_2;
       dataset3 -> files3_3;
       rule3:sw -> container3:ne [color=red, label="del", fontcolor=red];
   }

The general workflow when deleting a rule is described as follows: (Ignore lines
2 and 11 for the moment)

.. code-block:: none
    :linenos:
    :emphasize-lines: 2, 11

    Create a DB transaction
    Row-Lock the replication rule in the ReplicationRule table
    if state==OK:  # There are no running transfers!
        Delete the replication rule from the ReplicationRule table (Locks will be deleted cascading)
    if state==SUSPENDED:  # There are no running transfers!
        Delete the replication rule from the ReplicationRule table (Locks will be deleted cascading)
    if state==STUCK:  # There are no running transfers!
        Delete the replication rule from the ReplicationRule table (Locks will be deleted cascading)
    if state==REPLICATING:  # There are running transfers which may have to be cancelled
        Get all ReplicaLocks for all files affected by this rule
        Row-Lock the Locks in the ReplicaLocks table (Will be done in the same query)
        for each file:
            If the lock is REPLICATING and there are no other Locks, cancel the transfer
    Commit transaction

.. Row-Lock the replication rule in the ReplicationRule table
..         Row-Lock the Locks in the ReplicaLocks table (Will be done in the same query)

.. _re-evaluate_did_add:

""""""""""""""""""""""""""""""""""""""""""""""
Re-Evaluating a DID (Something has been added)
""""""""""""""""""""""""""""""""""""""""""""""

When files are added to datasets or datasets/containers to containers, the
affecting rules have to be re-evaluated and Locks have to be set on the new
children.

.. graphviz::

   digraph E1 {
       label="Rule on file";
       np[label="Not possible", shape=text]
   }

.. graphviz::

   digraph E2 {
       label="Rule on dataset";
       rule2 [shape=diamond, label="Rule", style=filled,color="lightblue"];
       dataset2 [shape=box, label="Dataset"];
       files2_1 [label="File1"];
       files2_2 [label="File2"];
       files2_3 [label="File3"];
       files2_4 [label="File4"];
       dataset2 -> files2_1;
       dataset2 -> files2_2;
       dataset2 -> files2_3;
       dataset2 -> files2_4 [color=darkgreen, label="attach", fontcolor=darkgreen];
       rule2:sw -> dataset2:ne;
   }

.. graphviz::

   digraph E3 {
       label="Rule on container";
       rule3 [shape=diamond, label="Rule", style=filled,color="lightblue"];
       container3[shape=house, label="Container"];
       dataset3_1[shape=box, label="Dataset1"];
       dataset3_2[shape=box, label="Dataset2"]
       files3_1 [label="File1"];
       files3_2 [label="File2"];
       files3_3 [label="File3"];
       files3_4 [label="File4"];
       container3 -> dataset3_1;
       dataset3_1 -> files3_1;
       dataset3_1 -> files3_2;
       dataset3_1 -> files3_3;
       dataset3_1 -> files3_4 [color=darkgreen, label="attach", fontcolor=darkgreen];
       files3_5 [label="File4"];
       files3_6 [label="File5"];
       files3_7 [label="File6"];
       dataset3_2 -> files3_5;
       dataset3_2 -> files3_6;
       dataset3_2 -> files3_7;
       container3 -> dataset3_2 [color=darkgreen, label="attach", fontcolor=darkgreen];
       rule3:sw -> container3:ne;
   }

The general workflow when re-evaluating a rule is described as follows: (Ignore lines
3, 5, 7, 9, 12 and 14 for the moment)

.. code-block:: none
    :linenos:
    :emphasize-lines: 3, 5, 7, 9, 12, 14

    Create a DB transaction
    Pickup the next did which needs re-evaluation
    Row-Lock this did in the DID table
    Get all parent dids (Go up the tree)
    Row-Lock these parent dids in the DID table
    Get all replication rules from the parent dids and the did itself
    Row-Lock these rules in the Rule table
    Get all the newly attached children of the DID
    Row-Lock these dids in the did table
    if these new child dids are DATASETS or CONTAINERS:
        Follow the tree down the path to get all new_files
        Row-Lock all intermediate datasets and containers in the DID table
    Get the ReplicaLocks for all new files
    Row-Lock these ReplicaLocks in the Lock Table
    for all rules found in the parents:
        Resolve RSE Expression and fetch Quotas
        if rule.grouping == DATASET or CONTAINER:
            Based on the existing locks get the grouping decision which has been made before
        For the new files make the lock decisions and create transfers (Same algorithm as in Add Replication Rule)
        If same grouping is not possible due to quota, pick another RSE
        If anything of the above fails, mark the rule as STUCK
    Mark the did as re_evaluated
    Commit the transaction

.. Row-Lock this did in the DID table
.. Row-Lock these parent dids in the DID table
.. Row-Lock these rules in the Rule table
.. Row-Lock these dids in the did table
.. Row-Lock all intermediate datasets and containers in the DID table
.. Row-Lock these ReplicaLocks in the Lock Table

.. _re-evaluate_did_del:

""""""""""""""""""""""""""""""""""""""""""""""""
Re-Evaluating a DID (Something has been removed)
""""""""""""""""""""""""""""""""""""""""""""""""

When files are removed from datasets or datasets/containers from containers, the
affecting rules have to be re-evaluated and Locks have to be removed.

.. graphviz::

   digraph E1 {
       label="Rule on file";
       np[label="Not possible", shape=text]
   }

.. graphviz::

   digraph E2 {
       label="Rule on dataset";
       rule2 [shape=diamond, label="Rule", style=filled,color="lightblue"];
       dataset2 [shape=box, label="Dataset"];
       files2_1 [label="File1"];
       files2_2 [label="File2"];
       files2_3 [label="File3"];
       files2_4 [label="File4"];
       dataset2 -> files2_1;
       dataset2 -> files2_2;
       dataset2 -> files2_3;
       dataset2 -> files2_4 [color=red, label="detach", fontcolor=red];
       rule2:sw -> dataset2:ne;
   }

.. graphviz::

   digraph E3 {
       label="Rule on container";
       rule3 [shape=diamond, label="Rule", style=filled,color="lightblue"];
       container3[shape=house, label="Container"];
       dataset3_1[shape=box, label="Dataset1"];
       dataset3_2[shape=box, label="Dataset2"]
       files3_1 [label="File1"];
       files3_2 [label="File2"];
       files3_3 [label="File3"];
       files3_4 [label="File4"];
       container3 -> dataset3_1;
       dataset3_1 -> files3_1;
       dataset3_1 -> files3_2;
       dataset3_1 -> files3_3;
       dataset3_1 -> files3_4 [color=red, label="detach", fontcolor=red];
       files3_5 [label="File4"];
       files3_6 [label="File5"];
       files3_7 [label="File6"];
       dataset3_2 -> files3_5;
       dataset3_2 -> files3_6;
       dataset3_2 -> files3_7;
       container3 -> dataset3_2 [color=red, label="detach", fontcolor=red];
       rule3:sw -> container3:ne;
   }

The general workflow when re-evaluating a rule is described as follows: (Ignore lines
3, 5, 7, and 11 for the moment)

.. code-block:: none
    :linenos:
    :emphasize-lines: 3, 5, 7, 11

    Create a DB transaction
    Pickup the next did which needs re-evaluation
    Row-Lock this did in the DID table
    Get all parent dids (Go up the tree)
    Row-Lock these parent dids in the DID table
    Get all replication rules from the parent dids and the did itself
    Row-Lock these rules in the Rule table
    Get all the files of the did (Does not consider the removed ones)
    for each rule:
        Get all locks of the rule
        Row-Lock these locks
        if there is no file for the lock, the lock can be deleted
    Mark the did as re_evaluated
    Commit the transaction


.. Row-Lock this did in the DID table
.. Row-Lock these parent dids in the DID table
.. Row-Lock these rules in the Rule table
.. Row-Lock these locks

.. _updating_locks:

""""""""""""""""""""""""""""""""""""""""""""
Updating locks on successful/failed transfer
""""""""""""""""""""""""""""""""""""""""""""

If a transfer is successful or fails, all the locks for the file on this RSE
have to be updated.

On successful transfer (Ignore line 3 for now)

.. code-block:: none
    :linenos:
    :emphasize-lines: 3

    Create a DB transaction
    Get all the locks of the transferred file on the rse
    Row-Lock these locks
    for each lock:
        Update Lock state to OK
        Check if the replication rule of the lock has any REPLICATING locks left, if not mark the rule as OK
    Commit the transaction

.. Row-Lock these locks

On failed  transfer (Ignore line 3 for now)

.. code-block:: none
    :linenos:
    :emphasize-lines: 3

    Create a DB transaction
    Get all the locks of the transferred file on the rse
    Row-Lock these locks
    for each lock:
        Update Lock state to STUCK
        Check if the replication rule of the lock has any REPLICATING locks lefts, if not mark the rule as STUCK
    Commit the transaction

.. Row-Lock these locks

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Race-Conditions and concurrency problems
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This section specifically describes the race-conditions and concurrency issues
that could bring the rules out of sync with the actual files. As this is very
critical and cannot be detected easily, it is very important to prevent this
issues in the first place.

1. A rule is applied to a did while some did in the structure (higher or lower) is being changed concurrently

   * :ref:`adding_replication_rules` line 8 would read a did listing which could be invalid at t+1 and thus not apply the rule to every file. We therefore make the following requirement: **Whenever a did is changed or a rule is applied/evaluated on a did the session needs to acquire a row-lock of the did in the did table!** Thus we  add line 2::

       Row-Lock the did in the did table

     As every action needs to acquire a lock in the did table, only a single session can change the did. However, also dids lower in the structure could be changed concurrently. To prevent this we add line 6 and 7::

       if did.type==CONTAINER:
           Row-Lock all child datasets and containers in the did table

   * :ref:`re-evaluate_did_add` To prevent changes of the did itself we add line 3::

       Row-Lock this did in the DID table

     Line 4 would read a did listing of higher-level dids  which could be invalid at t+1 and thus not apply the rules correctly. We add line 5::

       Row-Lock these parent dids in the DID table

     Line 8 would read a did listing of lower-level dids which could be invalid at t+1 and thus not apply the rules correctly. We add line 9::

       Row-Lock these dids in the did table

     Also line 12 is added for the same purpose::

       Row-Lock all intermediate datasets and containers in the DID table

   * :ref:`re-evaluate_did_del` Line 8 could end up with a wrong did listing at t+1. To prevent changes of the did itself we add line 3::

       Row-Lock this did in the DID table

     Line 4 could end up with an inconsistent listing at t+1. As parent dids have to be prevented from changing as well, line 5 is added::

       Row-Lock these parent dids in the DID table

   * When a did is attached to a parent-did, this parent-did has to be row-locked as well.

   * When a did is detached from a parent-did, this parent-did has to be row-locked as well.

2. While a did is re-evaluated, other rules (applying to the did) are changed concurrently

   * :ref:`adding_replication_rules` Line 8 would maybe get the right ReplicaLocks, but when creating the new locks (under the assumption that another lock is already there) this creates problems when these locks are deleted concurrently; Thus, when these locks get deleted while they are used as assumption for re-evaluation, it could happen that a lock is being created without a file replica (and without a transfer to create one). The solution is in line 9::

       Row-Lock all these ReplicaLocks (Actually done in the same query as 8.)

     By row-locking all the ReplicaLocks, it is not possible that a lock is being deleted while it is used as an assumption for re-evaluation.

   * :ref:`deleting_replication_rules` As the adding part is requesting row-locks for the rule and locks, it is important the the deletion part does the same. Line 2::

       Row-Lock the replication rule in the ReplicationRule table

     Line 11::

       Row-Lock the Locks in the ReplicaLocks table (Will be done in the same query)

   * :ref:`re-evaluate_did_add` These rule and replica-lock locks have also be requested in the re-evaluation part. Line 7::

       Row-Lock these rules in the Rule table

     and line 14::

       Row-Lock these ReplicaLocks in the Lock Table

   * :ref:`re-evaluate_did_del` The same thing also applies for the deletion part. Rules and Locks have to be row-locked as they cannot be used by another session concurrently. Line 7::

       Row-Lock these rules in the Rule table

     Line 11::

       Row-Lock these locks

   * :ref:`updating_locks` also when updating locks on successful/failed transfers, these locks have to be row-locked. Line 3::

       Row-Lock these locks
