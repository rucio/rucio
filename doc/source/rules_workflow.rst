==============
Rules Workflow
==============

When a rule is created, at least one replica lock is created for each of the associated files of the did. These replica locks can be in 3 states: OK, if the replica already exists at the site; REPLICATING, if the replica is in the process of beeing transfered to the RSE and STUCK, if several transfer attempts have been made unsuccessfully. Usually, new rules will only have replica locks in the state OK or REPLICATING. After rule creation, depending if there are any REPLICATING locks (or all have already been satisfied) the rule is created in the states OK or REPLICATING. However, as new files can be added to the did later, which results in additional replica locks, the state of the rule can change according to the following state diagram:

.. graphviz::

   digraph g {
     CREATE[label="RULE CREATION", shape=doubleoctagon];
     REPLICATING;
     OK;
     SUSPENDED;
     STUCK;
     CREATE -> OK [label="0 replicating locks"];
     CREATE -> REPLICATING [label=">0 replicating locks"];
     REPLICATING -> OK [label="0 replicating locks"];
     OK -> REPLICATING [label=">0 replicating locks"];
     OK -> STUCK [label="rule error"];
     STUCK -> REPLICATING [label="0 stuck locks & no rule error"];
     REPLICATING -> STUCK [label=">1 stuck locks"];
     REPLICATING -> STUCK [label="rule error"];
   }

The SUSPENDED state is set and unset manually.
