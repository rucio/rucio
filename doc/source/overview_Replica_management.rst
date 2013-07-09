------------------
Replica management
------------------

^^^^^^^^^^^^^^^^
General Overview
^^^^^^^^^^^^^^^^

Replica management is based on replication rules defined on logical files. A replication rule is owned by an account and defines the minimum number of replicas to be available on a list of RSEs. Accounts are allowed to set multiple rules [#f1]_. Rules may optionally have a limited lifetime and can be added, removed or modified at any time.

An example listing of replication rules is given below:

* prod: 1x replica @ CERN, no lifetime
* barisits: 1x replica @ US-T2, until 2012-01-01
* vgaronne: 2x replica @ T1, no lifetime

A rule engine validates the rules and creates transfer primitives to fulfil all rules, e.g. transfer a file from RSE A to RSE B. The rule engine is triggered when a file is created in the system, when a new rule is added to a file or when one explicitly requests for the rule to be applied on existing data. The rule engine will only create the minimum set of necessary transfer primitives to satisfy all rules.

An account can inject transfer primitives directly, e.g., transient replicas required for production operations. Notifications can be provided for the transfer request. All transfer requests are transient.

Deletion is triggered per RSE when storage policy dictates that space must be freed. A reaper service will look for replicas on that RSE which can be deleted without violating any replication rules. The reaper will use a Least Recently Used (LRU) algorithm to select replicas for deletion. The reaper service will also immediately delete all replicas of any file which is declared obsolete.

.. rubric:: Footnotes

.. [#f1] The system may reject rules if these violate other policies, e.g., a normal ATLAS user would not be allowed to set a rule which committed the system to generate 5PB of new replicas or to request replicas on an RSE tape system.
