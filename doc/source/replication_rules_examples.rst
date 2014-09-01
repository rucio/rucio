-----------------------
Replication rule syntax
-----------------------

Replica management is based on replication rules defined on data identifiers. A
replication rule gets resolved and issues replica locks on the physical
replicas.

A replication rule consists (besides other parameters) of a factor representing
the numbers of replicas wanted and a replication rule expression. This page
explains the syntax of these replication rule expressions.

A replication rule expression gets resolved into a set of RSEs, which are
possible destination RSEs for the number of replicas the user wants to create.

^^^^^^^^^^
Primitives
^^^^^^^^^^

A replication rule expression consists of, at least, a single
primitive. Primitives can be connected by operators (Defined in the next
section) to form terms.
The Rucio core resolves a primitive to a set of
RSEs. For example, the expression 'country=US' would be
resolved to the set of all RSEs located in the US.

==============  ===================  ============================================================
Element         Example              Regular Expression
==============  ===================  ============================================================
RSE             CERN_DATADISK        ([A-Z0-9]+((_|-)[A-Z0-9]+)*)
RSE-Tag         T1                   ([A-Z0-9]+((_|-)[A-Z0-9]+)*)
RSE Attributes  country=US           ([A-Za-z0-9\.]+=[A-Za-z0-9])
==============  ===================  ============================================================

^^^^^^^^^
Operators
^^^^^^^^^

Operators are used to connect primitives or terms to form terms. The syntactic
functionallity Rucio offers to form terms are the basic operations defined in
mathematical set theory (Unions, Intersections and Complements). Using an
operator on two sets of RSEs (as specified by a primitive or term) will
construct a new set based on the given sets.


The symbols *A* and *B* in this table stand for either a primitive element or a
term.

========  ==========  ==============  =========================
Operator  Meaning     Interpretation  Example
========  ==========  ==============  =========================
A|B       UNION       A union B       CERN_DATADISK | CERN_TAPE
A&B       INTERSECT   A intersect B   T1&country=de
A\\B      COMPLEMENT  A complement B  T1\\BNL
========  ==========  ==============  =========================

^^^^^^^^^^^^^^^^^^^
Order of Operations
^^^^^^^^^^^^^^^^^^^

The expression is generally evaluated from left to right. Parantheses can be used to specify the order of operations.

^^^^^^^^
Examples
^^^^^^^^

These examples, off course, depend on the attributes and tags defined in Rucio, but for the sake of this example we assume that the respective tags and attributes are defined. Users can use the ``$ rucio-admin rse get-attribute UKI-LT2-QMUL_DATADISK`` command to get the attributes definied for a RSE.

"""""""""
Example 1
"""""""""

*I want to have 2 replicas on Tier 1 RSEs*

**Replication factor**: 2

**Rule expression**: T1

"""""""""
Example 2
"""""""""

*I want to have 2 replicas on T2 RSEs in the UK but it shouldn't be Glasgow*

**Replication factor**: 2

**Rule expression**: country=uk&T2\\GLASGOW

"""""""""
Example 3
"""""""""

*I want to have 4 replicas on CERN or any RSE in the US but it shouldn't be a T3*

**Replication factor**: 4

**Rule expression**: (CERN|country=US)\\T3
