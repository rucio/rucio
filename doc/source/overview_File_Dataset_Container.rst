------------------------------
Files, Datasets and Containers
------------------------------

As data is physically stored in files, files are also the smallest operational unit of data in Rucio. Sub-file operations are currently not possible. Rucio enables users to identify and access on any arbitrary set of files.

Files can be grouped into datasets (a named set of files) and datasets can be grouped into containers (a named set of datasets or, recursively, containers). All three types of names refer to data so the term ‘data identifier’ (DID) is used to represent any set of file, dataset or container identifier. A data identifier is just the name of a single file, dataset or container.


**************************
Data identifiers and scope
**************************

Files, datasets and containers follow an identical naming scheme which is composed of two strings: the scope and a name. The combination of both is called a data identifier (DID). Thus for files, the Logical File Name (LFN), a term commonly used in DataGrid terminology to identify files is equivalent to the DID in Rucio.

The scope string partitions the namespace into several sub namespaces. The primary use case for this is to easily separate centrally created data from individual user data.

By default, accounts have read access to all scopes and write access only to their own scope. Privileged accounts have write access to multiple scopes, e.g., the Workload Management System is allowed to write into official data scopes.

Files, datasets and containers are uniquely identified over all time. This means that a data identifier, once used, can never be reused to refer to anything else at all, not even if the data it referred to has been deleted from the system.


**********************************
File, dataset and container status
**********************************

===========
File status
===========

The following status attributes are supported for files:

* ``availability``: LOST/DELETED/AVAILABLE

A file is LOST if there are no known replicas of the file in Rucio, while at the same time at least one account requested a replica; a file is DELETED if no account requested a replica; otherwise the file is AVAILABLE. This is a derived attribute.

* ``suppressed``: True/False

This is a user settable flag. It indicates that the owner of the scope no longer needs the name to be present in the scope. Files that are suppressed (by default) do not show up in search and list operations on the scope. Note however that this flag will be ignored when explicitly listing contents of datasets/containers.


========================
Dataset/Container status
========================


The dataset/container status is reflected by a set of attributes:


* ``open``: True/False

If a dataset/container is open, content can be added to it. Datasets/containers are created open and once closed, they cannot be opened again [#f1]_.


* ``monotonic``: True/False

If the monotonic attribute is set, content cannot be removed from an open dataset/container. Datasets/containers are, by default, created non-monotonic. Once set to monotonic, this cannot be reversed.

* ``complete``: True/False

A dataset/container where all files have replicas available is complete. Any dataset/container which contains files without replicas is incomplete. This is a derived attribute.


.. rubric:: Footnotes

.. [#f1] Datasets from which files have been lost can be repaired when replacement files are available, even if Open=False. The replacements need not be binary identical to the lost files.