------------------------------
Files, Datasets and Containers
------------------------------

ATLAS has a large amount of data, which is physically stored in files. For the data management system these files are the smallest operational unit of data (so sub-file operations are not possible). Physicists need to be able to identify and operate on any arbitrary set of files.

Files can be grouped into datasets (a named set of files) and datasets can be grouped into containers (a named set of datasets or, recursively, containers). All three types of names refer to data so the term ‘data identifier set’ (DIS) is used to mean any set of file, dataset or container identifiers. A data identifier is just the name of a single file, dataset or container.

The figure below gives an example of an aggregation hierarchy:


**************************
Data identifiers and scope
**************************

Files, datasets and containers follow an identical naming scheme which is composed of two strings: the scope and a name. The combination of both is called a data identifier (DI). For instance a file identifier (LFN) is composed of a scope and a file name.

The scope string partitions the name space in several sub spaces. The primary use case for this is to have separate scopes for production and individual users.

By default accounts will have read access to all scopes and write access only to their own scope. Privileged accounts will have write access to multiple scopes, e.g., production might use scopes such as mc11, data12_8TeV, tmp.prod.#

Files, datasets and containers are uniquely identified over all time. This implies that an identifier, once used, can never be reused to refer to anything else at all, not even if the data it referred to has been deleted from the system.


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

This is a user settable flag. It indicates that the owner of the scope no longer needs the name to be present in the scope. Files that are suppressed (by default) do not show up in search and list operations on the scope. The setting of this flag is subject to conditions, e.g., one can not suppress a file while at the same time requesting it to be replicated somewhere.

Note however that this flag will be ignored when explicitly listing contents of datasets/containers.


========================
Dataset/Container status
========================


The dataset/container status is reflected by a set of attributes:


* ``open``: True/False

If a dataset/container is open, content can be added to it. Datasets/Containers  are created open and once closed, they cannot be opened again.[2]_.


* ``monotonic``: True/False

If the monotonic attribute is set, content cannot be removed from an open dataset/container. Datasets/Containers are, by default, created non-monotonic. Once set to monotonic, this cannot be reversed.

* ``complete``: True/False

A dataset/container where all files have replicas available is complete. Any dataset/container which contains files without replicas is incomplete. This is a derived attribute.


.. rubric:: Footnotes

.. [#f1] A dataset might be also a part of a file or a parts of multiple files, e.g. a so-called event collection.
.. [2] Datasets from which files have been lost can be repaired when replacement files are available, even if Open=False. The replacements need not be binary identical to the lost files.

