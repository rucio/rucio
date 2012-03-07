------------------------
Subscriptions / Policies
------------------------

Rucio Subscriptions / Policies (name **TBD**) exist for the purpose of making data
placement decisions before the actual data has been created. In the current
DQ\ :sub:`2` \ system there are basically 3 applications which are responsible
for this behavior:

* DaTRI
* SantaClaus
* AK47

Short application descriptions
==============================

DaTRI
-----

See https://twiki.cern.ch/twiki/bin/viewauth/Atlas/DataTransferRequestInterface

DaTRI is a data-transfer tool which basically offers two functionalities:

* Transfers of existing data to a site X
* Transfer-Subscriptions of non-existing data, which match a certain pattern to a site X

Data is identified by dataset-names, patterns, container-names or
patterns. Requests can either finish after a transfer is complete or stay active
to look for newly-created data (which match a request pattern) to continously
transfer the data to a site.

All requests (there are exceptions) have to be approved by either a DaTRI admin
or a cloud coordinator.

There also exists a website which shows the status of all requests.

SantaClaus
----------

**TODO**

AK47
====

**TODO**


Workflow
========

In order to represent all (or most) of this functonality in Rucio in a generic
way, the respective steps of the workflow of the current applications have to be
identified and described. At the moment we spotted three fundamental steps for all
the applications which should be described in the following section.

* **Input Selection**: How is the input data selected? (Patterns on files/ds? etc.)
* **Destination Selection**: How is the destination selected?
* **Output Generation**: What are the characteristics of the output generation (source dataset just moved, subset of dataset moved into new dataset, etc.)?

DaTRI
-----

Input Selection
^^^^^^^^^^^^^^^
Based on:

* Pattern: Either a full datasetname, dataset pattern, containername or containerpattern
* Type: Data type of the dataset (e.g.: DESDM_EGAMMA, EVGEN)

Destination Selection
^^^^^^^^^^^^^^^^^^^^^
Specific destination endpoint; However, based on the endpoint the request has to be **approved** by an admin or cloud coordinator.

Output Generation
^^^^^^^^^^^^^^^^^

The output generation can be based on:

* Volume: The user selects a percentage of the original data
* Files List: File names or File name patterns
* Both volume and file list

SantaClaus
----------

Input Selection
^^^^^^^^^^^^^^^

**TODO**

Destination Selection
^^^^^^^^^^^^^^^^^^^^^

**TODO**

Output Generation
^^^^^^^^^^^^^^^^^

**TODO**

AK47
----

Input Selection
^^^^^^^^^^^^^^^

**TODO**

Destination Selection
^^^^^^^^^^^^^^^^^^^^^

**TODO**

Output Generation
^^^^^^^^^^^^^^^^^

**TODO**
