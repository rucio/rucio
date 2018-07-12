---------------------
Rucio Storage Element
---------------------

A Rucio Storage Element (RSE) is the logical abstraction of a storage system for physical files. It is the smallest unit of storage space addressable within Rucio. It has a unique identifier and a set of meta attributes describing properties such as supported protocols (https, srm, s3, ...), host/port address, quality of service, storage type (disk, tape, ...), physical space properties (used-, available-, non-pledged space), and geographical zone.

Rucio Storage Elements can be grouped in many logical ways, e.g. the UK RSEs, the Tier-1 RSEs, or the 'good' RSEs. One can reference groups of RSEs by metadata attributes or by explicit enumeration of RSEs. See the section about `RSE Expressions`_ for more information.

RSE tags are expanded at transfer time to enumerate target sites. Post-facto changes to the sites in an RSE tag list will not affect currently replicated files.


***************
Rucio Cache RSE
***************

A cache is storage service which keeps additional copies of files to reduce response time and bandwidth usage. In Rucio, a cache is an RSE, tagged as volatile. The control of the cache content is usually handled by an external process or applications (e.g. the Workflow management systems) and not by Rucio. Thus, as Rucio doesn’t control all file movements on these RSEs, the application populating the cache must register and unregister these file replicas in Rucio. The information about replica location on volatile RSEs can have a lifetime. Replicas registered on volatile RSEs are excluded from the Rucio replica management system (replication rules, quota, replication locks) described in the section Replica management. Explicit transfer requests can be made to Rucio in order to populate the cache.


.. _RSE Expressions: rse_expressions.html
