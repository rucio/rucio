---------------------
Rucio Storage Element
---------------------

A Rucio Storage Element (RSE) is a container for physical files. It is
the smallest unit of storage space addressable within Rucio. It has an
unique identifier and a set of meta attributes describing properties
such as supported protocols, e.g., file, https, srm; host/port
address; quality of service; storage type, e.g., disk, tape, ...;
physical space properties, e.g., used, available, non-pledged; and geographical zone.

Rucio Storage Elements can be grouped in many logical ways, e.g., the
UK RSEs, the Tier-1 RSEs, or the `good' RSEs. One can reference groups of
RSEs by metadata attributes or by explicit enumeration of RSEs.

RSE tags are expanded at transfer time to enumerate target
sites. Post-facto changes to the sites in an RSE tag list will not
affect currently replicated files.



