---------------------
Rucio Storage Element
---------------------

A Rucio Storage Element (RSE) is a container for physical files. It is the smallest unit of storage space addressable within Rucio. It has an unique identifier and a set of meta attributes describing properties such as supported protocols like file//: or http(s)//:, host/port address, quality of service, storage type (disk, tape, …), available space, used space, (non) pledge, or geographical zone.

Rucio Storage Elements can be grouped in many logical ways, e.g. the UK RSEs, the T1 RSEs, or the ‘good’ RSEs. One can reference groups of RSEs by meta-data attributes or by explicit enumeration of RSEs.

******************
Physical File Name
******************

The Physical File Name (PFN) is a fully qualified name identifying a replica of a file. PFNs may take the form of file names, URIs, or any other identifier meaningful to a Rucio Storage Element. The mapping between the LFN and the PFN is a deterministic function (LFN_to_PFN). 

Normally the upload to an RSE and the registration of an additional replica is an atomic operation. For trusted users like the T0 and PanDA production systems, it is possible to register a replica uploaded independently.
