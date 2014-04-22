--------------------
Meta-data attributes
--------------------


Meta-data associated with a dataset/file is represented using attribute/value pairs. 
The set of available attributes is restricted. Meta-data attributes are classified into four categories:

* ``System-defined attributes``: e.g. size, checksum, creationtime, modificationtime, status

* ``Physics attributes``: e.g. like number of events, cross-section, or GUID

* ``Production attributes``: storing information like which task or job produced the file

* ``Data management attributes``: necessary for the organisation of data on the grid (see Replica Management section)

For datasets, it is possible that the value of a meta-data attribute 
is a function of the meta-data of its constituents, e.g. the total size is 
the sum of the sizes of the constituents. In this case it is obviously not possible to assign a value to it.
