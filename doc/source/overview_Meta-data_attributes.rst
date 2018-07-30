--------------------
Meta-data attributes
--------------------


Meta-data associated with a dataset/file is represented using attribute/value pairs. 
Meta-data attributes are classified into four categories:

* ``System-defined attributes``: size (bytes), checksums (adler32, md5), creationtime, modificationtime, status, length (datasets/containers)

* ``Physics attributes``: GUID, number of events, project, datatype, run_number, stream_name, prod_step, version, campaign, lumiblocknr

* ``Workflow management attributes``: storing information like which task (task_id) or job (panda_id) produced the file

* ``Data management attributes``: necessary for the organisation of data on the grid (see Replica Management section)

For datasets, it is possible that the value of a meta-data attribute 
is a function of the meta-data of its constituents, e.g. the total size is 
the sum of the sizes of the constituents. In this case it is not possible to assign a value to it.
