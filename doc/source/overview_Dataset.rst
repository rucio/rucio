-------
Dataset
-------

ATLAS has a large amount of data, which is physically stored in files. The actual distribution of 
the data over files is mostly incidental. The data consists usually, but not exclusively, 
of persistent C++ objects associated with physics events.
Physicists need to be able to identify and operate on any arbitrary subset of this data: a dataset.
Hence, a dataset might be a single file or multiple files [#f1]_.

Datasets may be overlapping in the sense that a subset of data, i.e. a single file or more files, can be part of multiple datasets. 

New datasets can be defined based on the contents of existing datasets. In particular, it is possible to aggregate the contents of two or more datasets into a new one by taking the set union of their respective contents. While successive aggregations will implicitly create an aggregation hierarchy, this is not reflected in the naming of the datasets. Instead Rucio will merely record in the dataset metadata that it was created by performing such a union. Otherwise the dataset will be identical to one created by simple enumeration of the resulting contents, i.e. the corresponding files. 


**********************************
Dataset/file identifiers and scope
**********************************

To be able to unambiguously refer to a logical file it needs to have an identifier. 
For a logical file this is the Logical File Name (LFN) which is composed of two strings: the scope identifier and the file label [#f2]_. 
A single file is a dataset in itself and as such dataset identifiers follow the same scheme: Each dataset is identified by the Dataset 
Name (DSN) which is composed by the scope identifier and the dataset label.

The scope identifier partitions the dataset name space in several sub spaces. The primary use case for this is to have separate scopes for production and the individual users. There is a one to one relationship between account and scope.  There are no particular constraints on the strings used for both scope and labels other than a restricted set of allowed characters. In particular, it should be possible to use Universally Unique Identifiers (UUIDs) as labels.

Datasets/files are uniquely identified over all time. A DSN/LFN once used to refer to a dataset/file can never be reused to refer to another dataset/file, not even if the former has become obsolete or deleted from the system.  


****************
Dataset statuses
****************

The dataset status is reflected by a set of attributes. Datasets in Rucio can have the following attributes: 

* ``Open``: True/False

A dataset might be a result of more than one computational process, therefore the definition of a dataset is not an atomic operation. The operation can even spread out over a large amount of time. For this purpose, a dataset has an open status to publish its availability, i.e. to reflect that its content is (not) complete. Open datasets can not be used in aggregations. When the filling of the dataset is done, its state changes to closed and can thereafter not be re-opened.

* ``Monotonic``: True/False

If the monotonic mode is enabled files cannot be removed from an open dataset. 

* ``Hidden``: True/False

Datasets can be hidden so they do not show up in normal listing operations.

* ``Obsolete``: True/False

The obsolete status means that a dataset and its definition should not be used anymore.

* ``Complete``: True/False

The data a file points to can be temporarily or permanently lost, e.g. the system has lost all corresponding physical files. This is reflected in the lost status of the file and by the complete/incomplete status of all aggregate datasets containing them. The file content can be recovered and re-injected in the system causing the corresponding lost and complete/incomplete statuses to be updated.

There is no concept of dataset versioning. The loss of files is simply recorded as described  above with a single flag, hence not recording in what order they were lost. Adding further files requires the definition of a new dataset with a new identifier. The latter dataset might reflect the relation with the former, but this is not required.

.. rubric:: Footnotes

.. [#f1] A dataset might be also a part of a file or a parts of multiple files, e.g. a so-called event collection. 
.. [#f2] A part of a file can be identified by an LFN and a sub-file identifier. The latter is a string and its interpretation depends on the nature of the file, e.g. event files might use an event number, or binary files might use an offset/size pair.


