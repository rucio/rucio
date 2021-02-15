Typical replica workflow
========================

This section gives an overview of what happens within Rucio, for a typical replica workflow. Two workflows are described:
When a replica is uploaded to Rucio via a client and when a replica is created by a
site to site transfer due to the creation of a `replication rule`_.


Replica paths on storage
^^^^^^^^^^^^^^^^^^^^^^^^^

Rucio has two basic paradigms in deciding the path for a replica on a specific storage system. **Deterministic** and **Non-deterministic** paths. If we assume
a file whose data identifier is ``user.jdoe:test.file.1``, thus the scope is ``user.jdoe`` and the name is ``test.file.1``. In Rucio a deterministically created path is a path
which can be generated solely knowing the scope and name of a data identifier (Ignoring the static prefix of the storage endpoint). For a non-deterministic path
additional information describing the file is necessary, such as meta-data, the dataset the file belongs to, etc.

Rucio supports pluggable algorithms for both deterministic and non-deterministic algorithms. This section explains a few of them.

Deterministic algorithm based on hashes
--------------------------------------

The hash deterministic algorithm is an algorithm commonly used in Rucio. The advantage of this algorithm is that, due to the characteristics of cryptographic hash functions,
the files are evenly distributed to directories. This can be an important characteristic for storage systems whose access performance degrades based on the number
of files in a directory.

For a data identifier, e.g. ``user.jdoe:test.file.1`` a md5-hashsum is calculated ``077c8119053bebb168d125034bff64ac``. The generated path is then based on the first four
characters of the hashsum. e.g. ``/07/7c/user.jdoe/test.file.1``.


Deterministic algorithm based on naming convention
--------------------------------------------------

If a specific naming convention is enforced on the filenames, a possible deterministic algorithm can be based on it.

For the data identifier ``user.jdoe:test.file.1`` the first part of the filename (``test``) is extracted and used to generate the path: ``/test/user.jdoe/file.1``


Non-Deterministic algorithm based on parent dataset
---------------------------------------------------

If the file is part of a dataset, e.g. ``data:dataset1234`` the dataset can be used in the path of the filename. This is useful for e.g. tape storage systems, to keep the files belonging to the same dataset on the same tape.

For the data identifier ``user.jdoe:test.file.1`` which is part of the dataset ``data:dataset1234`` the generated path is: ``/data/dataset1234/user.jdoe/test.file.1``


Replica is uploaded with the command line client
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This is a typical workflow when a user uploads multiple files, which are part of a dataset, via the command line client.

1. The dataset ``test.dataset`` is being registered at the server.
   All files, or datasets are associated to a `scope`_, if not specifically mentioned the client will assume the default scope of the user,
   such as ``user.jdoe``. Thus the full data identifier for the dataset is ``user.jdoe:test.dataset``.

2. The client queries the RSE information from the server. This not only gives a list of prioritized write protocols to use but also the information
   if the RSE is a deterministic or non-deterministic one.

3. The file replica is registered as ``COPYING`` on the RSE.

4. Based on the identified naming algorithm of the RSE and the list of prioritized write protocols, the file URL is calculated.
   e.g. using the hash algorithm from above: ``https://storageserver.organization.org/VO/data/07/7c/user.jdoe/test.file.1``

5. The file upload is done with the first prioritized protocol. If the upload fails, step 4 is repeated with the second prioritized protocol, etc.

6. Once the upload is successfully finished, the replica state is changed to ``AVAILABLE``.

7. Step 3-6 are repeated (done in parallel) with all other files part of the uploaded dataset.


Replica is created by a replication rule
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This is a typical workflow if a file already exists in Rucio but the user wants to replicate it to a different RSE.

1. The user creates a replication rule for the dataset ``user.jdoe:test.dataset`` at the server.

2. The Rucio server creates internal requests for each single file in the dataset and puts them in a queue to be read by the data transfer service.

3. The data transfer submitter picks these requests up and queries the destination RSE information for each file.

4. Based on the identified naming algorithm of the destination RSE it creates the destination URLs and creates the file replicas in ``COPYING`` state.

5. The transfer service then submits the transfer job to the connected transfer tool (e.g. FTS)

6. Once the transfers are finished the transfer tool notifies Rucio about the transfer success and the transfer services mark the replicas as ``AVAILABLE``.




.. _replication rule: overview_Replica_management.html
.. _scope: overview_File_Dataset_Container.html

