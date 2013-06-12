**************
Data deletion
**************

Replica data model:

* rse_id: The rse identifier
* scope: The scope name of the file
* name: Filename
* state: Replica state (AVAILABLE, UNAVAILABLE, COPYING, BEING_DELETED, BAD)
* lock_cnt: Counter of the nr of locks
* created_at: Creation date of the replica1
* accessed_at: Last access time of the replica (null for the moment)
* tombstone: Date of the last lock removal (null otherwise) (Maintained in the rule core part.)

^^^^^^^^^^^^^
Reaper daemon
^^^^^^^^^^^^^

Parameters:

* MinFreeSpace: Minimun free space(in bytes) which should be available at a RSE.
* MaxBeingDeletedFiles: Maximum number of files beeing deleted for a RSE.

For each RSE, The reaper checks the available free space.
If the available free space is less than a limit defined per RSE(MinFreeSpace), a cleanup cycle is triggered.
The reaper selects (MinFreeSpace - ActualFreeSpace) bytes of files and then deletes them.
Replicas of any file which is declared obsolete are immediately deleted. Those files are marked with a tombstone
set to the epoch value (January 1, 1970).

Pseudo-code:

.. code-block:: none
    :linenos:

    For each RSE in RSEs:
        Check rse free space # Explanation below
        replicas = list_unlocked_and_obsolete_replicas (MinFreeSpace - ActualFreeSpace)
        # Gives n replicas corresponding to the amount of bytes to free up or all obsolete ones
        # The list is ordered by created_at and tombstone.
        for each replica in replicas:
            status = Mark the replica state as BEING_DELETED
                # Update conditions: where lock_cnt=0 and tombstone is not null
                # Rules should not select replicas in the state BEING_DELETED
            if status:
                    status = Delete file from RSE
                    if status:
                Remove file from replica table
    freed_space += filesize

