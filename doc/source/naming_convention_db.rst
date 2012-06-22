================================================
Naming convention for the Rucio database objects
================================================

All names must not be enclosed in quotes so that Oracle stores them in upper case in the data dictionary.

--------------------------------------------------------------------------------
The Primary Key constraints (which would mean its index will have the same name)
--------------------------------------------------------------------------------

name = TABLE_NAME || COLUMN_NAME(s) ||'_PK'

--------------------------
The Unique constraint name
--------------------------

name = TABLE_NAME || COLUMN_NAME(s) ||'_UQ'

--------------------
Not Null constraints
--------------------

name =  TABLE_NAME || COLUMN_NAME || '_NN'

Note: This needs to be checked with sqlalchemy

------------
Foreign Keys
------------

name = TABLE_NAME || COLUMN_NAME(s) || '_FK'

--------------
Normal indexes
--------------

name =  TABLE_NAME || COLUMN_NAME(s) || '_IDX'

---------
Sequences
---------

name =  TABLE_NAME || COLUMN_NAME || '_SEQ'

----------------
Constraint types
----------------

name =  TABLE_NAME || COLUMN_NAME || '_CHK'

