Database operations
===================

Supported databases
~~~~~~~~~~~~~~~~~~~

Rucio uses `SQLAlchemy <https://www.sqlalchemy.org/>`_ as the object-relational mapper between Python and SQL. Rucio is extensively tested against SQLite, MySQL/MariaDB, PostgreSQL, and Oracle and should work with them out of the box. The appropriate connection string has to be set in the ``etc/rucio.cfg``, for example:

Oracle: ``oracle://rucio:rucio@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=localhost)(PORT=10121))(ENABLE=BROKEN)(CONNECT_DATA=(SERVICE_NAME=localhost)))``

MySQL/MariaDB: ``mysql://rucio:rucio@localhost/rucio``

PostgreSQL: ``postgresql://rucio:rucio@localhost:6601/rucio``

SQLite: ``sqlite:////tmp/rucio.db``

Please ensure correct UNIX permissions on the SQLite file, such that the webserver process can read and write to it.

Upgrading and downgrading the database schema
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Rucio uses `Alembic <http://alembic.zzzcomputing.com/en/latest/>`_ as a database migration tool, which works hand-in-hand with `SQLAlchemy <https://www.sqlalchemy.org/>`_. Ensure that the ``alembic.ini`` is set to the same database string as the ``etc/rucio.cfg`` and issue the following command to upgrade the schema:

``alembic upgrade head``

In case of problems, you can always downgrade back with

``alembic downgrade head``

If you just want to output the SQL statements of the upgrade operation, without actually applying them automatically, issue the following command:

``alembic upgrade head --sql``

Notabene, schema upgrades are reserved for feature releases and will not happen with patch releases.

Creating a new version as a developer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you want to create an upgrade path for the schema, you need to generate a schema upgrade+downgrade file:

``alembic revision -m 'schema change message'``

This will output the name of the file that has been generated with two functions ``def upgrade()`` and ``def downgrade()`` that need to be implemented. These should reflect the changes to the ``lib/rucio/db/sqla/models.py`` SQLAlchemy mapping.
