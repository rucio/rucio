# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne,  <vincent.garonne@cern.ch> , 2011

import os

from migrate import exceptions as versioning_exceptions
from migrate.versioning import api as versioning_api
from migrate.versioning import repository as versioning_repository

from rucio.common import exception


def get_migrate_repo_path():
    """Get the path for the migrate repository."""
    repo_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'rucio_migrate_repo')
    assert os.path.exists(repo_path)
    return repo_path


def version_control(sql_connection, version=None):
    """
    Place the database under migration control
    """
    try:
        repo_path = get_migrate_repo_path()
        if version is None:
            version = versioning_repository.Repository(repo_path).latest
        versioning_api.version_control(sql_connection, repo_path, version)
    except versioning_exceptions.DatabaseAlreadyControlledError:
        msg = "database '%(sql_connection)s' is already under migration control" % locals()
        raise exception.DatabaseMigrationError(msg)


def db_version(sql_connection):
    """
    Return the database's current migration number

    :retval version number
    """
    repo_path = get_migrate_repo_path()
    try:
        return versioning_api.db_version(sql_connection, repo_path)
    except versioning_exceptions.DatabaseNotControlledError:
        msg = "database '%(sql_connection)s' is not under migration control" % locals()
        raise exception.DatabaseMigrationError(msg)


def upgrade(sql_connection, version=None):
    """
    Upgrade the database's current migration level

    :param version: version to upgrade (defaults to latest)
    :retval version number
    """
    db_version(sql_connection)  # Ensure db is under migration control
    repo_path = get_migrate_repo_path()
    version_str = version or 'latest'
    return versioning_api.upgrade(sql_connection, repo_path, version_str)


def downgrade(sql_connection, version):
    """
    Downgrade the database's current migration level

    :param version: version to downgrade to
    :retval version number
    """
    db_version(sql_connection)  # Ensure db is under migration control
    repo_path = get_migrate_repo_path()
    return versioning_api.downgrade(sql_connection, repo_path, version)
