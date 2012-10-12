# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the
# License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2011

from rucio.core import identifier as identifier_core


def list_replicas(scope, name):
    """
    List file replicas for a data_id.

    :param scope:   The scope name.
    :param dsn:     The name.

    """
    return identifier_core.list_replicas(scope=scope, name=name)


def add_identifier(scope, name, sources, issuer):
    """
    Add dataset/container

    :param scope:   The scope name.
    :param name:    The name.
    :param sources: The content.
    :param issuer: The issuer account.

    """
    return identifier_core.add_identifier(scope=scope, name=name, sources=sources, issuer=issuer)


def list_content(scope, name):
    """
    List dataset/container contents.

    :param scope:   The scope name.
    :param dsn:     The name.

    """
    return identifier_core.list_content(scope=scope, name=name)


def list_files(scope, name):
    """
    List container/dataset file contents.

    :param scope:   The scope name.
    :param dsn:     The name.

    """
    return identifier_core.list_files(scope=scope, name=name)
