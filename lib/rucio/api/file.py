# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the
# License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2011

from rucio.core.name import list_file_replicas as core_list_file_replicas


def list_file_replicas(scope, lfn):
    """
        List file replicas.
        :param scope: The scope of the file
        :param lfn: The name of the file

    """
    return core_list_file_replicas(scope=scope, lfn=lfn)
