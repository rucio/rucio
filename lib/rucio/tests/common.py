# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012


def return_random_datasets(num):
        """
        Returns one or more random datasets. This is used for testing.

        :parm num: Number of datasets to return
        :returns: Returns a random dataset name as a list of tuple [(scope1, dataset1),(scope2,dataset2),...]
        """

        if not isinstance(num, int) or not num:
            raise TypeError

        # Temporary dummy code, this should be replaced with database select, when schema is operational
        from uuid import uuid4 as uuid
        return [(str(uuid()), str(uuid())) for i in range(num)]
