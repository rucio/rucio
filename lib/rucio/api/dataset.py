# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the
# License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2011
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2011


def add_dataset(scope, dsn, content=None, dataset_meta=None):
        """
        Creates a dataset and register its constituents.

        :param scope:   The scope name.
        :param dsn:     The dataset name.
        :param content: A list of files or datasets. If "None" an empty dataset is generated which is deleted after 30 days if nothing is added to it.
        :param dataset_meta: A dictionnary with the meta-data information about the dataset.
        :returns: If the operation is successful a response code of "0" is returned. If an error occurs, a non zero response code is returned.
        """
        pass


def add_to_dataset(dsn, contents):
        """
        Addes files or other datasets to the specified "dsn" dataset. This specified dataset must be open.

        :param dsn: The target dataset which the user wants to add to.
        :param contents: The datasets/files that will be added to the target dataset.
        :returns: If the operation is successful a response code of "0" is returned. If an error occurs, a non zero response code is returned.
        """
        pass


def close_dataset(scope, dsn):
        """
        Closes a dataset. No more files can be added to this dataset.

        :param scope: The scope name.
        :param dsn: The dataset name.
        :returns: If the operation is successful a response code of "0" is returned. If an error occurs, a non zero response code is returned.
        """
        pass


def obsolete_dataset(dsn):
        """
        Sets dataset as obsolete. Dataset name is hidden by default. All replicas and data on the grid referenced by this dataset is deleted if not referenced by other datasets. An obsolete's dataset's name cannot be used in the future.

        :param dsn: The dataset to be obsolete.
        :returns: If the operation is successful a response code of "0" is returned. If an error occurs, a non zero response code is returned.
        """
        pass


def set_hidden_dataset(dsn, state=True):
        """
        Changes dataset hidden state. Hidden dataset will not be listed by user commands unless explicitly asked for or "--hidden" option is specified.

        :param dsn: The dataset to be hidden
        :parm state: Hidden state, True/False
        :returns: If the operation is successful a response code of "0" is returned. If an error occurs, a non zero response code is returned.
        """
        pass


def return_random_datasets(num):
        """
        Returns a random dataset. This is used for testing.

        :parm num: Number of datasets to return
        :returns: Returns a random dataset name as a list of tuple [(scope1, dataset1),(scope2,dataset2),...]
        """

        if not isinstance(num, int) or not num:
            raise TypeError

        # Temporary dummy code, this should be replaced with database select, when schema is operational
        from uuid import uuid4 as uuid
        return [(str(uuid()), str(uuid())) for i in range(num)]
