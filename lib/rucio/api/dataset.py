# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the
# License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2011
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2011-2012

from rucio.core.inode import change_dataset_owner as core_change_dataset_owner
from rucio.core.inode import obsolete_dataset as core_obsolete_dataset
from rucio.core.inode import does_dataset_exist, register_dataset


def add_dataset(scope, dsn, account, monotonic=None, content=None, dataset_meta=None):
    """
    Creates a dataset. Optionally it can register its constituents.

    :param scope:   The scope name.
    :param dsn:     The dataset name.
    :param account: The account registering the dataset
    :param content: A list of files or datasets. If "None"
                        an empty dataset is generated which is
                        deleted after 30 days if nothing is added to it.
    :param dataset_meta: A dictionnary with the meta-data information about the dataset.
    :raise ScopeNotFound: specified scope does not exist
    :raise AccountNotFound: specified account does not exist
    :raise DatasetNotFound: specified dataset does not exist in specified scope
    :raise NotADataset: specified dataset is actually a file
    :raise DatasetObsolete: specified dataset is obsolete
    :raise NoPermissions: specified account is not the owner of the dataset
    """
    if content is None and dataset_meta is None:
        register_dataset(scope, dsn, account, monotonic)
    elif content is not None:
        raise NotImplementedError  # TODO: A new register_dataset core is needed that combines ops in a single transaction
    else:
        raise NotImplementedError  # TODO: Needs metadata core component in place


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


def obsolete_dataset(scope, dsn, account):
    """
    Sets dataset as obsolete. Dataset name is hidden by default. An obsolete's dataset's name cannot be used in the future.

    :param scope: The scope of the dataset to be made obsolete
    :param dsn: The dataset to be made obsolete
    :raise DatasetObsolete: dataset is already obsolete
    """
    core_obsolete_dataset(scope, dsn, account)


def set_hidden_dataset(dsn, state=True):
    """
    Changes dataset hidden state. Hidden dataset will not be listed by user commands unless explicitly asked for or "--hidden" option is specified.

    :param dsn: The dataset to be hidden
    :param state: Hidden state, True/False
    :returns: If the operation is successful a response code of "0" is returned. If an error occurs, a non zero response code is returned.
    """
    pass


def change_dataset_owner(datasetScope, datasetName, oldAccount, newAccount):
    """
    Changes a dataset's owner.

    :param datasetScope: the scope of the dataset
    :param datasetName: the name of the dataset
    :param oldAccount: the owner of the dataset
    :param newAccount: the new owner of the dataset
    :raise ScopeNotFound: specified scope does not exist
    :raise AccountNotFound: specified account does not exist
    :raise DatasetNotFound: specified dataset does not exist in specified scope
    :raise NotADataset: specified dataset is actually a file
    :raise DatasetObsolete: specified dataset is obsolete
    :raise NoPermissions: specified account is not the owner of the dataset
    """

    core_change_dataset_owner(datasetScope, datasetName, oldAccount, newAccount)


def dataset_exists(datasetScope, datasetName, accountName, search_obsolete=False):
    """
    Checks to see if dataset exists.

    :param datasetScope: the scope of the dataset. This parameter does not do wildcard searches.
    :param datasetName: the name of the dataset. This parameter does not do wildcard searches.
    :param accountName: the account searching for the dataset.
    """

    return does_dataset_exist(datasetScope, datasetName, accountName, search_obsolete)
