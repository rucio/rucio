# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012

from sqlalchemy.exc import IntegrityError

from rucio.common import exception
from rucio.common.config import config_get
from rucio.core.account import get_account
from rucio.core.scope import check_scope
from rucio.db import models1 as models
from rucio.db.session import get_session


def create_dataset(accountName, datasetScope, datasetName):
    """ create a new dataset.

    :param accountName: the name of the account who is creating the dataset
    :param datasetScope: the namespace where this dataset belongs
    :param datasetName: the name of the dataset to be created
    :returns: nothing
    """

    session = get_session()
    get_account(accountName)
    values = {}
    values['dsn'] = datasetName
    values['scope'] = datasetScope
    new_dataset = models.Dataset()
    new_dataset.update(values)
    session.add(new_dataset)
    try:
        session.commit()
    except IntegrityError, error:
        if error.args[0] == "(IntegrityError) foreign key constraint failed":
            if not check_scope(datasetScope):  # Maybe a valid scope does not exist
                raise exception.ScopeNotFound('Scope does not exist')
            else:
                raise exception.RucioException
        elif error.args[0] == "(IntegrityError) columns scope, dsn are not unique":
            raise exception.DatasetAlreadyExists('Dataset %s already exists in scope %s' % (datasetName, datasetScope))
        else:
            raise exception.RucioException(error.args[0])
