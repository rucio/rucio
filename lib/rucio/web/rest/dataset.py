#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012

import json
import logging
import web

from rucio.api.dataset import add_dataset, change_dataset_owner, dataset_exists, list_datasets, obsolete_dataset
from rucio.core.authentication import validate_auth_token
from rucio.common import exception as exception

logger = logging.getLogger("rucio.rest")
sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
logger.addHandler(sh)

urls = (
    '/dataset/(.*)/(.*)', 'Dataset',
)


class Dataset:
    """ register datasets in Rucio """

    def POST(self, scope, datasetName):
        """ register a new dataset

        :param scope: The scope of the dataset being registered
        :param datasetName: The name of the new dataset being registered
        :param Rucio-Auth-Account: Account identifier
        :param Rucio-Auth-Token: as an 32 character hex string
        :params Rucio-Account: account belonging to the new dataset
        :raise notfound: scope or account does not exist
        :raise conflict: dataset or file with the same name already exists
        :raise InternalError: dataset type parameter is not properly defined or an unknown error happened
        :raise Unauthorized: User not authorised
        :returns: (HTTP Success: 201 Created)
        """

        web.header('Content-Type', 'application/octet-stream')
        auth_account = web.ctx.env.get('HTTP_RUCIO_ACCOUNT')
        auth_token = web.ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        monotonic_parameter = web.ctx.env.get('HTTP_TYPE')
        if monotonic_parameter == 'monotonic':
            monotonic = True
        elif monotonic_parameter == 'non-monotonic' or monotonic_parameter is None:
            monotonic = False
        else:
            raise web.HTTPError("400 Bad request", {}, "InputValidationError: dataset type parameter is not properly defined")
        auth = validate_auth_token(auth_token)
        if auth is None:
            raise web.Unauthorized()
        try:
            add_dataset(scope, datasetName, auth_account, monotonic=monotonic)
        except exception.ScopeNotFound, error:
            raise web.notfound('ScopeNotFound: %s' % error.args[0])
        except exception.AccountNotFound, error:
            raise web.notfound('AccountNotFound: %s' % error.args[0])
        except exception.DatasetAlreadyExists, error:
            raise web.conflict('DatasetAlreadyExists: %s' % error.args[0])
        except exception.FileAlreadyExists, error:
            raise web.conflict('FileAlreadyExists: %s' % error.args[0])
        except Exception, error:
            raise web.InternalError(error.args[0])
        return web.Created()

    def DELETE(self, scope, datasetName):
        """ obsolete a dataset in Rucio

        :param scope: The scope of the dataset being obsoleted
        :param datasetName: The name of the dataset being obsoleted
        :param Rucio-Auth-Account: Account identifier
        :param Rucio-Auth-Token: as an 32 character hex string
        :params Rucio-Account: account obsoleting the dataset
        :raise notfound: scope or account does not exist, or dataset already obsolete
        :raise InternalError: an unknown error happened
        :raise Unauthorized: User not authorised
        :returns: (HTTP Success: 500 OK)
        """

        web.header('Content-Type', 'application/octet-stream')
        auth_account = web.ctx.env.get('HTTP_RUCIO_ACCOUNT')
        auth_token = web.ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)
        if auth is None:
            raise web.Unauthorized()
        try:
            obsolete_dataset(scope, datasetName, auth_account)
        except exception.ScopeNotFound, error:
            raise web.notfound('ScopeNotFound: %s' % error.args[0])
        except exception.AccountNotFound, error:
            raise web.notfound('AccountNotFound: %s' % error.args[0])
        except exception.DatasetObsolete, error:
            raise web.notfound('DatasetObsolete: %s' % error.args[0])
        except exception.FileAlreadyExists, error:
            raise web.conflict('FileAlreadyExists: %s' % error.args[0])
        except exception.DatasetNotFound, error:
            raise web.notfound('DatasetNotFound: %s' % error.args[0])
        except exception.NotADataset, error:
            raise web.notfound('NotADataset: %s' % error.args[0])
        except Exception, error:
            raise web.InternalError(error.args[0])
        return web.OK()

    def PUT(self, scope, datasetName):
        """ obsolete a dataset in Rucio

        :param scope: The scope of the dataset being obsoleted
        :param datasetName: The name of the dataset being obsoleted
        :param Rucio-Auth-Account: Account identifier
        :param Rucio-Auth-Token: as an 32 character hex string
        :params Rucio-Account: account obsoleting the dataset
        :raise notfound: scope, dataset, or account does not exist, or dataset already obsolete, or specified dataset is not a dataset
        :raise InternalError: an unknown error happened
        :raise Unauthorized: User not authorised
        :returns: (HTTP Success: 500 OK)
        """

        web.header('Content-Type', 'application/octet-stream')
        auth_account = web.ctx.env.get('HTTP_RUCIO_ACCOUNT')
        auth_token = web.ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        new_account = web.ctx.env.get('HTTP_NEW_ACCOUNT')
        auth = validate_auth_token(auth_token)
        if new_account is None:
            raise web.HTTPError("400 Bad request", {}, "InputValidationError: search type parameter is not properly defined")
        if auth is None:
            raise web.Unauthorized()
        try:
            change_dataset_owner(scope, datasetName, auth_account, new_account)
        except exception.ScopeNotFound, error:
            raise web.notfound('ScopeNotFound: %s' % error.args[0])
        except exception.AccountNotFound, error:
            raise web.notfound('AccountNotFound: %s' % error.args[0])
        except exception.DatasetObsolete, error:
            raise web.notfound('DatasetObsolete: %s' % error.args[0])
        except exception.DatasetNotFound, error:
            raise web.notfound('DatasetNotFound: %s' % error.args[0])
        except exception.NotADataset, error:
            raise web.notfound('NotADataset: %s' % error.args[0])
        except exception.NoPermissions, error:
            raise web.Unauthorized('NoPermissions: %s' % error.args[0])
        except Exception, error:
            raise web.InternalError(error.args[0])
        return web.OK()

    def GET(self, scope, datasetName):
        """ checks to see if dataset is registered in Rucio

        :param scope: The scope of the dataset being obsoleted
        :param datasetName: The name of the dataset being obsoleted
        :param Rucio-Auth-Account: Account identifier
        :param Rucio-Auth-Token: as an 32 character hex string
        :params Rucio-Account: account obsoleting the dataset
        :raise notfound: account does not exist
        :raise InternalError: an unknown error happened
        :raise Unauthorized: User not authorised
        :returns: HTTP Success: 500 OK), response is True if dataset exists else it is False
        """

        web.header('Content-Type', 'application/octet-stream')
        auth_account = web.ctx.env.get('HTTP_RUCIO_ACCOUNT')
        auth_token = web.ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)
        search_type = web.ctx.env.get('HTTP_SEARCH_TYPE')
        if search_type not in ('current', 'obsolete', 'all', None):
            raise web.HTTPError("400 Bad request", {}, "InputValidationError: search type parameter is not properly defined")
        if search_type is not None:
            search_type = search_type.lower()
        if auth is None:
            raise web.Unauthorized()
        try:
            if search_type is None:
                return dataset_exists(scope, datasetName, auth_account, search_obsolete=False)
            elif search_type == 'current':
                return dataset_exists(scope, datasetName, auth_account, search_obsolete=False)
            elif search_type == 'obsolete':
                return dataset_exists(scope, datasetName, auth_account, search_obsolete=True)
            elif search_type == 'all':
                return dataset_exists(scope, datasetName, auth_account, search_obsolete=None)
        except exception.AccountNotFound, error:
            raise web.notfound('AccountNotFound: %s' % error.args[0])
        except Exception, error:
            raise web.InternalError(error.args[0])

dataset_web_app = web.application(urls, globals())

"""----------------------
   Web service startup
----------------------"""

if __name__ == "__main__":
    dataset_web_app.run()
