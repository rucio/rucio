#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Angelos Molfetas, <angelos.molfetas@cern.ch>, 2012
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012

from json import loads
from logging import getLogger, StreamHandler, DEBUG
from web import application, ctx, data, header, input as web_input, websafe, Created, InternalError, HTTPError, OK, Unauthorized

from rucio.api.dataset import add_dataset, change_dataset_owner, dataset_exists, obsolete_dataset
from rucio.core.authentication import validate_auth_token
from rucio.common.exception import AccountNotFound, DatasetAlreadyExists, DatasetNotFound, DatasetObsolete, FileAlreadyExists, NoPermissions, NotADataset, ScopeNotFound
from rucio.common.utils import generate_http_error

logger = getLogger("rucio.rest")
sh = StreamHandler()
sh.setLevel(DEBUG)
logger.addHandler(sh)

urls = (
    '/(.*)/(.*)', 'Dataset2Parameter',
    '/(.*)', 'Dataset1Parameter'
)


class Dataset1Parameter:

    def POST(self, scope):
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

        header('Content-Type', 'application/octet-stream')
        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        json_data = data()

        try:
            parameter = loads(json_data)
        except ValueError:
            raise generate_http_error(400, 'ValueError', 'cannot decode json parameter dictionary')

        datasetName = None
        monotonic_parameter = None

        try:
            datasetName = parameter['datasetName']
            monotonic_parameter = parameter['datasetType']
        except KeyError, e:
            if e.args[0] == 'datasetName':
                raise generate_http_error(400, 'KeyError', "\'datasetName\' not defined")
        except TypeError:
            raise generate_http_error(400, 'TypeError', 'body must be a json dictionary')

        if monotonic_parameter == 'monotonic':
            monotonic = True
        elif monotonic_parameter == 'non-monotonic' or monotonic_parameter is None:
            monotonic = False
        else:
            raise generate_http_error(400, 'InputValidationError', 'dataset type parameter is not properly defined')

        auth = validate_auth_token(auth_token)
        if auth is None:
            raise Unauthorized()

        auth_account = auth[0]

        try:
            add_dataset(scope, datasetName, auth_account, monotonic=monotonic)
        except ScopeNotFound, error:
            raise generate_http_error(404, 'ScopeNotFound', error.args[0][0])
        except AccountNotFound, error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0][0])
        except DatasetAlreadyExists, error:
            raise generate_http_error(409, 'DatasetAlreadyExists', error.args[0][0])
        except FileAlreadyExists, error:
            raise generate_http_error(409, 'FileAlreadyExists', error.args[0][0])
        except Exception, error:
            raise InternalError(error.args[0])
        return Created()


class Dataset2Parameter:

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

        header('Content-Type', 'application/octet-stream')
        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')
        auth = validate_auth_token(auth_token)
        if auth is None:
            raise Unauthorized()
        auth_account = auth[0]

        try:
            obsolete_dataset(scope, datasetName, auth_account)
        except ScopeNotFound, error:
            raise generate_http_error(404, 'ScopeNotFound', error.args[0][0])
        except AccountNotFound, error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0][0])
        except DatasetObsolete, error:
            raise generate_http_error(404, 'DatasetObsolete', error.args[0][0])
        except FileAlreadyExists, error:
            raise generate_http_error(409, 'FileAlreadyExists', error.args[0][0])
        except DatasetNotFound, error:
            raise generate_http_error(404, 'DatasetNotFound', error.args[0][0])
        except NotADataset, error:
            raise generate_http_error(404, 'NotADataset', error.args[0][0])
        except Exception, error:
            raise InternalError(error.args[0])
        return OK()

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

        header('Content-Type', 'application/octet-stream')
        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        params = web_input(newAccount=None)
        new_account = websafe(params.newAccount)

        if not len(new_account):
            new_account = None
        if new_account is None:
            raise HTTPError("400 Bad request", {}, "InputValidationError: search type parameter is not properly defined")

        auth = validate_auth_token(auth_token)
        if auth is None:
            raise Unauthorized()
        auth_account = auth[0]

        try:
            change_dataset_owner(scope, datasetName, auth_account, new_account)
        except ScopeNotFound, error:
            raise generate_http_error(404, 'ScopeNotFound', error.args[0][0])
        except AccountNotFound, error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0][0])
        except DatasetObsolete, error:
            raise generate_http_error(404, 'DatasetObsolete', error.args[0][0])
        except DatasetNotFound, error:
            raise generate_http_error(404, 'DatasetNotFound', error.args[0][0])
        except NotADataset, error:
            raise generate_http_error(404, 'NotADataset', error.args[0][0])
        except NoPermissions, error:
            raise generate_http_error(401, 'NoPermissions', error.args[0][0])
        except Exception, error:
            raise InternalError(error.args[0])
        return OK()

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

        header('Content-Type', 'application/octet-stream')
        auth_token = ctx.env.get('HTTP_RUCIO_AUTH_TOKEN')

        params = web_input(searchType=None)
        search_type = websafe(params.searchType)
        if not len(search_type):
            search_type = None
        if search_type not in ('current', 'obsolete', 'all', None):
            raise HTTPError("400 Bad request", {}, "InputValidationError: search type parameter is not properly defined")
        if search_type is not None:
            search_type = search_type.lower()

        auth = validate_auth_token(auth_token)
        if auth is None:
            raise Unauthorized()
        auth_account = auth[0]

        try:
            if search_type is None:
                return dataset_exists(scope, datasetName, auth_account, search_obsolete=False)
            elif search_type == 'current':
                return dataset_exists(scope, datasetName, auth_account, search_obsolete=False)
            elif search_type == 'obsolete':
                return dataset_exists(scope, datasetName, auth_account, search_obsolete=True)
            elif search_type == 'all':
                return dataset_exists(scope, datasetName, auth_account, search_obsolete=None)
        except AccountNotFound, error:
            raise generate_http_error(404, 'AccountNotFound', error.args[0][0])
        except Exception, error:
            raise InternalError(error.args[0])


"""----------------------
   Web service startup
----------------------"""

app = application(urls, globals())
application = app.wsgifunc()
