# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012

from json import dumps
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.common.utils import build_url


class DatasetClient(BaseClient):

    """Dataset client class for working with rucio datasets"""

    BASEURL = 'datasets'

    def __init__(self, host, port=None, account=None, use_ssl=True, ca_cert=None, auth_type=None, creds=None):
        super(DatasetClient, self).__init__(host, port, account, use_ssl, ca_cert, auth_type, creds)

    def add_dataset(self, scope, datasetName, monotonic=None):
        """
        Sends the request to add a new dataset.

        :param scope: the scope name.
        :param datasetName: the dataset name.
        :param monotonic:
        :raise ScopeNotFound: the scope does not exist.
        :raise AccountNotFound: the account does not exist.
        :raise DatasetAlreadyExists: the dataset is already registerd in the system.
        :raise FileAlreadyExists: the file is already registered in the system.
        :raise RucioException: unknown error.
        :returns: True is dataset is successfully registered.
        """

        path = '/'.join([self.BASEURL, scope])
        url = build_url(self.host, path=path, use_ssl=self.use_ssl)
        data = dumps({'datasetName': datasetName, 'monotonic': monotonic})

        r = self._send_request(url, data=data, type='POST')

        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def obsolete_dataset(self, scope, datasetName):
        """
        Sends the request to obsolete a dataset.

        :param scope: the scope of the dataset.
        :param datasetName: the name of the dataset.
        :raise ScopeNotFound: scope does not exist.
        :raise DatasetObsolete: the dataset is already obsolete.
        :raise DatasetNotFound: the dataset does not exist.
        :returns: True if datasets is successfully obsoleted, False otherwise.
        """

        path = '/'.join([self.BASEURL, scope, datasetName])
        url = build_url(self.host, path=path, use_ssl=self.use_ssl)

        r = self._send_request(url, type='DEL')

        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def change_dataset_owner(self, scope, datasetName, newAccount):
        """
        Sends the request to change the owner of a dataset.

        :param scope: the scope of the dataset.
        :param datasetName: the name of the dataset.
        :param newAccount: the account name of the new owner.
        :raise ScopeNotFound: the scope does not exist.
        :raise AccountNotFound: the account does not exist.
        :raise DatasetObsolete: the dataset is obsolete.
        :raise DatasetNotFound: the dataset does not exist.
        :raise NoPermissions: no permissions the change the dataset.
        :returns: True if dataset owner is successfully changed, False otherwise.
        """

        path = '/'.join([self.BASEURL, scope, datasetName])
        params = {'newAccount': newAccount}
        url = build_url(self.host, path=path, use_ssl=self.use_ssl, params=params)

        r = self._send_request(url, type='PUT')

        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def dataset_exists(self, scope, datasetName, searchType=None):
        """
        Sends the request to check if a dataset exists.

        :param scope: the scope of the dataset.
        :param datasetName: the name of the dataset.
        :param searchType: the type of the search [current, obsolete, all]
        :returns: True if datasets exists, False otherwise.
        """

        path = '/'.join([self.BASEURL, scope, datasetName])
        params = {}
        if searchType:
            params = {'searchType': searchType}
        url = build_url(self.host, path=path, use_ssl=self.use_ssl, params=params)

        r = self._send_request(url, type='GET')

        print r.text
        if r.text == 'True':
            return True
        elif r.text == 'False':
            return False
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)
