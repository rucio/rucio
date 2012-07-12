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

    BASEURL = 'datasets/'

    def __init__(self, host, port=None, account=None, use_ssl=True, ca_cert=None, auth_type=None, creds=None):
        super(DatasetClient, self).__init__(host, port, account, use_ssl, ca_cert, auth_type, creds)

    def add_dataset(self, scope, datasetName, monotonic=None):
        """
        Sends the request to add a new dataset.

        :param scope: The scope name.
        :param datasetName: the dataset name.
        :param monotonic:
        :raise ScopeNotFound: the scope doesn't exist.
        :raise AccountNotFound: the account doesn't exist.
        :raise DatasetAlreadyExists: the dataset is already registerd in the system.
        :raise FileAlreadyExists: the file is already registered in the system.
        :raise RucioException: unknown error.
        :returns: True is dataset is successfully registered.
        """

        path = self.BASEURL + scope
        url = build_url(self.host, path=path, use_ssl=self.use_ssl)
        data = dumps({'datasetName': datasetName, 'monotonic': monotonic})

        r = self._send_request(url, data=data, type='POST')

        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)
