'''
  Copyright European Organization for Nuclear Research (CERN)
  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Cedric Serfon, <cedric.serfon@cern.ch>, 2017
'''

from json import loads
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url, render_json


class LifetimeClient(BaseClient):

    """Lifetime client class for working with Lifetime Model exceptions"""

    LIFETIME_BASEURL = 'lifetime_exceptions'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None, user_agent='rucio-clients'):
        super(LifetimeClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout, user_agent)

    def list_exceptions(self, exception_id=None, states=None):
        """
        List exceptions to Lifetime Model.

        :param id:         The id of the exception
        :param states:     The states to filter
        """

        path = self.LIFETIME_BASEURL + '/'
        params = {}
        if exception_id:
            params['exception_id'] = exception_id
        if states:
            params['states'] = exception_id
        url = build_url(choice(self.list_hosts), path=path, params=params)

        result = self._send_request(url)
        if result.status_code == codes.ok:
            lifetime_exceptions = self._load_json_data(result)
            return lifetime_exceptions
        else:
            exc_cls, exc_msg = self._get_exception(headers=result.headers, status_code=result.status_code)
            raise exc_cls(exc_msg)

    def add_exception(self, dids, account, pattern, comments, expires_at):
        """
        Add exceptions to Lifetime Model.

        :param dids:        The list of dids
        :param account:     The account of the requester.
        :param pattern:     The account.
        :param comments:    The comments associated to the exception.
        :param expires_at:  The expiration date of the exception.

        returns:            The id of the exception.
        """
        path = self.LIFETIME_BASEURL + '/'
        url = build_url(choice(self.list_hosts), path=path)
        data = {'dids': dids, 'account': account, 'pattern': pattern, 'comments': comments, 'expires_at': expires_at}
        print render_json(**data)
        result = self._send_request(url, type='POST', data=render_json(**data))
        print result.text
        if result.status_code == codes.created:
            return loads(result.text)
        exc_cls, exc_msg = self._get_exception(headers=result.headers, status_code=result.status_code, data=result.content)
        raise exc_cls(exc_msg)
