# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2016
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2016

import json
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.common.utils import build_url


class ObjectStoreClient(BaseClient):
    """Replica client class for working with replicas"""

    OBJECTSTORE_BASEURL = 'objectstores'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None, user_agent='rucio-clients'):
        super(ObjectStoreClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout, user_agent)

    def connect(self, rse, url):
        """
        :param rse: RSE name.
        :param url: URL string.

        :returns: OK.
        """
        url = build_url(self.host, path='/'.join([self.OBJECTSTORE_BASEURL, url, rse, 'connect']))
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return

        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def get_signed_url(self, url, rse, operation='read'):
        """
        :param url: URL string.
        :param rse: RSE name.

        :returns: A signed URL refering to the file.
        """
        url = build_url(self.host, path='/'.join([self.OBJECTSTORE_BASEURL, url, rse, operation]))
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return r.text

        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def get_signed_urls(self, urls, rse, operation='read'):
        """
        :param ruls: List of URLs.
        :param rse: RSE name.

        :returns: URL dictionaries refering to the files.
        """
        url = build_url(self.host, path='/'.join([self.OBJECTSTORE_BASEURL, rse, operation]))
        headers = {}
        r = self._send_request(url, headers=headers, type='POST', data=json.dumps(urls))

        if r.status_code == codes.ok:
            return json.loads(r.text)

        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def get_metadata(self, urls, rse):
        """
        :param ruls: List of URLs.
        :param rse: RSE name.

        :returns: Dictionary of metadata refering to the files.
        """
        url = build_url(self.host, path='/'.join([self.OBJECTSTORE_BASEURL, 'info', rse]))
        headers = {}
        r = self._send_request(url, headers=headers, type='POST', data=json.dumps(urls))

        if r.status_code == codes.ok:
            return json.loads(r.text)

        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def rename(self, pfn, new_pfn, rse):
        """
        :param rul: URL string.
        :param new_rul: URL string.
        :param rse: RSE name.

        :returns: Dictionary of metadata refering to the files.
        """
        url = build_url(self.host, path='/'.join([self.OBJECTSTORE_BASEURL, 'rename', rse]))
        headers = {}
        urls = {'url': pfn, 'new_url': new_pfn}
        r = self._send_request(url, headers=headers, type='POST', data=json.dumps(urls))

        if r.status_code == codes.ok:
            return

        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)
