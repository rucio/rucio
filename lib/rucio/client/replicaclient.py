# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2013
# - Cedric Serfon, <cedric.serfon@cern.ch>, 2014

from json import dumps
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url, render_json


class ReplicaClient(BaseClient):
    """Replica client class for working with replicas"""

    REPLICAS_BASEURL = 'replicas'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None):
        super(ReplicaClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout)

    def declare_bad_file_replicas(self, pfns, rse):
        """
        Declare a list of bad replicas.

        :param pfns: The list of PFNs.
        :param rse: The RSE name.
        """
        data = {'rse': rse, 'pfns': pfns}
        url = build_url(self.host, path='/'.join([self.REPLICAS_BASEURL, 'badreplicas']))
        headers = {}
        r = self._send_request(url, headers=headers, type='POST', data=dumps(data))
        if r.status_code == codes.created:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code)
        raise exc_cls(exc_msg)

    def get_did_from_pfns(self, pfns, rse):
        """
        Get the DIDs associated to a PFN on one given RSE

        :param pfns: The list of PFNs.
        :param rse: The RSE name.
        :returns: A list of dictionaries {pfn: {'scope': scope, 'name': name}}
        """
        data = {'rse': rse, 'pfns': pfns}
        url = build_url(self.host, path='/'.join([self.REPLICAS_BASEURL, 'getdidsfromreplicas']))
        headers = {}
        r = self._send_request(url, headers=headers, type='POST', data=dumps(data))
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code)
        raise exc_cls(exc_msg)

    def list_replicas(self, dids, schemes=None, unavailable=False, metalink=None):
        """
        List file replicas for a list of data identifiers (DIDs).

        :param dids: The list of data identifiers (DIDs) like :
        [{'scope': <scope1>, 'name': <name1>}, {'scope': <scope2>, 'name': <name2>}, ...]
        :param schemes: A list of schemes to filter the replicas. (e.g. file, http, ...)
        :param unavailable: Also include unavailable replicas in the list.
        :param metalink: ``None`` (default) retrieves as JSON,
                         ``3`` retrieves as metalink+xml,
                         ``4`` retrieves as metalink4+xml
        """
        data = {'dids': dids}
        if schemes:
            data['schemes'] = schemes
        if unavailable:
            data['unavailable'] = True
        url = build_url(choice(self.list_hosts), path='/'.join([self.REPLICAS_BASEURL, 'list']))

        headers = {}
        if metalink is not None:
            if metalink == 3:
                headers['Accept'] = 'application/metalink+xml'
            elif metalink == 4:
                headers['Accept'] = 'application/metalink4+xml'

        # pass json dict in querystring
        r = self._send_request(url, headers=headers, type='POST', data=dumps(data))
        if r.status_code == codes.ok:
            if not metalink:
                return self._load_json_data(r)
            return r.text
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code)
        raise exc_cls(exc_msg)

    def add_replica(self, rse, scope, name, bytes, adler32, pfn=None, md5=None, meta={}):
        """
        Add file replicas to a RSE.

        :param rse: the RSE name.
        :param scope: The scope of the file.
        :param name: The name of the file.
        :param bytes: The size in bytes.
        :param adler32: adler32 checksum.
        :param pfn: PFN of the file for non deterministic RSE.
        :param md5: md5 checksum.
        :param meta: Metadata attributes.

        :return: True if files were created successfully.

        """
        dict = {'scope': scope, 'name': name, 'bytes': bytes, 'meta': meta, 'adler32': adler32}
        if md5:
            dict['md5'] = md5
        if pfn:
            dict['pfn'] = pfn
        return self.add_replicas(rse=rse, files=[dict])

    def add_replicas(self, rse, files, ignore_availability=True):
        """
        Bulk add file replicas to a RSE.

        :param rse: the RSE name.
        :param files: The list of files. This is a list of DIDs like :
        [{'scope': <scope1>, 'name': <name1>}, {'scope': <scope2>, 'name': <name2>}, ...]
        :param ignore_availability: Ignore the RSE blacklisting.

        :return: True if files were created successfully.
        """
        url = build_url(choice(self.list_hosts), path=self.REPLICAS_BASEURL)
        data = {'rse': rse, 'files': files, 'ignore_availability': ignore_availability}
        r = self._send_request(url, type='POST', data=render_json(**data))
        if r.status_code == codes.created:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code)
        raise exc_cls(exc_msg)

    def delete_replicas(self, rse, files, ignore_availability=True):
        """
        Bulk delete file replicas from a RSE.

        :param rse: the RSE name.
        :param files: The list of files. This is a list of DIDs like :
        [{'scope': <scope1>, 'name': <name1>}, {'scope': <scope2>, 'name': <name2>}, ...]
        :param ignore_availability: Ignore the RSE blacklisting.

        :return: True if files have been deleted successfully.
        """
        url = build_url(choice(self.list_hosts), path=self.REPLICAS_BASEURL)
        data = {'rse': rse, 'files': files, 'ignore_availability': ignore_availability}
        r = self._send_request(url, type='DEL', data=render_json(**data))
        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code)
        raise exc_cls(exc_msg)

    def update_replicas_states(self, rse, files):
        """
        Bulk update the file replicas states from a RSE.

        :param rse: the RSE name.
        :param files: The list of files. This is a list of DIDs like :
        [{'scope': <scope1>, 'name': <name1>}, {'scope': <scope2>, 'name': <name2>}, ...]

        :return: True if files have been deleted successfully.
        """
        url = build_url(choice(self.list_hosts), path=self.REPLICAS_BASEURL)
        data = {'rse': rse, 'files': files}
        r = self._send_request(url, type='PUT', data=render_json(**data))
        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code)
        raise exc_cls(exc_msg)
