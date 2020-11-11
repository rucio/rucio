# Copyright 2013-2020 CERN for the benefit of the ATLAS collaboration.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Authors:
# - Vincent Garonne <vgaronne@gmail.com>, 2013-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2019
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2015
# - Ralph Vigne <ralph.vigne@cern.ch>, 2015
# - Brian Bockelman <bbockelm@cse.unl.edu>, 2018
# - Martin Barisits <martin.barisits@cern.ch>, 2018
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Luc Goossens <luc.goossens@cern.ch>, 2020
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020
#
# PY3K COMPATIBLE

try:
    from urllib import quote_plus
except ImportError:
    from urllib.parse import quote_plus

from datetime import datetime
from json import dumps, loads
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url, render_json


class ReplicaClient(BaseClient):
    """Replica client class for working with replicas"""

    REPLICAS_BASEURL = 'replicas'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=600, user_agent='rucio-clients', vo=None):
        super(ReplicaClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout, user_agent, vo=vo)

    def declare_bad_file_replicas(self, pfns, reason):
        """
        Declare a list of bad replicas.

        :param pfns: The list of PFNs.
        :param reason: The reason of the loss.
        """
        data = {'reason': reason, 'pfns': pfns}
        url = build_url(self.host, path='/'.join([self.REPLICAS_BASEURL, 'bad']))
        headers = {}
        r = self._send_request(url, headers=headers, type='POST', data=dumps(data))
        if r.status_code == codes.created:
            return loads(r.text)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def declare_bad_did_replicas(self, rse, dids, reason):
        """
        Declare a list of bad replicas.

        :param rse: The RSE where the bad replicas reside
        :param dids: The DIDs of the bad replicas
        :param reason: The reason of the loss.
        """
        data = {'reason': reason, 'rse': rse, 'dids': dids}
        url = build_url(self.host, path='/'.join([self.REPLICAS_BASEURL, 'bad/dids']))
        headers = {}
        r = self._send_request(url, headers=headers, type='POST', data=dumps(data))
        if r.status_code == codes.created:
            return loads(r.text)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def declare_suspicious_file_replicas(self, pfns, reason):
        """
        Declare a list of bad replicas.

        :param pfns: The list of PFNs.
        :param reason: The reason of the loss.
        """
        data = {'reason': reason, 'pfns': pfns}
        url = build_url(self.host, path='/'.join([self.REPLICAS_BASEURL, 'suspicious']))
        headers = {}
        r = self._send_request(url, headers=headers, type='POST', data=dumps(data))
        if r.status_code == codes.created:
            return loads(r.text)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def get_did_from_pfns(self, pfns, rse=None):
        """
        Get the DIDs associated to a PFN on one given RSE

        :param pfns: The list of PFNs.
        :param rse: The RSE name.
        :returns: A list of dictionaries {pfn: {'scope': scope, 'name': name}}
        """
        data = {'rse': rse, 'pfns': pfns}
        url = build_url(self.host, path='/'.join([self.REPLICAS_BASEURL, 'dids']))
        headers = {}
        r = self._send_request(url, headers=headers, type='POST', data=dumps(data))
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def list_replicas(self, dids, schemes=None, unavailable=False,
                      all_states=False, metalink=False, rse_expression=None,
                      client_location=None, sort=None, domain=None,
                      resolve_archives=True, resolve_parents=False,
                      updated_after=None):
        """
        List file replicas for a list of data identifiers (DIDs).

        :param dids: The list of data identifiers (DIDs) like :
            [{'scope': <scope1>, 'name': <name1>}, {'scope': <scope2>, 'name': <name2>}, ...]
        :param schemes: A list of schemes to filter the replicas. (e.g. file, http, ...)
        :param unavailable: Also include unavailable replicas in the list.
        :param metalink: ``False`` (default) retrieves as JSON,
                         ``True`` retrieves as metalink4+xml.
        :param rse_expression: The RSE expression to restrict replicas on a set of RSEs.
        :param client_location: Client location dictionary for PFN modification {'ip', 'fqdn', 'site'}
        :param sort: Sort the replicas: ``geoip`` - based on src/dst IP topographical distance
                                        ``closeness`` - based on src/dst closeness
                                        ``dynamic`` - Rucio Dynamic Smart Sort (tm)
        :param domain: Define the domain. None is fallback to 'wan', otherwise 'wan, 'lan', or 'all'
        :param resolve_archives: When set to True, find archives which contain the replicas.
        :param resolve_parents: When set to True, find all parent datasets which contain the replicas.
        :param updated_after: epoch timestamp or datetime object (UTC time), only return replicas updated after this time

        :returns: A list of dictionaries with replica information.

        """
        data = {'dids': dids,
                'domain': domain}

        if schemes:
            data['schemes'] = schemes
        if unavailable:
            data['unavailable'] = True
        data['all_states'] = all_states

        if rse_expression:
            data['rse_expression'] = rse_expression

        if client_location:
            data['client_location'] = client_location

        if sort:
            data['sort'] = sort

        if updated_after:
            if isinstance(updated_after, datetime):
                # encode in UTC string with format '%Y-%m-%dT%H:%M:%S'  e.g. '2020-03-02T12:01:38'
                data['updated_after'] = updated_after.strftime('%Y-%m-%dT%H:%M:%S')
            else:
                data['updated_after'] = updated_after

        data['resolve_archives'] = resolve_archives

        data['resolve_parents'] = resolve_parents

        url = build_url(choice(self.list_hosts),
                        path='/'.join([self.REPLICAS_BASEURL, 'list']))

        headers = {}
        if metalink:
            headers['Accept'] = 'application/metalink4+xml'

        # pass json dict in querystring
        r = self._send_request(url, headers=headers, type='POST', data=dumps(data), stream=True)
        if r.status_code == codes.ok:
            if not metalink:
                return self._load_json_data(r)
            return r.text
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
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
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
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
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def update_replicas_states(self, rse, files):
        """
        Bulk update the file replicas states from a RSE.

        :param rse: the RSE name.
        :param files: The list of files. This is a list of DIDs like :
            [{'scope': <scope1>, 'name': <name1>, 'state': <state1>}, {'scope': <scope2>, 'name': <name2>, 'state': <state2>}, ...],
            where a state value can be either of:
            'A' (available)
            'S' (suspicious)
            'U' (unavailable)
            'R' (recovered)
            'B' (bad)
            'L' (lost)
            'D' (deleted)
        :return: True if replica states have been updated successfully, otherwise an exception is raised.

        """
        url = build_url(choice(self.list_hosts), path=self.REPLICAS_BASEURL)
        data = {'rse': rse, 'files': files}
        r = self._send_request(url, type='PUT', data=render_json(**data))
        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def list_dataset_replicas(self, scope, name, deep=False):
        """
        List dataset replicas for a did (scope:name).

        :param scope: The scope of the dataset.
        :param name: The name of the dataset.
        :param deep: Lookup at the file level.

        :returns: A list of dict dataset replicas.

        """
        payload = {}
        if deep:
            payload = {'deep': True}

        url = build_url(self.host,
                        path='/'.join([self.REPLICAS_BASEURL, quote_plus(scope), quote_plus(name), 'datasets']),
                        params=payload)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def list_dataset_replicas_bulk(self, dids):
        """
        List dataset replicas for a did (scope:name).

        :param dids: The list of DIDs of the datasets.

        :returns: A list of dict dataset replicas.
        """
        payload = {'dids': list(dids)}
        url = build_url(self.host, path='/'.join([self.REPLICAS_BASEURL, 'datasets_bulk']))
        r = self._send_request(url, type='POST', data=dumps(payload))
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def list_dataset_replicas_vp(self, scope, name, deep=False):
        """
        List dataset replicas for a DID (scope:name) using the
        Virtual Placement service.

        NOTICE: This is an RnD function and might change or go away at any time.

        :param scope: The scope of the dataset.
        :param name: The name of the dataset.
        :param deep: Lookup at the file level.

        :returns: If VP exists a list of dicts of sites
        """
        payload = {}
        if deep:
            payload = {'deep': True}

        url = build_url(self.host,
                        path='/'.join([self.REPLICAS_BASEURL, quote_plus(scope), quote_plus(name), 'datasets_vp']),
                        params=payload)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def list_datasets_per_rse(self, rse, filters=None, limit=None):
        """
        List datasets at a RSE.

        :param rse: the rse name.
        :param filters: dictionary of attributes by which the results should be filtered.
        :param limit: limit number.

        :returns: A list of dict dataset replicas.

        """
        url = build_url(self.host, path='/'.join([self.REPLICAS_BASEURL, 'rse', rse]))
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)

        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def add_bad_pfns(self, pfns, reason, state, expires_at):
        """
        Declare a list of bad replicas.

        :param pfns: The list of PFNs.
        :param reason: The reason of the loss.
        :param state: The state of the replica. Either BAD, SUSPICIOUS, TEMPORARY_UNAVAILABLE
        :param expires_at: Specify a timeout for the TEMPORARY_UNAVAILABLE replicas. None for BAD files.

        :return: True if PFNs were created successfully.

        """
        data = {'reason': reason, 'pfns': pfns, 'state': state, 'expires_at': expires_at}
        url = build_url(self.host, path='/'.join([self.REPLICAS_BASEURL, 'bad/pfns']))
        headers = {}
        r = self._send_request(url, headers=headers, type='POST', data=dumps(data))
        if r.status_code == codes.created:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def set_tombstone(self, replicas):
        """
        Set a tombstone on a list of replicas.

        :param replicas: list of replicas.
        """
        url = build_url(self.host, path='/'.join([self.REPLICAS_BASEURL, 'tombstone']))
        data = {'replicas': replicas}
        r = self._send_request(url, type='POST', data=render_json(**data))
        if r.status_code == codes.created:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)
