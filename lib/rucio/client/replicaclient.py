# -*- coding: utf-8 -*-
# Copyright 2013-2021 CERN
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
# - Vincent Garonne <vincent.garonne@cern.ch>, 2013-2018
# - Mario Lassnig <mario.lassnig@cern.ch>, 2013-2021
# - Cedric Serfon <cedric.serfon@cern.ch>, 2014-2018
# - Ralph Vigne <ralph.vigne@cern.ch>, 2015
# - Brian Bockelman <bbockelm@cse.unl.edu>, 2018
# - Martin Barisits <martin.barisits@cern.ch>, 2018-2021
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2018-2019
# - Jaroslav Guenther <jaroslav.guenther@cern.ch>, 2019
# - Ilija Vukotic <ivukotic@cern.ch>, 2020
# - Luc Goossens <luc.goossens@cern.ch>, 2020
# - Andrew Lister <andrew.lister@stfc.ac.uk>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2020-2021
# - Eric Vaandering <ewv@fnal.gov>, 2020
# - Radu Carpa <radu.carpa@cern.ch>, 2021

from datetime import datetime
from json import dumps, loads

from requests.status_codes import codes
from six.moves.urllib.parse import quote_plus

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url, render_json


class ReplicaClient(BaseClient):
    """Replica client class for working with replicas"""

    REPLICAS_BASEURL = 'replicas'

    def declare_bad_file_replicas(self, pfns, reason):
        """
        Declare a list of bad replicas.

        :param pfns: The list of PFNs.
        :param reason: The reason of the loss.
        """
        data = {'reason': reason, 'pfns': pfns}
        url = build_url(self.host, path='/'.join([self.REPLICAS_BASEURL, 'bad']))
        headers = {}
        r = self._send_request(url, headers=headers, type_='POST', data=dumps(data))
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
        r = self._send_request(url, headers=headers, type_='POST', data=dumps(data))
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
        r = self._send_request(url, headers=headers, type_='POST', data=dumps(data))
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
        r = self._send_request(url, headers=headers, type_='POST', data=dumps(data))
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def list_replicas(self, dids, schemes=None, ignore_availability=True,
                      all_states=False, metalink=False, rse_expression=None,
                      client_location=None, sort=None, domain=None,
                      signature_lifetime=None, nrandom=None,
                      resolve_archives=True, resolve_parents=False,
                      updated_after=None):
        """
        List file replicas for a list of data identifiers (DIDs).

        :param dids: The list of data identifiers (DIDs) like :
            [{'scope': <scope1>, 'name': <name1>}, {'scope': <scope2>, 'name': <name2>}, ...]
        :param schemes: A list of schemes to filter the replicas. (e.g. file, http, ...)
        :param ignore_availability: Also include replicas from blocked RSEs into the list
        :param metalink: ``False`` (default) retrieves as JSON,
                         ``True`` retrieves as metalink4+xml.
        :param rse_expression: The RSE expression to restrict replicas on a set of RSEs.
        :param client_location: Client location dictionary for PFN modification {'ip', 'fqdn', 'site', 'latitude', 'longitude'}
        :param sort: Sort the replicas: ``geoip`` - based on src/dst IP topographical distance
                                        ``closeness`` - based on src/dst closeness
                                        ``dynamic`` - Rucio Dynamic Smart Sort (tm)
        :param domain: Define the domain. None is fallback to 'wan', otherwise 'wan, 'lan', or 'all'
        :param signature_lifetime: If supported, in seconds, restrict the lifetime of the signed PFN.
        :param nrandom: pick N random replicas. If the initial number of replicas is smaller than N, returns all replicas.
        :param resolve_archives: When set to True, find archives which contain the replicas.
        :param resolve_parents: When set to True, find all parent datasets which contain the replicas.
        :param updated_after: epoch timestamp or datetime object (UTC time), only return replicas updated after this time

        :returns: A list of dictionaries with replica information.

        """
        data = {'dids': dids,
                'domain': domain}

        if schemes:
            data['schemes'] = schemes
        if ignore_availability is not None:
            data['ignore_availability'] = ignore_availability
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

        if signature_lifetime:
            data['signature_lifetime'] = signature_lifetime

        if nrandom:
            data['nrandom'] = nrandom

        data['resolve_archives'] = resolve_archives

        data['resolve_parents'] = resolve_parents

        url = build_url(choice(self.list_hosts),
                        path='/'.join([self.REPLICAS_BASEURL, 'list']))

        headers = {}
        if metalink:
            headers['Accept'] = 'application/metalink4+xml'

        # pass json dict in querystring
        r = self._send_request(url, headers=headers, type_='POST', data=dumps(data), stream=True)
        if r.status_code == codes.ok:
            if not metalink:
                return self._load_json_data(r)
            return r.text
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def list_suspicious_replicas(self, rse_expression=None, younger_than=None, nattempts=None):
        """
        List file replicas tagged as suspicious.

        :param rse_expression: The RSE expression to restrict replicas on a set of RSEs.
        :param younger_than: Datetime object to select the replicas which were declared since younger_than date. Default value = 10 days ago.
        :param nattempts: The minimum number of replica appearances in the bad_replica DB table from younger_than date. Default value = 0.
        :param state: State of the replica, either 'BAD' or 'SUSPICIOUS'. No value returns replicas with either state.

        """
        params = {}
        if rse_expression:
            params['rse_expression'] = rse_expression

        if younger_than:
            params['younger_than'] = younger_than

        if nattempts:
            params['nattempts'] = nattempts

        url = build_url(choice(self.list_hosts),
                        path='/'.join([self.REPLICAS_BASEURL, 'suspicious']))
        r = self._send_request(url, type_='GET', params=params)
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def add_replica(self, rse, scope, name, bytes_, adler32, pfn=None, md5=None, meta={}):
        """
        Add file replicas to a RSE.

        :param rse: the RSE name.
        :param scope: The scope of the file.
        :param name: The name of the file.
        :param bytes_: The size in bytes.
        :param adler32: adler32 checksum.
        :param pfn: PFN of the file for non deterministic RSE.
        :param md5: md5 checksum.
        :param meta: Metadata attributes.

        :return: True if files were created successfully.

        """
        dict_ = {'scope': scope, 'name': name, 'bytes': bytes_, 'meta': meta, 'adler32': adler32}
        if md5:
            dict_['md5'] = md5
        if pfn:
            dict_['pfn'] = pfn
        return self.add_replicas(rse=rse, files=[dict_])

    def add_replicas(self, rse, files, ignore_availability=True):
        """
        Bulk add file replicas to a RSE.

        :param rse: the RSE name.
        :param files: The list of files. This is a list of DIDs like :
            [{'scope': <scope1>, 'name': <name1>}, {'scope': <scope2>, 'name': <name2>}, ...]
        :param ignore_availability: Ignore the RSE blocklsit.

        :return: True if files were created successfully.

        """
        url = build_url(choice(self.list_hosts), path=self.REPLICAS_BASEURL)
        data = {'rse': rse, 'files': files, 'ignore_availability': ignore_availability}
        r = self._send_request(url, type_='POST', data=render_json(**data))
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
        :param ignore_availability: Ignore the RSE blocklist.

        :return: True if files have been deleted successfully.

        """
        url = build_url(choice(self.list_hosts), path=self.REPLICAS_BASEURL)
        data = {'rse': rse, 'files': files, 'ignore_availability': ignore_availability}
        r = self._send_request(url, type_='DEL', data=render_json(**data))
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
        r = self._send_request(url, type_='PUT', data=render_json(**data))
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
        r = self._send_request(url, type_='GET')
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
        r = self._send_request(url, type_='POST', data=dumps(payload))
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
        r = self._send_request(url, type_='GET')
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
        r = self._send_request(url, type_='GET')
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
        r = self._send_request(url, headers=headers, type_='POST', data=dumps(data))
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
        r = self._send_request(url, type_='POST', data=render_json(**data))
        if r.status_code == codes.created:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)
