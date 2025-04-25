# Copyright European Organization for Nuclear Research (CERN) since 2012
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

from datetime import datetime
from json import dumps, loads
from typing import Any, Optional
from urllib.parse import quote_plus

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.utils import build_url, chunks, render_json


class ReplicaClient(BaseClient):
    """Replica client class for working with replicas"""

    REPLICAS_BASEURL = 'replicas'
    REPLICAS_CHUNK_SIZE = 1000

    def quarantine_replicas(self, replicas, rse=None, rse_id=None):
        """
        Add quaratined replicas for RSE.

        Parameters
        ----------
        replicas : list
            List of replica infos: {'scope': <scope> (optional), 'name': <name> (optional), 'path':<path> (required)}.
        rse : str, optional
            RSE name.
        rse_id : str, optional
            RSE id. Either RSE name or RSE id must be specified, but not both.
        """

        if (rse is None) == (rse_id is None):
            raise ValueError("Either RSE name or RSE id must be specified, but not both")

        url = build_url(self.host, path='/'.join([self.REPLICAS_BASEURL, 'quarantine']))
        headers = {}
        for chunk in chunks(replicas, self.REPLICAS_CHUNK_SIZE):
            data = {'rse': rse, 'rse_id': rse_id, 'replicas': chunk}
            r = self._send_request(url, headers=headers, type_='POST', data=dumps(data))
            if r.status_code != codes.ok:
                exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
                raise exc_cls(exc_msg)

    def declare_bad_file_replicas(self, replicas, reason, force=False):
        """
        Declare a list of bad replicas.

        Parameters
        ----------
        replicas : list
            Either a list of PFNs (string) or a list of dicts {'scope': <scope>, 'name': <name>, 'rse_id': <rse_id> or 'rse': <rse_name>}
        reason : str
            The reason of the loss.
        force : bool, optional
            Tell the server to ignore existing replica status in the bad_replicas table. Default: False

        Returns
        -------
        dict
            Dictionary of the form {"rse_name": ["did: error",...]} - list of strings for DIDs failed to declare, by RSE
        """

        out = {}    # {rse: ["did: error text",...]}
        url = build_url(self.host, path='/'.join([self.REPLICAS_BASEURL, 'bad']))
        headers = {}
        for chunk in chunks(replicas, self.REPLICAS_CHUNK_SIZE):
            data = {'reason': reason, 'replicas': chunk, 'force': force}
            r = self._send_request(url, headers=headers, type_='POST', data=dumps(data))
            if r.status_code not in (codes.created, codes.ok):
                exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
                raise exc_cls(exc_msg)
            chunk_result = loads(r.text)
            if chunk_result:
                for rse, lst in chunk_result.items():
                    out.setdefault(rse, []).extend(lst)
        return out

    def declare_bad_did_replicas(self, rse, dids, reason):
        """
        Declare a list of bad replicas.

        Parameters
        ----------
        rse : str
            The RSE where the bad replicas reside.
        dids : list
            The DIDs of the bad replicas.
        reason : str
            The reason of the loss.
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

        Parameters
        ----------
        pfns: list
            The list of PFNs.
        reason: str
            The reason of the loss.

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
        Get the DIDs associated to a PFN on one given RSE.

        Parameters
        ----------
        pfns : list
            The list of PFNs.
        rse : str
            The RSE name.
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

        Parameters
        ----------
        dids: list
            The list of data identifiers (DIDs) like :
            [{'scope': <scope1>, 'name': <name1>}, {'scope': <scope2>, 'name': <name2>}, ...]
        schemes: list
            A list of schemes to filter the replicas. (e.g. file, http, ...)
        ignore_availability: bool
            Also include replicas from blocked RSEs into the list
        all_states: bool
            Include all states of the replicas. Default: False
        metalink: bool
            ``False`` (default) retrieves as JSON,
            ``True`` retrieves as metalink4+xml.
        rse_expression: str
            The RSE expression to restrict replicas on a set of RSEs.
        client_location: dict
            Client location dictionary for PFN modification {'ip', 'fqdn', 'site', 'latitude', 'longitude'}
        sort: str
            Sort the replicas: ``geoip`` - based on src/dst IP topographical distance
        domain: str
            Define the domain. None is fallback to 'wan', otherwise 'wan, 'lan', or 'all'
        signature_lifetime: int
            If supported, in seconds, restrict the lifetime of the signed PFN.
        nrandom: int
            pick N random replicas. If the initial number of replicas is smaller than N, returns all replicas.
        resolve_archives: bool
            When set to True, find archives which contain the replicas.
        resolve_parents: bool
            When set to True, find all parent datasets which contain the replicas.
        updated_after: datetime
            epoch timestamp or datetime object (UTC time), only return replicas updated after this time


        Returns
        -------
        list
            A list of dictionaries with replica information.
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

        Parameters
        ----------
        rse_expression:
            The RSE expression to restrict replicas on a set of RSEs.
        younger_than:
            Datetime object to select the replicas which were declared since younger_than date. Default value = 10 days ago.
        nattempts:
            The minimum number of replica appearances in the bad_replica DB table from younger_than date. Default value = 0.
        state:
            State of the replica, either 'BAD' or 'SUSPICIOUS'. No value returns replicas with either state.
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

    def add_replica(
        self,
        rse: str,
        scope: str,
        name: str,
        bytes_: int,
        adler32: str,
        pfn: Optional[str] = None,
        md5: Optional[str] = None,
        meta: Optional[dict[str, Any]] = None
    ) -> bool:
        """
        Add file replicas to a RSE.

        Parameters
        ----------
        rse : str
            The RSE name.
        scope : str
            The scope of the file.
        name : str
            The name of the file.
        bytes_ : int
            The size in bytes.
        adler32 : str
            adler32 checksum.
        pfn : str, optional
            PFN of the file for non deterministic RSE.
        md5 : str, optional
            md5 checksum.
        meta : dict, optional
            Metadata attributes.

        Returns
        -------
        bool
            True if files were created successfully.
        """
        meta = meta or {}
        dict_ = {'scope': scope, 'name': name, 'bytes': bytes_, 'meta': meta, 'adler32': adler32}
        if md5:
            dict_['md5'] = md5
        if pfn:
            dict_['pfn'] = pfn
        return self.add_replicas(rse=rse, files=[dict_])

    def add_replicas(self, rse, files, ignore_availability=True):
        """
        Bulk add file replicas to a RSE.

        Parameters
        ----------
        rse:
            the RSE name
        files:
            The list of files. This is a list of DIDs like :
            [{'scope': <scope1>, 'name': <name1>}, {'scope': <scope2>, 'name': <name2>}, ...]
        ignore_availability:
            Ignore the RSE blocklist

        Returns
        -------
        True if files were created successfully.
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
        Parameters
        ----------
        rse:
            the RSE name
        files:
            The list of files. This is a list of DIDs like :
            [{'scope': <scope1>, 'name': <name1>}, {'scope': <scope2>, 'name': <name2>}, ...]
        ignore_availability:
            Ignore the RSE blocklist

        Returns
        -------
        True if files have been deleted successfully.
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

                Parameters
        ----------
        rse : str
            The RSE name.
        files : list
            The list of files. This is a list of DIDs like :
            [{'scope': <scope1>, 'name': <name1>, 'state': <state1>}, {'scope': <scope2>, 'name': <name2>, 'state': <state2>}, ...],
            Where a state value can be any of:
                * 'A' (AVAILABLE)
                * 'U' (UNAVAILABLE)
                * 'C' (COPYING)
                * 'B' (BEING_DELETED)
                * 'D' (BAD)
                * 'T' (TEMPORARY_UNAVAILABLE)

        Returns
        -------
        True if replica states have been updated successfully, otherwise an exception is raised.
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

        Parameters
        ----------
        scope:
            The scope of the dataset.
        name:
            The name of the dataset.
        deep:
            Lookup at the file level.

        Returns
        -------
        A list of dict dataset replicas
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

        Parameters
        ----------
        dids:
            The list of DIDs of the datasets

        Returns
        -------
        A list of dict dataset replicas
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

        Parameters
        ----------
        scope:
            The scope of the dataset.
        name:
            The name of the dataset.
        deep:
            Lookup at the file level.

        Returns
        -------
        If VP exists a list of dicts of sites

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

        Parameters
        ----------
        rse:
            The RSE name.
        filters:
            dictionary of attributes by which the results should be filtered.
        limit:
            limit number.
        Returns
        -------
        A list of dict dataset replicas
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

        Parameters
        ----------
        pfns:
            The list of PFNs.
        reason:
            The reason of the loss.
        state:
            The state of the replica. Either BAD, SUSPICIOUS, TEMPORARY_UNAVAILABLE
        expires_at:
            Specify a timeout for the TEMPORARY_UNAVAILABLE replicas. None for BAD files.

        Returns
        -------
        True if PFNs were created successfully.
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

        Parameters
        ----------
        replicas:
            list of replicas.
        """
        url = build_url(self.host, path='/'.join([self.REPLICAS_BASEURL, 'tombstone']))
        data = {'replicas': replicas}
        r = self._send_request(url, type_='POST', data=render_json(**data))
        if r.status_code == codes.created:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)
