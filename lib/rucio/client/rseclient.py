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

from json import dumps, loads
from typing import TYPE_CHECKING, Any, Literal, Optional, Union
from urllib.parse import quote

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient, choice
from rucio.common.utils import build_url

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from rucio.common.constants import RSE_ALL_SUPPORTED_PROTOCOL_OPERATIONS_LITERAL, RSE_SUPPORTED_PROTOCOL_DOMAINS_LITERAL, SUPPORTED_PROTOCOLS_LITERAL


class RSEClient(BaseClient):
    """RSE client class for working with rucio RSEs"""

    RSE_BASEURL = 'rses'

    def get_rse(self, rse: str) -> dict[str, Any]:
        """
        Returns details about the referred RSE.

        Parameters
        ----------
        rse:
            Name of the referred RSE

        Returns
        --------
        A dict containing all attributes of the referred RSE.

        Raises
        -------
        RSENotFound:
            if the referred RSE was not found in the database.
        """
        path = '/'.join([self.RSE_BASEURL, rse])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            rse_dict = loads(r.text)
            return rse_dict
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def add_rse(self, rse: str, **kwargs) -> Literal[True]:

        """
        Sends the request to create a new RSE.

        Parameters
        ----------
        rse
            The name of the RSE.
        deterministic
            Boolean to know if the pfn is generated deterministically.
        volatile
            Boolean for RSE cache.
        city
            City for the RSE.
        region_code
            The region code for the RSE.
        country_name
            The country.
        continent
            The continent.
        time_zone
            Timezone.
        staging_area
            Staging area.
        ISP
            Internet service provider.
        rse_type
            RSE type.
        latitude
            Latitude coordinate of RSE.
        longitude
            Longitude coordinate of RSE.
        ASN
            Access service network.
        availability
            Availability.

        Returns
        -------
            True if RSE was created successfully else False

        Raises
        ------
        Duplicate
            If RSE already exists.
        """
        path = 'rses/' + rse
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='POST', data=dumps(kwargs))
        if r.status_code == codes.created:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def update_rse(self, rse: str, parameters: dict[str, Any]) -> Literal[True]:
        """
        Update RSE properties like availability or name.

        Parameters
        ----------
        rse:
            The name of the RSE.
        parameters:
            A dictionary with property (name, read, write, delete as keys).
        """
        path = 'rses/' + rse
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='PUT', data=dumps(parameters))
        if r.status_code == codes.created:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def delete_rse(self, rse: str) -> Literal[True]:
        """
        Sends the request to delete a rse.

        Parameters
        ----------
        rse
            The name of the RSE.

        Returns
        -------
        True if RSE was deleted successfully else False.
        """
        path = 'rses/' + rse
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='DEL')
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_rses(self, rse_expression: Optional[str] = None) -> "Iterator[dict[str, Any]]":
        """
        Sends the request to list all rucio locations(RSEs).

        Parameters
        ----------
        rse_expression
            RSE expression to use as filter.
        Returns
        -------
        A list containing the names of all rucio locations.
        """
        if rse_expression:
            path = ['rses', "?expression=" + quote(rse_expression)]
            path = '/'.join(path)
        else:
            path = 'rses/'
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def add_rse_attribute(
            self,
            rse: str,
            key: str,
            value: Any
    ) -> Literal[True]:
        """
        Sends the request to add a RSE attribute.

        Parameters
        ----------
        rse:
            The name of the RSE.
        key:
            The attribute key.
        value:
            The attribute value.

        Returns
        -------
        True if RSE attribute was created successfully else False.

        Raises
        -------
        Duplicate
            If RSE attribute already exists.
        """
        path = '/'.join([self.RSE_BASEURL, rse, 'attr', key])
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'value': value})

        r = self._send_request(url, type_='POST', data=data)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def delete_rse_attribute(self, rse: str, key: str) -> Literal[True]:
        """
        Sends the request to delete a RSE attribute.

        Parameters
        ----------
        rse
            The RSE name.
        key
            The attribute key.

        Returns
        -------
        True if RSE attribute was deleted successfully else False.
        """
        path = '/'.join([self.RSE_BASEURL, rse, 'attr', key])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type_='DEL')
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_rse_attributes(self, rse: str) -> dict[str, Any]:
        """
        Sends the request to get RSE attributes.

        Parameters
        ----------
        rse
            The RSE name.

        Returns
        -------
        A dict with the RSE attribute name/value pairs.
        """
        path = '/'.join([self.RSE_BASEURL, rse, 'attr/'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            attributes = loads(r.text)
            return attributes
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def add_protocol(self, rse: str, params: dict[str, Any]) -> Literal[True]:
        """
        Sends the request to create a new protocol for the given RSE.

        Parameters
        ----------
        rse :
            The name of the RSE.
        params :
            Attributes of the protocol. Supported are:
            - scheme: identifier of this protocol
            - hostname: hostname for this protocol (default = localhost)
            - port: port for this protocol (default = 0)
            - prefix: string used as a prefix for this protocol when generating the PFN (default = None)
            - impl: qualified name of the implementation class for this protocol (mandatory)
            - read: integer representing the priority of this protocol for read operations (default = -1)
            - write: integer representing the priority of this protocol for write operations (default = -1)
            - delete: integer representing the priority of this protocol for delete operations (default = -1)
            - extended_attributes: miscellaneous protocol specific information e.g. spacetoken for SRM (default = None)

        Returns
        -------
            True if protocol was created successfully.

        Raises
        ------
        Duplicate
            If protocol with same hostname, port and protocol identifier already exists for the given RSE.
        RSENotFound
            If the RSE doesn't exist.
        KeyNotFound
            If params is missing mandatory attributes to create the protocol.
        AccessDenied
            If not authorized.
        """
        scheme = params['scheme']
        path = '/'.join([self.RSE_BASEURL, rse, 'protocols', scheme])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='POST', data=dumps(params))
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def get_protocols(
            self,
            rse: str,
            protocol_domain: "RSE_SUPPORTED_PROTOCOL_DOMAINS_LITERAL" = 'ALL',
            operation: Optional["RSE_ALL_SUPPORTED_PROTOCOL_OPERATIONS_LITERAL"] = None,
            default: bool = False,
            scheme: Optional['SUPPORTED_PROTOCOLS_LITERAL'] = None
    ) -> Any:
        """
        Returns protocol information.
        Parameter combinations are: (operation OR default) XOR protocol.

        Parameters
        ----------
        rse :
            The RSE name.
        protocol_domain :
            The scope of the protocol. Supported are 'LAN', 'WAN', and 'ALL', by default 'ALL'.
        operation :
            The name of the requested operation (read, write, or delete).
            If None, all operations are queried, by default None.
        default :
            Indicates if only the default operations should be returned, by default False.
        scheme :
            The identifier of the requested protocol, by default None.

        Returns
        -------
            A dict with details about each matching protocol.

        Raises
        ------
        RSENotFound
            If the RSE doesn't exist.
        RSEProtocolNotSupported
            If no matching protocol entry could be found.
        RSEOperationNotSupported
            If no matching protocol entry for the requested operation could be found.
        """

        path = None
        params = {}
        if scheme:
            path = '/'.join([self.RSE_BASEURL, rse, 'protocols', scheme])
        else:
            path = '/'.join([self.RSE_BASEURL, rse, 'protocols'])
            if operation:
                params['operation'] = operation
            if default:
                params['default'] = default
        params['protocol_domain'] = protocol_domain
        url = build_url(choice(self.list_hosts), path=path, params=params)

        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            protocols = loads(r.text)
            return protocols
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def lfns2pfns(
            self,
            rse: str,
            lfns: 'Iterable[str]',
            protocol_domain: 'RSE_SUPPORTED_PROTOCOL_DOMAINS_LITERAL' = 'ALL',
            operation: Optional['RSE_ALL_SUPPORTED_PROTOCOL_OPERATIONS_LITERAL'] = None,
            scheme: Optional['SUPPORTED_PROTOCOLS_LITERAL'] = None
    ) -> dict[str, str]:
        """
        Returns PFNs that should be used at a RSE, corresponding to requested LFNs.
        The PFNs are generated for the RSE *regardless* of whether a replica exists for the LFN.

        Parameters
        ----------
        rse :
            The RSE name.
        lfns :
            A list of LFN strings to translate to PFNs.
        protocol_domain :
            The scope of the protocol.
        operation :
            The name of the requested operation (read, write, or delete).
            If None, all operations are queried, by default None.
        scheme :
            The identifier of the requested protocol (gsiftp, https, davs, etc), by default None.

        Returns
        -------
            A dictionary of LFN / PFN pairs.

        Raises
        ------
        RSENotFound
            If the RSE doesn't exist.
        RSEProtocolNotSupported
            If no matching protocol entry could be found.
        RSEOperationNotSupported
            If no matching protocol entry for the requested operation could be found.
        """
        path = '/'.join([self.RSE_BASEURL, rse, 'lfns2pfns'])
        params = []
        if scheme:
            params.append(('scheme', scheme))
        if protocol_domain != 'ALL':
            params.append(('domain', protocol_domain))
        if operation:
            params.append(('operation', operation))
        for lfn in lfns:
            params.append(('lfn', lfn))

        url = build_url(choice(self.list_hosts), path=path, params=params, doseq=True)

        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            pfns = loads(r.text)
            return pfns
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def delete_protocols(
            self,
            rse: str,
            scheme: 'SUPPORTED_PROTOCOLS_LITERAL',
            hostname: Optional[str] = None,
            port: Optional[int] = None
    ) -> Literal[True]:
        """
        Deletes matching protocols from RSE. Protocols using the same identifier can be
        distinguished by hostname and port.

        Parameters
        ----------
        rse :
            The RSE name.
        scheme :
            The identifier of the protocol.
        hostname :
            The hostname of the protocol.
        port :
            The port of the protocol.

        Returns
        -------
        True if success.

        Raises
        -------
        RSEProtocolNotSupported
            If no matching protocol entry could be found.
        RSENotFound
            If the RSE doesn't exist.
        AccessDenied
            If not authorized.
        """
        path = [self.RSE_BASEURL, rse, 'protocols', scheme]
        if hostname:
            path.append(hostname)
            if port:
                path.append(str(port))

        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='DEL')
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def update_protocols(
            self,
            rse: str,
            scheme: 'SUPPORTED_PROTOCOLS_LITERAL',
            data: dict[str, Any],
            hostname: Optional[str] = None,
            port: Optional[int] = None):
        """
        Updates matching protocols from RSE. Protocol using the same identifier can be
        distinguished by hostname and port.

        Parameters
        ----------
        rse:
            The RSE name.
        scheme:
            The identifier of the protocol.
        data:
            A dict providing the new values of the protocol attributes. Keys must match column names in database.
        hostname:
            The hostname of the protocol.
        port:
            The port of the protocol.
        Returns
        -------
        True if success.

        Raises
        -------
        RSEProtocolNotSupported
            If no matching protocol entry could be found.
        RSENotFound
            If the RSE doesn't exist.
        KeyNotFound
            If invalid data was provided for update.
        AccessDenied
            If not authorized.
        """
        path = [self.RSE_BASEURL, rse, 'protocols', scheme]
        if hostname:
            path.append(hostname)
            if port:
                path.append(str(port))

        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='PUT', data=dumps(data))
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def swap_protocols(
            self,
            rse: str,
            domain: 'RSE_SUPPORTED_PROTOCOL_DOMAINS_LITERAL',
            operation: 'RSE_ALL_SUPPORTED_PROTOCOL_OPERATIONS_LITERAL',
            scheme_a: 'SUPPORTED_PROTOCOLS_LITERAL',
            scheme_b: 'SUPPORTED_PROTOCOLS_LITERAL'
    ) -> bool:
        """
        Swaps the priorities of the provided operation.

        Parameters
        ----------
        rse :
            The RSE name.
        domain :
            The domain in which priorities should be swapped (e.g., 'wan' or 'lan').
        operation :
            The operation for which priorities should be swapped (e.g., 'read', 'write', or 'delete').
        scheme_a :
            The scheme of one of the two protocols to be swapped (e.g., 'srm').
        scheme_b :
            The scheme of the other protocol to be swapped (e.g., 'http').

        Returns
        -------
            True if successful.

        Raises
        ------
        RSEProtocolNotSupported
            If no matching protocol entry could be found.
        RSENotFound
            If the RSE doesn't exist.
        KeyNotFound
            If invalid data was provided for update.
        AccessDenied
            If not authorized.
        """

        protocols = self.get_protocols(rse, domain, operation, False, scheme_a)['protocols']
        protocol_a = next((p for p in protocols if p['scheme'] == scheme_a), None)
        protocol_b = next((p for p in protocols if p['scheme'] == scheme_b), None)

        if protocol_a is None or protocol_b is None:
            return False

        priority_a = protocol_a['domains'][domain][operation]
        priority_b = protocol_b['domains'][domain][operation]
        self.update_protocols(rse, protocol_a['scheme'], {'domains': {domain: {operation: priority_b}}}, protocol_a['hostname'], protocol_a['port'])
        self.update_protocols(rse, protocol_b['scheme'], {'domains': {domain: {operation: priority_a}}}, protocol_b['hostname'], protocol_b['port'])
        return True

    def add_qos_policy(self, rse: str, qos_policy: str) -> Literal[True]:
        """
        Add a QoS policy to an RSE.

        Parameters
        ----------
        rse
            The name of the RSE.
        qos_policy
            The QoS policy to add.

        Returns
        -------
        True if successful.

        Raises
        ------
        Duplicate
            If the QoS policy already exists.
        """

        path = [self.RSE_BASEURL, rse, 'qos_policy', qos_policy]
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='POST')
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def delete_qos_policy(self, rse: str, qos_policy: str) -> Literal[True]:
        """
        Delete a QoS policy from an RSE.

        Parameters
        ----------
        rse
            The name of the RSE.
        qos_policy
            The QoS policy to delete.
        session:
            The database session in use.

        Returns
        -------
        True if successful.

        Raises
        ------
        RSENotFound
            If the RSE doesn't exist.
        QoSPolicyNotFound
            If the QoS policy doesn't exist.
        """

        path = [self.RSE_BASEURL, rse, 'qos_policy', qos_policy]
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='DEL')
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_qos_policies(self, rse: str) -> list[str]:
        """
        List all QoS policies of an RSE.

        :param rse_id: The id of the RSE.
        :param session: The database session in use.

        :returns: List containing all QoS policies.
        """

        path = [self.RSE_BASEURL, rse, 'qos_policy']
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return loads(r.text)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def set_rse_usage(
            self,
            rse: str,
            source: str,
            used: int,
            free: int,
            files: Optional[int] = None
    ) -> Literal[True]:
        """
        Set RSE usage information.

        Parameters
        ----------
        rse:
            The RSE name.
        source:
            The information source, e.g. srm.
        used:
            The used space in bytes.
        free:
            The free space in bytes.
        files:
            The number of files.

        Returns
        -------
        True if successful.
        """
        path = [self.RSE_BASEURL, rse, 'usage']
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        data = {'source': source, 'used': used, 'free': free, 'files': files}
        r = self._send_request(url, type_='PUT', data=dumps(data))
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def get_rse_usage(
            self,
            rse: str,
            filters: Optional[dict[str, Any]] = None
    ) -> "Iterator[dict[str, Any]]":
        """
        Get RSE usage information.

        Parameters
        ----------
        rse:
            The RSE name.
        filters:
            dictionary of attributes by which the results should be filtered

        Returns
        -------
        True if successful, otherwise false.
        """
        path = [self.RSE_BASEURL, rse, 'usage']
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET', params=filters)
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_rse_usage_history(
            self,
            rse: str,
            filters: Optional[dict[str, Any]] = None
    ) -> "Iterator[dict[str, Any]]":
        """
        List RSE usage history information.

        Parameters
        ----------
        rse:
            The RSE name.
        filters:
            dictionary of attributes by which the results should be filtered

        Returns
        -------
        list of dictionaries
        """
        path = [self.RSE_BASEURL, rse, 'usage', 'history']
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET', params=filters)
        if r.status_code == codes.ok:
            return self._load_json_data(r)
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers,
                                                   status_code=r.status_code,
                                                   data=r.content)
            raise exc_cls(exc_msg)

    def set_rse_limits(
            self,
            rse: str,
            name: str,
            value: int
    ) -> Literal[True]:
        """
        Set RSE limit information.

        Parameters
        ----------
        rse:
            The RSE name.
        name:
            The name of the limit.
        value:
            The feature value.

        Returns
        -------
        True if successful.
        """
        path = [self.RSE_BASEURL, rse, 'limits']
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='PUT', data=dumps({'name': name, 'value': value}))
        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers,
                                               status_code=r.status_code,
                                               data=r.content)
        raise exc_cls(exc_msg)

    def get_rse_limits(
            self,
            rse: str
    ) -> "Iterator[dict[str, Union[str, int]]]":
        """
        Get RSE limits.

        Parameters
        ----------
        rse:
            The RSE name.

        Returns
        -------
        An iterator of RSE limits as dicts with 'name' and 'value' as keys.
        """
        path = [self.RSE_BASEURL, rse, 'limits']
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return next(self._load_json_data(r))
        exc_cls, exc_msg = self._get_exception(headers=r.headers,
                                               status_code=r.status_code,
                                               data=r.content)
        raise exc_cls(exc_msg)

    def delete_rse_limits(self, rse: str, name: str) -> Literal[True]:
        """
        Delete RSE limit information.

        Parameters
        ----------
        rse:
            The RSE name.
        name:
            The name of the limit.

        Returns
        -------
        True if successful.
        """
        path = [self.RSE_BASEURL, rse, 'limits']
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='DEL', data=dumps({'name': name}))
        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers,
                                               status_code=r.status_code,
                                               data=r.content)

        raise exc_cls(exc_msg)

    def add_distance(
            self,
            source: str,
            destination: str,
            parameters: dict[str, int]
    ) -> Literal[True]:
        """
        Add a src-dest distance.

        :param source: The source.
        :param destination: The destination.
        :param parameters: A dictionary with property.
        """
        path = [self.RSE_BASEURL, source, 'distances', destination]
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='POST', data=dumps(parameters))
        if r.status_code == codes.created:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers,
                                               status_code=r.status_code,
                                               data=r.content)
        raise exc_cls(exc_msg)

    def update_distance(
            self,
            source: str,
            destination: str,
            parameters: dict[str, int]
    ) -> Literal[True]:
        """
        Update distances with the given RSE ids.

        Parameters
        ----------
        source :
            The source RSE.
        destination :
            The destination RSE.
        parameters :
            A dictionary with property
        """
        path = [self.RSE_BASEURL, source, 'distances', destination]
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='PUT', data=dumps(parameters))
        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers,
                                               status_code=r.status_code,
                                               data=r.content)
        raise exc_cls(exc_msg)

    def get_distance(
            self,
            source: str,
            destination: str
    ) -> list[dict[str, Union[str, int]]]:
        """
        Get distances between rses.

        Param
        ----------
        source :
            The source RSE.
        destination :

            The destination RSE.

        Returns
        -------
            A list of dictionaries with the distance information.
        """
        path = [self.RSE_BASEURL, source, 'distances', destination]
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return next(self._load_json_data(r))
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def delete_distance(
            self,
            source: str,
            destination: str
    ) -> Literal[True]:
        """
        Delete distances with the given RSE ids.

        Parameters
        ----------
        source :
            The source
        destination :
            The destination
        """
        path = [self.RSE_BASEURL, source, 'distances', destination]
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='DEL')
        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers,
                                               status_code=r.status_code,
                                               data=r.content)
        raise exc_cls(exc_msg)
