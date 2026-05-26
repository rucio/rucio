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
from rucio.common.constants import HTTPMethod
from rucio.common.utils import build_url

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from rucio.common.constants import RSE_ALL_SUPPORTED_PROTOCOL_OPERATIONS_LITERAL, RSE_SUPPORTED_PROTOCOL_DOMAINS_LITERAL, SUPPORTED_PROTOCOLS_LITERAL


class RSEClient(BaseClient):
    """RSE client class for working with rucio RSEs"""

    RSE_BASEURL = 'rses'

    def get_rse(self, rse: str) -> dict[str, Any]:
        """
        Returns details about an RSE.

        Parameters
        ----------
        rse:
            Name of the RSE

        Returns
        --------
        Dictionary of settings and protocol attributes.
        Additional attributes can be added beyond the ones listed below by using "RSEClient.add_rse_attribute"
        and read with "RSEClient.list_rse_attributes".
            **`availability`**:
                int: [Deprecated]

            **`availability_delete`**:
                bool: Can the replicas on the RSE be deleted?

            **`availability_read`**:
                bool: Can replicas on the RSE be read?

            **`availability_write`**:
                bool: Can the RSE be written to?

            **`credentials`**:
                Optional[str]: Crediental for an attached protocol (if any)

            **`deterministic`**:
                bool: Are the PFNs on the RSE set deteriminstically?

            **`domain`**:
                dict|list: Domains (lan/wan) the RSE can act on (and premissions, if dictionary).
                Form of {"wan": {"read"...}, "lan": {...}} if dictionary, else ["wan", "lan"].

            **`id`**:
                str: ID of the RSE

            **`lfn2pfn_algorithm`**:
                Optional[str]: Algorithm for LFN to PFNs

            **`protocols`**:
                list[dict]: Describing the protocols used by the RSE for storage

            **`qos_class`**:
                Optional[str]: QoS Policy

            **`rse`**:
                str: Name of the RSE

            **`rse_type`**:
                str: Storage type of RSE, typically "DISK" or "TAPE"

            **`sign_url`**:
                Optional[str]: Signing service configuration, if configured.

            **`staging_area`**:
                bool: Whether the RSE is a staging area.

            **`verify_checksum`**:
                bool: Whether checksums are verified.

            **`volatile`**:
                bool: Whether the RSE is volatile.


        Raises
        -------
        RSENotFound:
            if the referred RSE was not found in the database.

        Examples
        --------
        ??? Example

            Query an RSE via an RSE Expression and get it attributes of all RSEs that match

            ```python
            from rucio.client.client import Client

            rse_client = Client()
            rse_expression="rse_type=DISK"
            possible_rses = [rse['rse'] for rse in rse_client.list_rses(rse_expression)]
            for rse in possible_rses:
                print(rse_client.get_rse(rse))
            ```

        See Also
        --------
        rucio.client.rseclient.RSEClient.add_rse_attribute
        rucio.client.rseclient.RSEClient.update_rse
        rucio.client.rseclient.RSEClient.list_rses
        rucio.client.rseclient.RSEClient.list_rse_attributes
        """
        path = '/'.join([self.RSE_BASEURL, rse])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, method=HTTPMethod.GET)
        if r.status_code == codes.ok:
            rse_dict = loads(r.text)
            return rse_dict
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def add_rse(self, rse: str, **kwargs) -> Literal[True]:

        """
        Create a new RSE

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
            [Deprecated] integer availability bitmask.
        availability_read
            Whether replicas on the RSE can be read.
        availability_write
            Whether replicas can be written to the RSE.
        availability_delete
            Whether replicas on the RSE can be deleted.

        Returns
        -------
            True if RSE was created successfully created.

        Raises
        ------
        Duplicate
            If RSE already exists.
        InvalidObject
            If the RSE name does not match the given schema.
        AccessDenied
            If the issuer cannot create the RSE.

        Examples
        --------
        ??? Example

            Create a new disk RSE and add an attribute

            ```python
            from rucio.client.client import Client

            rse_client = Client()
            rse_name="MyNewRSE"
            rse_client.add_rse(rse_name, rse_type="DISK")

            rse_client.add_rse_attribute(rse_name, key="TIER", value="3")  # Custom organizational attribute

            ```

        See Also
        --------
        rucio.client.rseclient.RSEClient.delete_rse
        rucio.client.rseclient.RSEClient.update_rse
        rucio.client.rseclient.RSEClient.add_protocol
        rucio.client.rseclient.RSEClient.list_rses

        """
        path = 'rses/' + rse
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.POST, data=dumps(kwargs))
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
            Dictionary of properties to update. Format as
            {"name": "updated_value"}.
            Parameters are described in `rucio.client.rseclient.RSEClient.add_rse`.

        Returns
        -------
        True if RSE was updated successfully.

        Raises
        -------
        AccessDenied
            If the issuer cannot update the RSE.
        RSENotFound
            If the RSE does not exist.

        Examples
        --------
        ??? Example

            Correct the RSE type after an RSE has been made.

            ```python
            from rucio.client.client import Client

            rse_client = Client()
            rse_name="MyNewRSE"
            rse_client.add_rse(rse_name, rse_type="DISK")
            rse_client.update_rse(rse_name, rse_type="TAPE")

            ```

        See Also
        --------
        rucio.client.rseclient.RSEClient.delete_rse
        rucio.client.rseclient.RSEClient.add_rse
        rucio.client.rseclient.RSEClient.add_protocol

        """
        path = 'rses/' + rse
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.PUT, data=dumps(parameters))
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
        True if RSE was deleted successfully.

        Raises
        ------
        RSENotFound
            If the RSE was not found.
        RSEOperationNotSupported
            If the RSE is not empty.

        See Also
        --------
        rucio.client.rseclient.RSEClient.add_rse
        rucio.client.rseclient.RSEClient.update_rse
        """
        path = 'rses/' + rse
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.DELETE)
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_rses(self, rse_expression: Optional[str] = None) -> "Iterator[dict[str, Any]]":
        """
        List all RSEs that match the given RSE Expression.
        RSE Expressions are constructed using attributes, settings, and the name of the RSE, using logical operators and wildcards.


        Parameters
        ----------
        rse_expression
            RSE expression to use as filter.

        Returns
        -------
        All RSE names matching the RSE expression, if given, otherwise all RSEs with their settings.

        Examples
        --------
        ??? Example

            Print RSEs, either all on the instance or filtered by expression.

            ```python
            from rucio.client.client import Client
            rse_client = Client()

            for rse in rse_client.list_rses():
                print(rse)  # Print all RSEs with settings

            for rse in rse_client.list_rses("rse_type=TAPE"):
                print(rse) # Print all RSEs of type "TAPE".
                # Prints with {"rse": <RSE_NAME>}

            for rse in rse_client.list_rses("RSE_*"):
                print(rse) # Print all RSEs that have names starting with "RSE_"

            for rse in rse_client.list_rses("rse_type=DISK&availability_read=True"):
                print(rse) # Print all RSEs that are of type "DISK" and have read availability set to True

            ```

        See Also
        --------
        rucio.client.rseclient.RSEClient.get_rse
        """
        if rse_expression:
            path = ['rses', "?expression=" + quote(rse_expression)]
            path = '/'.join(path)
        else:
            path = 'rses/'
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.GET)
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
       Add an RSE attribute.
       Attributes are key/value pairs that can be used in policies, constructing RSE expressions, or defining custom properties (such as LFN2PFN algorithms.)

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
        True if RSE attribute was created successfully.

        Raises
        -------
        Duplicate
            If RSE attribute already exists.

        Examples
        --------
        ??? Example

            Add an attribute

            ```python
            from rucio.client.client import Client

            rse_client = Client()
            rse_name="MyRSE"
            rse_client.add_rse_attribute(rse_name, key="TIER", value="3")  # Custom organizational attribute

            ```

        See Also
        --------
        rucio.client.rseclient.RSEClient.delete_rse_attribute
        rucio.client.rseclient.RSEClient.get_rse
        rucio.client.rseclient.RSEClient.update_rse
        """
        path = '/'.join([self.RSE_BASEURL, rse, 'attr', key])
        url = build_url(choice(self.list_hosts), path=path)
        data = dumps({'value': value})

        r = self._send_request(url, method=HTTPMethod.POST, data=data)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def delete_rse_attribute(self, rse: str, key: str) -> Literal[True]:
        """
        Delete an RSE attribute.

        Parameters
        ----------
        rse
            The RSE name.
        key
            The attribute key.

        Returns
        -------
        True if RSE attribute was deleted successfully.

        Raises
        -------
        RSEAttributeNotFound
            If the attribute to delete was not found for the given RSE.

        Examples
        --------
        ??? Example

            Remove an attribute

            ```python
            from rucio.client.client import Client

            rse_client = Client()
            rse_name="MyRSE"
            rse_client.delete_rse_attribute(rse_name, key="TIER")

            ```

        See Also
        --------
        rucio.client.rseclient.RSEClient.add_rse_attribute
        rucio.client.rseclient.RSEClient.list_rse_attributes
        rucio.client.rseclient.RSEClient.update_rse
        """
        path = '/'.join([self.RSE_BASEURL, rse, 'attr', key])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, method=HTTPMethod.DELETE)
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_rse_attributes(self, rse: str) -> dict[str, Any]:
        """
       List all RSE attributes.

        Parameters
        ----------
        rse
            The RSE name.

        Returns
        -------
        A dict with the RSE attribute name/value pairs.
        Attributes returned can be any attribute previously added to the RSE via `rucio.client.rseclient.RSEClient.add_rse_attribute`.

        Raises
        ------
        RSENotFound
            RSE does not exist.

        Examples
        --------
        ??? Example
            List all attributes of an RSE
            ```python
            from rucio.client.client import Client
            rse_client = Client()
            rse_name="MyRSE"
            attributes = rse_client.list_rse_attributes(rse_name)
            for key, value in attributes.items():
                print(f"{key}: {value}")

            > TIER: 3
            > TEST: True
            ```

        See Also
        --------
        rucio.client.rseclient.RSEClient.add_rse_attribute
        rucio.client.rseclient.RSEClient.delete_rse_attribute
        """
        path = '/'.join([self.RSE_BASEURL, rse, 'attr/'])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.GET)
        if r.status_code == codes.ok:
            attributes = loads(r.text)
            return attributes
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def add_protocol(self, rse: str, params: dict[str, Any]) -> Literal[True]:
        """
        Add a new protocol for an RSE.
        This is required to read/write data onto the RSE.

        Multiple protocols can be added to the same RSE, but they cannot have the same scheme, hostname, and port.

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
            - domain: dict[Literal["lan", "wan"], dict] with the keys:
                - read: integer representing the priority of this protocol for read operations (default = -1)
                - write: integer representing the priority of this protocol for write operations (default = -1)
                - delete: integer representing the priority of this protocol for delete operations (default = -1)
                - third_party_copy_read
                - third_party_copy_write
            - extended_attributes: miscellaneous protocol specific information e.g. spacetoken for SRM (default = None)

            Extended attributes required for each protocol can be seen listed in the documentation for each protocol implementation
            (e.g. `rucio.rse.protocols.posix.Default` for the POSIX protocol).

        Returns
        -------
            True if protocol was created successfully.

        Raises
        ------
        Duplicate
            If protocol with same hostname, port and protocol identifier already exists for the given RSE.
        RSENotFound
            If the RSE doesn't exist.
        InvalidObject
            If params is missing mandatory attributes to create the protocol.
        AccessDenied
            If not authorized.

        Examples
        --------
        ??? Example

            Adding a POSIX protocol to an RSE, suitable for testing

            ```python
            from rucio.client.client import Client

            rse_client = Client()
            rse_name="MyRSE"
            protocol_params = {
                'scheme': 'file',
                'hostname': 'localhost',
                'port': 0,
                'prefix': '/path/posix_rse',
                'impl': 'rucio.rse.protocols.posix.Default',
                'domains': {
                    'lan': {'read': 1, 'write': 1, 'delete': 1},
                    'wan': {'read': 1, 'write': 1, 'delete': 1,
                            'third_party_copy_read': 1, 'third_party_copy_write': 1}
                },
            }
            rse_client.add_protocol(rse_name, protocol_params)

            ```

        See Also
        --------
        rucio.client.rseclient.RSEClient.get_rse
        rucio.client.rseclient.RSEClient.get_protocols
        rucio.client.rseclient.RSEClient.delete_protocols
        """
        scheme = params['scheme']
        path = '/'.join([self.RSE_BASEURL, rse, 'protocols', scheme])
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.POST, data=dumps(params))
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
        Get protocol information for an RSE

        Parameters
        ----------
        rse :
            The RSE name.
        protocol_domain :
            The scope of the protocol.
        operation :
            The name of the requested operation. If None, all operations are queried.
        default :
            Only return the default protocol
        scheme :
            The identifier of the requested protocol.

        Returns
        -------
            A list of dicts with details about each matching protocol.
            Each protocol contains the following keys:
            - scheme [str]: identifier
            - hostname [str]: hostname
            - port [int]: port
            - prefix [str]: string used as a prefix for this protocol when generating the PFN
            - impl [str]: qualified name of the implementation class for this protocol
            - domains [dict]: dictionary with domain (lan/wan) as keys and permissions for operations as values
            - extended_attributes [Optional[dict]]: miscellaneous protocol specific information

            If only one protocol matches the query, a single dict is returned instead of a list.

        Raises
        ------
        RSENotFound
            If the RSE doesn't exist.
        RSEProtocolNotSupported
            If no matching protocol entry could be found.
        RSEOperationNotSupported
            If no matching protocol entry for the requested operation could be found.

        Examples
        --------
        ??? Example

            Query different protocols that exist for MyRSE

            ```python
            from rucio.client.client import Client

            rse_client = Client()
            rse_name="MyRSE"
            rse_client.get_protocols(rse_name)  # Get all protocols
            rse_client.get_protocols(rse_name, default=True) # Get default protocol
            # Get protocols that can be used for read operations on wan domain
            rse_client.get_protocols(rse_name, protocol_domain='wan', operation='read')
            rse_client.get_protocols(rse_name, scheme='file') # Get protocol with file scheme
            ```

        See Also
        --------
        rucio.client.rseclient.RSEClient.get_rse
        rucio.client.rseclient.RSEClient.add_protocol
        rucio.client.rseclient.RSEClient.delete_protocols
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

        r = self._send_request(url, method=HTTPMethod.GET)
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
            LFNs are typically written as "scope:name", though the exact format can vary depending on
            the Rucio instance's implementation of ScopeExtraction.
            Contact your Rucio administrator if you are unsure about the expected format of LFNs for your instance.
        protocol_domain :
            The scope of the protocol. (e.g., 'wan' or 'lan').
        operation :
            The name of the requested operation (read, write, or delete).
            If None, 'write' is used by default.
        scheme :
            The identifier of the requested protocol (https, davs, etc), by default None.

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

        Examples
        --------
        ??? Example
        ```python

            from rucio.client.client import Client
            rse_client = Client()
            rse_name="MyRSE"
            lfns = ["scope1:name1", "scope2:name2"] # Exact format depends on ScopeExtraction implimentation for your rucio instance
            pfns = rse_client.lfns2pfns(rse_name, lfns)  # Get PFNs for the LFNs on MyRSE
            > {"scope1:name1": "protocol://host:port/prefix/scope1/name1",
            >  "scope2:name2": "protocol://host:port/prefix/scope2/name2"}

        ```
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

        r = self._send_request(url, method=HTTPMethod.GET)
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
        If not hostname and port and not provided, all protocols with the same scheme will be deleted.

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

        Examples
        --------
        ??? Example
            Delete a specific protocol by providing scheme, hostname, and port

            ```python
            from rucio.client.client import Client

            rse_client = Client()
            rse_name="MyRSE"
            # Only removes the protocol on host1:8443
            rse_client.delete_protocols(rse_name, scheme='srm', hostname='host1', port=8443)
            ```

            Delete all protocols with a specific scheme by providing only the scheme

            ```python
            from rucio.client.client import Client

            rse_client = Client()
            rse_name="MyRSE"
            # Removes all SRM protocols, regardless of hostname and port
            rse_client.delete_protocols(rse_name, scheme='srm')
            ```

        See Also
        --------
        rucio.client.rseclient.RSEClient.get_protocols
        rucio.client.rseclient.RSEClient.add_protocol
        """
        path = [self.RSE_BASEURL, rse, 'protocols', scheme]
        if hostname:
            path.append(hostname)
            if port:
                path.append(str(port))

        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.DELETE)
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
        Updates matching protocols from RSE.
        Protocols are uniquely defined by a combination of identifier, hostname, and port.
        If hostname and port are not provided, there must be a scheme without hostname and port.

        ** Note ** - You cannot change the hostname and port of a protocol.
        To change this, the protocol must be deleted and re-made with the new hostname and port.

        Parameters
        ----------
        rse:
            The RSE name.
        scheme:
            The identifier of the protocol.
        data:
            A dict providing the new values of the protocol attributes. Keys must match column names in database.
            ** domains **: Dict with domain (lan/wan) as keys and permissions for operations as values. Example: {"lan": {"read": 1, "write": 1, "delete": 1}, "wan": {"read": 1, "write": 1, "delete": 1}}
            ** prefix **: String used as a prefix for this protocol when generating the PFN.
            ** impl **: Qualified name of the implementation class for this protocol.
            ** extended_attributes **: Dict with protocol specific information

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
        AccessDenied
            If not authorized.

        Examples
        --------
        ??? Example

            Update the prefix attribute of a protocol

            ```python
            from rucio.client.client import Client
            rse_client = Client()
            rse_name="MyRSE"

            rse_client.get_protocols(rse_name, scheme='srm')
            > [{'scheme': 'srm', 'hostname': 'host1', 'port': 8443, 'prefix': '/old/prefix', ...},
            >  {'scheme': 'srm', 'hostname': 'host2', 'port': 8443, 'prefix': '/old/prefix', ...}]

            # The hostname and ports must be supplied
            rse_client.update_protocols(rse_name, scheme='srm', data={'prefix': '/new/prefix'})
            > rucio.common.exception.RSEProtocolNotSupported: RSE does not support requested protocol.
            > Details: RSE 'MyRse' does not support protocol 'srm' for hostname 'None' on port 'None'

            # Supply hostname and port to correctly update protocols
            rse_client.update_protocols(rse_name, scheme='srm', hostname="host1", port=8443,  data={'prefix': '/new/prefix'})
            ```

        See Also
        --------
        rucio.client.rseclient.RSEClient.get_protocols
        rucio.client.rseclient.RSEClient.add_protocol
        """
        path = [self.RSE_BASEURL, rse, 'protocols', scheme]
        if hostname:
            path.append(hostname)
            if port:
                path.append(str(port))

        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.PUT, data=dumps(data))
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
            True if successful, False if there are not protocols cannot be cleanly swapped

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
        self.update_protocols(rse, protocol_a['scheme'], {'domains': {domain: {operation: priority_b}}},
                              protocol_a['hostname'], protocol_a['port'])
        self.update_protocols(rse, protocol_b['scheme'], {'domains': {domain: {operation: priority_a}}},
                              protocol_b['hostname'], protocol_b['port'])
        return True

    # TODO Remove QoS functionality, #8509
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
        r = self._send_request(url, method=HTTPMethod.POST)
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
        r = self._send_request(url, method=HTTPMethod.DELETE)
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
        r = self._send_request(url, method=HTTPMethod.GET)
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
        Added to the history of the RSE usage, for monitoring and accounting.

        Parameters
        ----------
        rse:
            The RSE name.
        source:
            The information source, any string used for accounting and documenting source of usage inforrmation
        used:
            The used space in bytes
        free:
            The free space in bytes
        files:
            The number of files, optional.

        Returns
        -------
        True if successful

        Examples
        --------
        ??? Example
            Set RSE usage information

            ```python
            from rucio.client.client import Client
            Client().set_rse_usage("MyRse", source="automated_script", used=1000000000, free=500000000)
            ```

        See Also
        --------
        rucio.client.rseclient.RSEClient.get_rse_usage
        rucio.client.rseclient.RSEClient.list_rse_usage_history
        """
        path = [self.RSE_BASEURL, rse, 'usage']
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        data = {'source': source, 'used': used, 'free': free, 'files': files}
        r = self._send_request(url, method=HTTPMethod.PUT, data=dumps(data))
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
        Get RSE usage information as set by `RSEClient.set_rse_usage`. Will only show the most recent usage of a source.

        Parameters
        ----------
        rse:
            The RSE name.
        filters:
            Optional filters to apply.
                ** source ** [str]: Source of usage
                ** per_account ** [bool]: Calculate usage by account

        Returns
        -------
        List of dictionaries, containing the following:
            ** rse_id ** [str]: The RSE id
            ** source ** [str]: Source of usage
            ** used ** [int]: Used space in bytes
            ** free ** [int]: Free space in bytes
            ** files ** [int|None]: Number of files
            ** updated_at ** [datetime.datetime]: Timestamp of the usage information

        See Also
        --------
        rucio.client.rseclient.RSEClient.set_rse_usage
        rucio.client.rseclient.RSEClient.list_rse_usage_history
        """
        path = [self.RSE_BASEURL, rse, 'usage']
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.GET, params=filters)
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
            Optional filters to apply.
                ** source ** [str]: Source of usage

        Returns
        -------
        List of dictionaries, containing the following:
            ** rse_id ** [str]: The RSE id
            ** source ** [str]: Source of usage
            ** used ** [int]: Used space in bytes
            ** free ** [int]: Free space in bytes
            ** files ** [int|None]: Number of files
            ** updated_at ** [datetime.datetime]: Timestamp of the usage information
        Will show all historical usage information for the RSE, including the current usage information as set by `RSEClient.set_rse_usage`

        See Also
        --------
        rucio.client.rseclient.RSEClient.set_rse_usage
        rucio.client.rseclient.RSEClient.list_rse_usage_history
        """
        path = [self.RSE_BASEURL, rse, 'usage', 'history']
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.GET, params=filters)
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
        Set the limit for the amount of data that can be stored on the RSE.
        If an RSE limit with the same name already exists, it will be overwritten.

        The name "MaxSpaceAvailable" will be used to when selecting RSEs create replicas
        if multiple RSEs match rule requirements and have the avaiable quotas.


        Parameters
        ----------
        rse:
            The RSE name.
        name:
            The name of the limit.
        value:
            Limit given in bytes.

        Returns
        -------
        True if successful.


        Examples
        --------
        ??? Example
            Set a limit for the amount of data that can be stored on an RSE
            ```python
            from rucio.client.client import Client
            rse_client = Client()
            rse_name="MyRSE"
            rse_client.set_rse_limits(rse_name, name="MaxSpaceAvailable", value=1000000000000)  # Set a limit of 1TB for the RSE
            ```

        See Also
        --------
        rucio.client.rseclient.RSEClient.get_rse_limits
        rucio.client.rseclient.RSEClient.delete_rse_limits
        """
        path = [self.RSE_BASEURL, rse, 'limits']
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.PUT, data=dumps({'name': name, 'value': value}))
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
        Dictionaries with the name and value of each limit for the RSE.

        Examples
        --------
        ??? Example
            Get RSE limits
            ```python
            from rucio.client.client import Client
            rse_client = Client()
            rse_name="MyRSE"
            rse_client.get_rse_limits(rse_name)
            > {"MaxSpaceAvailable": 1000000000000, "AnotherLimit": 500000000000}


        See Also
        --------
        rucio.client.rseclient.RSEClient.set_rse_limits
        rucio.client.rseclient.RSEClient.delete_rse_limits
        """
        path = [self.RSE_BASEURL, rse, 'limits']
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.GET)
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
            The name of the limit, can be any limit made with `set_rse_limits`.

        Returns
        -------
        True if successful, will not fail if the limit did not exist.

        Raises
        ------
        RSENotFound
            If the RSE doesn't exist.

        See Also
        --------
        rucio.client.rseclient.RSEClient.set_rse_limits
        rucio.client.rseclient.RSEClient.get_rse_limits
        """
        path = [self.RSE_BASEURL, rse, 'limits']
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.DELETE, data=dumps({'name': name}))
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
        parameters: dict[str, int],
        bidirectional: bool = False
    ) -> Literal[True]:
        """
        Add a distance between two RSEs.
        Distances are used to deterimine paths between RSEs during transfers, a lower distance will be preferred over a higher one.

        RSEs must have distances between them for them to be used in multi-hop transfers.

        Parameters
        ----------
        source :
            The source RSE name.
        destination :
            The destination RSE name.
        parameters :
            Dicionary in the format {"distance": int}.
        bidirectional:
            If True, also adds the distance from dest to src.

        Returns
        -------
        True if successful.

        Raises
        ------
        Duplicate
            If a distance between the RSEs already exists.
        RSENotFound
            If either of the RSEs doesn't exist.

        Examples
        --------
        ??? Example
            Add a distance between two RSEs
            ```python
            from rucio.client.client import Client
            rse_client = Client()
            rse_client.add_distance(source="RSE1", destination="RSE2", parameters={"distance": 10})
            ```
        """
        path = [self.RSE_BASEURL, source, 'distances', destination]
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        parameters["bidirectional"] = bidirectional
        r = self._send_request(url, method=HTTPMethod.POST, data=dumps(parameters))
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
        parameters: dict[str, int],
        bidirectional: bool = False
    ) -> Literal[True]:
        """
        Update distances between RSEs.

        If the distance does not exist, it will not be created.

        Parameters
        ----------
        source :
            The source RSE.
        destination :
            The destination RSE.
        parameters :
            Updated distance in the form {"distance": int}.
        bidirectional :
            If True, also updates the distance from dest to src.

        Returns
        -------
        True if successful.

        Examples
        --------
        ??? Example
            Add a distance between two RSEs
            ```python
            from rucio.client.client import Client
            rse_client = Client()
            rse_client.add_distance(source="RSE1", destination="RSE2", parameters={"distance": 10})
            rse_client.update_distance(source="RSE1", destination="RSE2", parameters={"distance": 20})  # Update the distance to 20
            ```

        See Also
        --------
        rucio.client.rseclient.RSEClient.add_distance
        """
        path = [self.RSE_BASEURL, source, 'distances', destination]
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        parameters["bidirectional"] = bidirectional
        r = self._send_request(url, method=HTTPMethod.PUT, data=dumps(parameters))
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
            Each dictionary contains the following keys:
            ** created_at ** [datetime.datetime]: Datetime when the distance was created.
            ** updated_at ** [datetime.datetime]: Datetime when the distance was last updated.
            ** src_rse_id ** [str]:  ID of the source RSE.
            ** src_rse ** [str]: Name of source RSE.
            ** dest_rse_id ** [str]: ID of the destination RSE.
            ** dest_rse ** [str]: Name of destination RSE.
            ** distance ** [int]: Value of distance between RSEs.
            ** ranking ** [int]: Legacy name for distance, same value as distance.

        """
        path = [self.RSE_BASEURL, source, 'distances', destination]
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, method=HTTPMethod.GET)
        if r.status_code == codes.ok:
            return next(self._load_json_data(r))
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def delete_distance(
        self,
        source: str,
        destination: str,
        bidirectional: bool = False
    ) -> Literal[True]:
        """
        Delete distances with the given RSE ids.

        Parameters
        ----------
        source :
            The source
        destination :
            The destination
        bidirectional :
            If True, also deletes the distance from dest to src.

        Returns
        -------
            True if successful.

        Raises
        ------
        RSENotFound
            If either of the RSEs doesn't exist.
        """
        path = [self.RSE_BASEURL, source, 'distances', destination]
        path = '/'.join(path)
        params = {'bidirectional': bidirectional}
        url = build_url(choice(self.list_hosts), path=path, params=params)
        r = self._send_request(url, method=HTTPMethod.DELETE)
        if r.status_code == codes.ok:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers,
                                               status_code=r.status_code,
                                               data=r.content)
        raise exc_cls(exc_msg)
