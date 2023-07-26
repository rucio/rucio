# -*- coding: utf-8 -*-
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
from urllib.parse import quote

from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.client.baseclient import choice
from rucio.common.utils import build_url


class RSEClient(BaseClient):
    """RSE client class for working with rucio RSEs"""

    RSE_BASEURL = 'rses'

    def get_rse(self, rse):
        """
        Returns details about the referred RSE.

        :param rse: Name of the referred RSE

        :returns: A dict containing all attributes of the referred RSE

        :raises RSENotFound: if the referred RSE was not found in the database
        """
        path = '/'.join([self.RSE_BASEURL, rse])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            rse = loads(r.text)
            return rse
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def add_rse(self, rse, **kwargs):
        """
        Sends the request to create a new RSE.

        :param rse: the name of the rse.
        :param deterministic: Boolean to know if the pfn is generated deterministically.
        :param volatile: Boolean for RSE cache.
        :param city: City for the RSE.
        :param region_code: The region code for the RSE.
        :param country_name: The country.
        :param continent: The continent.
        :param time_zone: Timezone.
        :param staging_area: Staging area.
        :param ISP: Internet service provider.
        :param rse_type: RSE type.
        :param latitude: Latitude coordinate of RSE.
        :param longitude: Longitude coordinate of RSE.
        :param ASN: Access service network.
        :param availability: Availability.

        :return: True if location was created successfully else False.
        :raises Duplicate: if rse already exists.
        """
        path = 'rses/' + rse
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='POST', data=dumps(kwargs))
        if r.status_code == codes.created:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def update_rse(self, rse, parameters):
        """
        Update RSE properties like availability or name.

        :param rse: the name of the new rse.
        :param  parameters: A dictionnary with property (name, read, write, delete as keys).
        """
        path = 'rses/' + rse
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='PUT', data=dumps(parameters))
        if r.status_code == codes.created:
            return True
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def delete_rse(self, rse):
        """
        Sends the request to delete a rse.

        :param rse: the name of the rse.
        :return: True if location was created successfully else False.
        """
        path = 'rses/' + rse
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='DEL')
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_rses(self, rse_expression=None):
        """
        Sends the request to list all rucio locations(RSEs).

        :rse_expression: RSE Expression to use as filter.
        :return:         a list containing the names of all rucio locations.
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

    def add_rse_attribute(self, rse, key, value):
        """
        Sends the request to add a RSE attribute.

        :param rse: the name of the rse.
        :param key: the attribute key.
        :param value: the attribute value.

        :return: True if RSE attribute was created successfully else False.
        :raises Duplicate: if RSE attribute already exists.
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

    def delete_rse_attribute(self, rse, key):
        """
        Sends the request to delete a RSE attribute.

        :param rse: the RSE name.
        :param key: the attribute key.

        :return: True if RSE attribute was deleted successfully else False.
        """
        path = '/'.join([self.RSE_BASEURL, rse, 'attr', key])
        url = build_url(choice(self.list_hosts), path=path)

        r = self._send_request(url, type_='DEL')
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
            raise exc_cls(exc_msg)

    def list_rse_attributes(self, rse):
        """
        Sends the request to get RSE attributes.

        :param rse: The RSE name.

        :return: A ``dict`` with the RSE attribute name/value pairs.
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

    def add_protocol(self, rse, params):
        """
        Sends the request to create a new protocol for the given RSE.

        :param rse: the name of the  rse.
        :param scheme: identifier of this protocol
        :param params: Attributes of the protocol. Supported are:
            hostname:       hostname for this protocol (default = localhost)
            port:           port for this protocol (default = 0)
            prefix:         string used as a prfeix for this protocol when generating the PFN (default = None)
            impl:           qualified name of the implementation class for this protocol (mandatory)
            read:           integer representing the priority of this procotol for read operations (default = -1)
            write:          integer representing the priority of this procotol for write operations (default = -1)
            delete:         integer representing the priority of this procotol for delete operations (default = -1)
            extended_attributes:  miscellaneous protocol specific information e.g. spacetoken for SRM (default = None)

        :return: True if protocol was created successfully else False.

        :raises Duplicate: if protocol with same hostname, port and protocol identifier
                            already exists for the given RSE.
        :raises RSENotFound: if the RSE doesn't exist.
        :raises KeyNotFound: if params is missing manadtory attributes to create the
                             protocol.
        :raises AccessDenied: if not authorized.
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

    def get_protocols(self, rse, protocol_domain='ALL', operation=None, default=False, scheme=None):
        """
        Returns protocol information. Parameter comibantions are:
        (operation OR default) XOR protocol.

        :param rse: the RSE name.
        :param protocol_domain: The scope of the protocol. Supported are 'LAN', 'WAN', and 'ALL' (as default).
        :param operation: The name of the requested operation (read, write, or delete).
                          If None, all operations are queried.
        :param default: Indicates if only the default operations should be returned.
        :param scheme: The identifier of the requested protocol.

        :returns: A list with details about each matching protocol.

        :raises RSENotFound: if the RSE doesn't exist.
        :raises RSEProtocolNotSupported: if no matching protocol entry could be found.
        :raises RSEOperationNotSupported: if no matching protocol entry for the requested
                                          operation could be found.
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

    def lfns2pfns(self, rse, lfns, protocol_domain='ALL', operation=None, scheme=None):
        """
        Returns PFNs that should be used at a RSE, corresponding to requested LFNs.
        The PFNs are generated for the RSE *regardless* of whether a replica exists for the LFN.

        :param rse: the RSE name
        :param lfns: A list of LFN strings to translate to PFNs.
        :param protocol_domain: The scope of the protocol. Supported are 'LAN', 'WAN', and 'ALL' (as default).
        :param operation: The name of the requested operation (read, write, or delete).
                          If None, all operations are queried.
        :param scheme: The identifier of the requested protocol (gsiftp, https, davs, etc).

        :returns: A dictionary of LFN / PFN pairs.
        :raises RSENotFound: if the RSE doesn't exist.
        :raises RSEProtocolNotSupported: if no matching protocol entry could be found.
        :raises RSEOperationNotSupported: if no matching protocol entry for the requested
                                          operation could be found.
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

    def delete_protocols(self, rse, scheme, hostname=None, port=None):
        """
        Deletes matching protocols from RSE. Protocols using the same identifier can be
        distinguished by hostname and port.

        :param rse: the RSE name.
        :param scheme: identifier of the protocol.
        :param hostname: hostname of the protocol.
        :param port: port of the protocol.

        :returns: True if success.

        :raises RSEProtocolNotSupported: if no matching protocol entry could be found.
        :raises RSENotFound: if the RSE doesn't exist.
        :raises AccessDenied: if not authorized.
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

    def update_protocols(self, rse, scheme, data, hostname=None, port=None):
        """
        Updates matching protocols from RSE. Protocol using the same identifier can be
        distinguished by hostname and port.

        :param rse: the RSE name.
        :param scheme: identifier of the protocol.
        :param data: A dict providing the new values of the protocol attibutes.
                     Keys must match column names in database.
        :param hostname: hostname of the protocol.
        :param port: port of the protocol.

        :returns: True if success.

        :raises RSEProtocolNotSupported: if no matching protocol entry could be found.
        :raises RSENotFound: if the RSE doesn't exist.
        :raises KeyNotFound: if invalid data was provided for update.
        :raises AccessDenied: if not authorized.
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

    def swap_protocols(self, rse, domain, operation, scheme_a, scheme_b):
        """
        Swaps the priorities of the provided operation.

        :param rse: the RSE name.
        :param domain: the domain in which priorities should be swapped i.e. wan or lan.
        :param operation: the operation that should be swapped i.e. read, write, or delete.
        :param scheme_a: the scheme of one of the two protocols to be swapped, e.g. srm.
        :param scheme_b: the scheme of the other of the two protocols to be swapped, e.g. http.

        :returns: True if success.

        :raises RSEProtocolNotSupported: if no matching protocol entry could be found.
        :raises RSENotFound: if the RSE doesn't exist.
        :raises KeyNotFound: if invalid data was provided for update.
        :raises AccessDenied: if not authorized.
        """
        protocol_a = protocol_b = None
        protocols = self.get_protocols(rse, domain, operation, False, scheme_a)['protocols']
        for p in protocols:
            if p['scheme'] == scheme_a:
                protocol_a = p
            if p['scheme'] == scheme_b:
                protocol_b = p
        if (protocol_a or protocol_b) is None:
            return False
        priority_a = protocol_a['domains'][domain][operation]
        priority_b = protocol_b['domains'][domain][operation]
        self.update_protocols(rse, protocol_a['scheme'], {'domains': {domain: {operation: priority_b}}}, protocol_a['hostname'], protocol_a['port'])
        self.update_protocols(rse, protocol_b['scheme'], {'domains': {domain: {operation: priority_a}}}, protocol_b['hostname'], protocol_b['port'])
        return True

    def add_qos_policy(self, rse, qos_policy):
        """
        Add a QoS policy from an RSE.

        :param rse_id: The id of the RSE.
        :param qos_policy: The QoS policy to add.
        :param session: The database session in use.

        :raises Duplicate: If the QoS policy already exists.
        :returns: True if successful, except otherwise.
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

    def delete_qos_policy(self, rse, qos_policy):
        """
        Delete a QoS policy from an RSE.

        :param rse_id: The id of the RSE.
        :param qos_policy: The QoS policy to delete.
        :param session: The database session in use.

        :returns: True if successful, silent failure if QoS policy does not exist.
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

    def list_qos_policies(self, rse):
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

    def set_rse_usage(self, rse, source, used, free, files=None):
        """
        Set RSE usage information.

        :param rse: the RSE name.
        :param source: the information source, e.g. srm.
        :param used: the used space in bytes.
        :param free: the free in bytes.
        :param files: the number of files

        :returns: True if successful, otherwise false.
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

    def get_rse_usage(self, rse, filters=None):
        """
        Get RSE usage information.

        :param rse: the RSE name.
        :param filters: dictionary of attributes by which the results should be filtered

        :returns: True if successful, otherwise false.
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

    def list_rse_usage_history(self, rse, filters=None):
        """
        List RSE usage history information.

        :param rse: The RSE name.
        :param filters: dictionary of attributes by which the results should be filtered.

        :returns:  list of dictionnaries.
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

    def set_rse_limits(self, rse, name, value):
        """
        Set RSE limit information.

        :param rse: The RSE name.
        :param name: The name of the limit.
        :param value: The feature value.

        :returns: True if successful, otherwise false.
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

    def get_rse_limits(self, rse):
        """
        Get RSE limits.

        :param rse: The RSE name.

        :returns: True if successful, otherwise false.
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

    def delete_rse_limits(self, rse, name):
        """
        Delete RSE limit information.

        :param rse: The RSE name.
        :param name: The name of the limit.

        :returns: True if successful, otherwise false.
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

        return exc_cls(exc_msg)

    def add_distance(self, source, destination, parameters):
        """
        Add a src-dest distance.

        :param source: The source.
        :param destination: The destination.
        :param parameters: A dictionnary with property.
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

    def update_distance(self, source, destination, parameters):
        """
        Update distances with the given RSE ids.

        :param source: The source.
        :param destination: The destination.
        :param parameters: A dictionnary with property.
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

    def get_distance(self, source, destination):
        """
        Get distances between rses.

        :param source: The source RSE.
        :param destination: The destination RSE.

        :returns distance: List of dictionaries.
        """
        path = [self.RSE_BASEURL, source, 'distances', destination]
        path = '/'.join(path)
        url = build_url(choice(self.list_hosts), path=path)
        r = self._send_request(url, type_='GET')
        if r.status_code == codes.ok:
            return next(self._load_json_data(r))
        exc_cls, exc_msg = self._get_exception(headers=r.headers, status_code=r.status_code, data=r.content)
        raise exc_cls(exc_msg)

    def delete_distance(self, source, destination):
        """
        Delete distances with the given RSE ids.

        :param source: The source.
        :param destination: The destination.
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
