# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Mario Lassnig, <mario.lassnig@cern.ch>, 2013
# - Ralph Vigne, <ralph.vigne@cern.ch>, 2013

from json import dumps, loads
from requests.status_codes import codes

from rucio.client.baseclient import BaseClient
from rucio.common.utils import build_url


class RSEClient(BaseClient):
    """RSE client class for working with rucio RSEs"""

    RSE_BASEURL = 'rses'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None):
        super(RSEClient, self).__init__(rucio_host, auth_host, account, ca_cert, auth_type, creds, timeout)

    def add_rse(self, rse, prefix=None, deterministic=True, volatile=False):
        """
        Sends the request to create a new rse.

        :param rse: the name of the rse.
        :param prefix: the base path of the rse.
        :param deterministic: Boolean to know if the pfn is generated deterministically.
        :param volatile: Boolean for RSE cache.

        :return: True if location was created successfully else False.
        :raises Duplicate: if rse already exists.
        """

        headers = {'Rucio-Auth-Token': self.auth_token}
        path = 'rses/' + rse
        url = build_url(self.host, path=path)

        data = dumps({'prefix': prefix, 'volatile': volatile, 'deterministic': deterministic})

        r = self._send_request(url, headers, type='POST', data=data)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def delete_rse(self, rse):
        """
        Sends the request to delete a rse.

        :param rse: the name of the rse.
        :return: True if location was created successfully else False.
        """

        headers = {'Rucio-Auth-Token': self.auth_token}
        path = 'rses/' + rse
        url = build_url(self.host, path=path)
        r = self._send_request(url, headers, type='DEL')
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def list_rses(self, filters=None):
        """
        Sends the request to list all rucio locations(RSEs).

        :filters: dict of keys & expected values to filter results

        :return: a list containing the names of all rucio locations.
        :raises AccountNotFound: if account doesn't exist.
        """

        headers = {'Rucio-Auth-Token': self.auth_token}
        path = 'rses/'
        url = build_url(self.host, path=path)

        r = self._send_request(url, headers)
        if r.status_code == codes.ok:
            accounts = loads(r.text)
            return accounts
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
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
        url = build_url(self.host, path=path)
        data = dumps({'value': value})

        r = self._send_request(url, type='POST', data=data)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def delete_rse_attribute(self, rse, key):
        """
        Sends the request to delete a RSE attribute.

        :param rse: the name of the rse.
        :param key: the attribute key.

        :return: True if RSE attribute was deleted successfully else False.
        """
        path = '/'.join([self.RSE_BASEURL, rse, 'attr', key])
        url = build_url(self.host, path=path)

        r = self._send_request(url, type='DEL')
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def list_rse_attributes(self, rse):
        """
        Sends the request to get RSE attributes.

        :param rse: the name of the rse.

        :return: True if RSE attribute was created successfully else False.
        """
        path = '/'.join([self.RSE_BASEURL, rse, 'attr/'])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='GET')
        if r.status_code == codes.ok:
            attributes = loads(r.text)
            return attributes
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def add_file_replica(self, rse, scope, name, size,  adler32=None, md5=None, pfn=None, dsn=None):
        """
        Add a file replica to a RSE.

        :param rse: the name of the rse.
        :param scope: the name of the scope.
        :param name: the data identifier name.
        :param size: the size of the file.
        :param md5: The md5 checksum.
        :param adler32: The adler32 checksum.
        :param pfn: the physical file name for non deterministic rse.
        :param dsn: the dataset name.

        :return: True if file was created successfully else False.
        :raises Duplicate: if file replica already exists.
        """
        data = dumps({'size': size, 'md5': md5, 'adler32': adler32, 'pfn': pfn, 'dsn': dsn})
        path = '/'.join([self.RSE_BASEURL, rse, 'files', scope, name])
        url = build_url(self.host, path=path)
        r = self._send_request(url, type='POST', data=data)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def add_protocol(self, rse, protocol, params):
        """
        Sends the request to create a new protocol for the given RSE.

        :param rse: the name of the  rse.
        :param protocol: identifier of this protocol
        :param params: Attributes of the protocol. Supported are:
            hostname:       hostname for this protocol (default = localhost)
            port:           port for this protocol (default = 0)
            prefix:         string used as a prfeix for this protocol when generating
                            the PFN (default = None)
            impl:           qualified name of the implementation class for this
                            protocol (mandatory)
            read:           integer representing the priority of this procotol for
                            read operations (default = -1)
            write:          integer representing the priority of this procotol for
                            write operations (default = -1)
            delete:         integer representing the priority of this procotol for
                            delet operations (default = -1)
            extended_attributes:  miscellaneous protocol specific information e.g. spacetoken
                            for SRM (default = None)


        :return: True if protocol was created successfully else False.

        :raises Duplicate: if protocol with same hostname, port and protocol identifier
                            already exists for the given RSE.
        :raises RSENotFound: if the RSE doesn't exist.
        :raises KeyNotFound: if params is missing manadtory attributes to create the
                             protocol.
        :raises AccessDenied: if not authorized.
        """
        headers = {'Rucio-Auth-Token': self.auth_token}
        path = '/'.join([self.RSE_BASEURL, rse, 'protocols', protocol])
        url = build_url(self.host, path=path)
        data = dumps(params)
        r = self._send_request(url, headers, type='POST', data=data)
        if r.status_code == codes.created:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def get_protocols(self, rse, operation=None, default=False, protocol=None):
        """
        Returns protocol information. Parameter comibantions are:
        (operation OR default) XOR protocol.

        :param rse: The name of the rse.
        :param operation: The name of the requested operation (read, write, or delete).
                          If None, all operations are queried.
        :param default: Indicates if only the default operations should be returned.
        :param protocol: The identifier of the requested protocol.

        :returns: A list with details about each matching protocol.

        :raises RSENotFound: if the RSE doesn't exist.
        :raises RSEProtocolNotSupported: if no matching protocol entry could be found.
        :raises RSEOperationNotSupported: if no matching protocol entry for the requested
                                          operation could be found.
        """

        headers = {'Rucio-Auth-Token': self.auth_token}
        path = None
        params = {}
        if protocol:
            path = '/'.join([self.RSE_BASEURL, rse, 'protocols', protocol])
        else:
            path = '/'.join([self.RSE_BASEURL, rse, 'protocols'])
            if operation:
                params['operation'] = operation
            if default:
                params['default'] = default
        url = build_url(self.host, path=path, params=params)

        r = self._send_request(url, headers, type='GET')
        if r.status_code == codes.ok:
            protocols = loads(r.text)
            return protocols
        else:
            exc_cls, exc_msg = self._get_exception(r.headers)
            raise exc_cls(exc_msg)

    def delete_protocols(self, rse, protocol, hostname=None, port=None):
        """
        Deletes matching protocols from RSE. Protocols using the same identifier can be
        distinguished by hostname and port.

        :param rse: the name of the  rse.
        :param protocol: identifier of the protocol.
        :param hostname: hostname of the protocol.
        :param port: port of the protocol.

        :returns: True if success.

        :raises RSEProtocolNotSupported: if no matching protocol entry could be found.
        :raises RSENotFound: if the RSE doesn't exist.
        :raises AccessDenied: if not authorized.
        """

        headers = {'Rucio-Auth-Token': self.auth_token}
        path = [self.RSE_BASEURL, rse, 'protocols', protocol]
        if hostname:
            path.append(hostname)
            if port:
                path.append(str(port))

        path = '/'.join(path)
        url = build_url(self.host, path=path)
        r = self._send_request(url, headers, type='DEL')
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)

    def update_protocols(self, rse, protocol, data, hostname=None, port=None):
        """
        Updates matching protocols from RSE. Protocol using the same identifier can be
        distinguished by hostname and port.

        :param rse: the name of the  rse.
        :param protocol: identifier of the protocol.
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

        headers = {'Rucio-Auth-Token': self.auth_token}
        path = [self.RSE_BASEURL, rse, 'protocols', protocol]
        if hostname:
            path.append(hostname)
            if port:
                path.append(str(port))

        path = '/'.join(path)
        url = build_url(self.host, path=path)
        r = self._send_request(url, headers, type='PUT', data=dumps(data))
        if r.status_code == codes.ok:
            return True
        else:
            exc_cls, exc_msg = self._get_exception(r.headers, r.status_code)
            raise exc_cls(exc_msg)
