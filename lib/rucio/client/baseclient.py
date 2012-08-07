# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012


"""
Client class for callers of the Rucio system
"""

from logging import getLogger, StreamHandler, ERROR
from os import chmod, environ, mkdir, path

from ConfigParser import NoOptionError, NoSectionError
from requests import delete, get, post, put
from requests.auth import HTTPKerberosAuth
from requests.status_codes import codes
from requests.exceptions import SSLError

from rucio.common import exception
from rucio.common.config import config_get
from rucio.common.exception import CannotAuthenticate, NoAuthInformation, MissingClientParameter, RucioException
from rucio.common.utils import build_url

LOG = getLogger(__name__)
sh = StreamHandler()
sh.setLevel(ERROR)
LOG.addHandler(sh)


class BaseClient(object):

    """Main client class for accessing Rucio resources. Handles the authentication."""

    AUTH_RETRIES = 2
    TOKEN_PATH = '/tmp/rucio'
    TOKEN_PREFIX = 'auth_token_'

    def __init__(self, rucio_host=None, rucio_port=None, auth_host=None, auth_port=None, account=None, use_ssl=True, ca_cert=None, auth_type=None, creds=None, timeout=None):
        """
        Constructor of the BaseClient.
        :param rucio_host: the address of the rucio server, if None it is read from the config file.
        :param rucio_port: the port of the rucio server, if None it is read from the config file.
        :param auth_host: the address of the rucio authentication server, if None it is read from the config file.
        :param auth_port: the port of the rucio authentication server, if None it is read from the config file.
        :param account: the account to authenticate to rucio.
        :param use_ssl: enable or disable ssl for commucation. Default is enabled.
        :param ca_cert: the path to the rucio server certificate.
        :param auth_type: the type of authentication (e.g.: 'userpass', 'kerberos' ...)
        :param creds: a dictionary with credentials needed for authentication.
        """
        self.host = rucio_host
        self.port = rucio_port
        self.auth_host = auth_host
        self.auth_port = auth_port

        try:
            if self.host is None:
                self.host = config_get('client', 'rucio_host')
            if self.port is None:
                self.port = config_get('client', 'rucio_port')
            if self.auth_host is None:
                self.auth_host = config_get('client', 'auth_host')
            if self.auth_port is None:
                self.auth_port = config_get('client', 'auth_port')
        except (NoOptionError, NoSectionError), e:
            raise MissingClientParameter('Section client and Option \'%s\' cannot be found in config file' % e.args[0])

        self.account = account
        self.use_ssl = use_ssl
        self.ca_cert = ca_cert
        self.auth_type = auth_type
        self.creds = creds
        self.auth_token = None
        self.headers = {}
        self.timeout = None

        if auth_type is None:
            LOG.debug('no auth_type passed. Trying to get it from the config file.')
            try:
                self.auth_type = config_get('client', 'auth_type')
            except (NoOptionError, NoSectionError), e:
                raise MissingClientParameter('Option \'%s\' cannot be found in config file' % e.args[0])

        if creds is None:
            LOG.debug('no creds passed. Trying to get it from the config file.')
            self.creds = {}
            try:
                if self.auth_type == 'userpass':
                    self.creds['username'] = config_get('client', 'username')
                    self.creds['password'] = config_get('client', 'password')
                elif self.auth_type == 'x509':
                    self.creds['client_cert'] = config_get('client', 'client_cert')
            except (NoOptionError, NoSectionError), e:
                raise MissingClientParameter('Option \'%s\' cannot be found in config file' % e.args[0])

        if use_ssl and ca_cert is None:
            LOG.debug('no ca_cert passed. Trying to get it from the config file.')
            try:
                self.ca_cert = config_get('client', 'ca_cert')
            except (NoOptionError, NoSectionError), e:
                raise MissingClientParameter('Option \'%s\' cannot be found in config file' % e.args[0])

        if account is None:
            LOG.debug('no account passed. Trying to get it from the config file.')
            try:
                self.account = config_get('client', 'account')
            except (NoOptionError, NoSectionError), e:
                try:
                    self.account = environ['RUCIO_ACCOUNT']
                except KeyError:
                    raise MissingClientParameter('Option \'account\' cannot be found in config file and RUCIO_ACCOUNT is not set.')
        self.__authenticate()

    def _get_exception(self, headers):
        """
        Helper method to parse an error string send by the server and transform it into the corresponding rucio exception.

        :param headers: The http response header containing the Rucio exception details.
        :return: A rucio exception class and an error string.
        """
        if 'ExceptionClass' not in headers:
            if 'ExceptionMessage' not in headers:
                return getattr(exception, 'RucioException'), 'no error information passed'
            return getattr(exception, 'RucioException'), headers['ExceptionMessage']

        exc_cls = None
        try:
            exc_cls = getattr(exception, headers['ExceptionClass'])
        except AttributeError:
            return getattr(exception, 'RucioException'), headers['ExceptionMessage']

        return exc_cls, headers['ExceptionMessage']

    def _send_request(self, url, headers=None, type='GET', data=None, retries=3):
        """
        Helper method to send requests to the rucio server. Gets a new token and retries if an unauthorized error is returned.

        :param url: the http url to use.
        :param headers: additional http headers to send.
        :param type: the http request type to use.
        :param data: post data.
        :param retries: number of retries in case of unauthorized.
        :return: the HTTP return body.
        """

        r = None
        retry = 0
        hds = {'Rucio-Auth-Token': self.auth_token}

        if headers is not None:
            hds.update(headers)

        while retry < retries:
            try:
                if type == 'GET':
                    r = get(url, headers=hds, verify=self.ca_cert, timeout=self.timeout)
                elif type == 'PUT':
                    r = put(url, headers=hds, verify=self.ca_cert, timeout=self.timeout)
                elif type == 'POST':
                    r = post(url, headers=hds, data=data, verify=self.ca_cert, timeout=self.timeout)
                elif type == 'DEL':
                    r = delete(url, headers=hds, verify=self.ca_cert, timeout=self.timeout)
                else:
                    return
            except SSLError:
                LOG.warning('Couldn\'t verify ca cert. Using unverified connection')
                self.ca_cert = False
                retry += 1
                continue

            if r.status_code == codes.unauthorized:
                self.__get_token()
                hds['Rucio-Auth-Token'] = self.auth_token
                retry += 1
            else:
                break

        return r

    def __get_token_userpass(self):
        """
        Sends a request to get an auth token from the server. Uses username/password.

        :param username: the username to authenticate with the system.
        :param password: the password to authenticate with the system.
        :return: the auth token as a string, None if not authorized or raises an exeption if some failure occurs.
        """

        headers = {'Rucio-Account': self.account, 'Rucio-Username': self.creds['username'], 'Rucio-Password': self.creds['password']}
        url = build_url(self.auth_host, port=self.auth_port, path='auth/userpass', use_ssl=self.use_ssl)

        retry = 0
        while retry < self.AUTH_RETRIES:
            try:
                r = get(url, headers=headers, verify=self.ca_cert)
            except SSLError:
                LOG.warning('Couldn\'t verify ca cert. Using unverified connection')
                self.ca_cert = False
                retry += 1
                continue
            break

        if retry == 2:
            LOG.error('cannot get auth_token')
            return False

        if r.status_code == codes.unauthorized:
            raise CannotAuthenticate('wrong credentials')
        if r.status_code != codes.ok:
            raise RucioException('unknown error')

        self.auth_token = r.headers['rucio-auth-token']
        LOG.debug('got new token \'%s\'' % self.auth_token)
        return True

    def __get_token_x509(self):
        """
        Sends a request to get an auth token from the server. Uses x509 authentication.
        """

        headers = {'Rucio-Account': self.account}
        url = build_url(self.host, path='auth/x509', use_ssl=self.use_ssl)

        client_cert = self.creds['client_cert']

        if not path.exists(client_cert):
            LOG.error('given client cert (%s) doesn\'t exist' % client_cert)
            return False

        retry = 0
        while retry < self.AUTH_RETRIES:
            try:
                r = get(url, headers=headers, cert=client_cert, verify=self.ca_cert)
            except SSLError, e:
                if 'error:14090086' not in e.args[0][0]:
                    return False
                LOG.warning('Couldn\'t verify ca cert. Using unverified connection')
                self.ca_cert = False
                retry += 1
                continue
            break

        if retry == 2:
            LOG.error('cannot get auth_token')
            return False

        if r.status_code == codes.unauthorized:
            raise CannotAuthenticate('wrong credentials')
        if r.status_code != codes.ok:
            raise RucioException('unknown error')

        self.auth_token = r.headers['rucio-auth-token']
        LOG.debug('got new token \'%s\'' % self.auth_token)
        return True

    def __get_token_gss(self):
        """
        Sends a request to get an auth token from the server. Uses Kerberos authentication.
        """

        headers = {'Rucio-Account': self.account}
        url = build_url(self.auth_host, port=self.auth_port, path='auth/gss', use_ssl=self.use_ssl)

        retry = 0
        while retry < self.AUTH_RETRIES:
            try:
                r = get(url, headers=headers, verify=self.ca_cert, auth=HTTPKerberosAuth())
            except SSLError:
                LOG.warning('Couldn\'t verify ca cert. Using unverified connection')
                self.ca_cert = False
                retry += 1
                continue
            break

        if retry == 2:
            LOG.error('cannot get auth_token')
            return False

        if r.status_code == codes.unauthorized:
            raise CannotAuthenticate('wrong credentials')
        if r.status_code != codes.ok:
            raise RucioException('unknown error')

        self.auth_token = r.headers['rucio-auth-token']
        LOG.debug('got new token \'%s\'' % self.auth_token)
        return True

    def __get_token(self):
        """
        Sends a request to get a new token and write it to file. To be used if a 401 - Unauthorized error is received.
        """

        LOG.debug('get a new token')
        if self.auth_type == 'userpass':
            if not self.__get_token_userpass():
                raise CannotAuthenticate('userpass authentication failed')
        elif self.auth_type == 'x509':
            if not self.__get_token_x509():
                raise CannotAuthenticate('x509 authentication failed')
        elif self.auth_type == 'gss':
            if not self.__get_token_gss():
                raise CannotAuthenticate('kerberos authentication failed')
        else:
            raise CannotAuthenticate('auth type \'%s\' no supported' % self.auth_type)

        self.__write_token()
        self.headers['Rucio-Auth-Token'] = self.auth_token

    def __read_token(self):
        """
        Checks if a local token file exists and reads the token from it.

        :return: True if a token could be read. False if no file exists.
        """

        self.token_file = self.TOKEN_PATH + '/' + self.TOKEN_PREFIX + self.account
        self.token_file = '/tmp/rucio/auth_token_' + self.account

        if not path.exists(self.token_file):
            return False

        try:
            token_file_handler = open(self.token_file, 'r')
            self.auth_token = token_file_handler.readline()
            self.headers['Rucio-Auth-Token'] = self.auth_token
        except IOError as (errno, strerror):
            print("I/O error({0}): {1}".format(errno, strerror))
        except Exception, e:
            raise e

        LOG.debug('read token \'%s\' from file' % self.auth_token)
        return True

    def __write_token(self):
        """
        Write the current auth_token to the local token file.
        """

        self.token_file = self.TOKEN_PATH + '/' + self.TOKEN_PREFIX + self.account
        self.token_file = '/tmp/rucio/auth_token_' + self.account

        # check if rucio temp directory is there. If not create it with permissions only for the current user
        if not path.isdir(self.TOKEN_PATH):
            try:
                LOG.debug('rucio token folder \'%s\' not found. Create it.' % self.TOKEN_PATH)
                mkdir(self.TOKEN_PATH, 0700)
            except Exception, e:
                raise e

        # if the file exists check if the stored token is valid. If not request a new one and overwrite the file. Otherwise use the one from the file
        try:
            token_file_handler = open(self.token_file, 'w')
            token_file_handler.write(self.auth_token)
            token_file_handler.close()
            chmod(self.token_file, 0700)
        except IOError as (errno, strerror):
            print("I/O error({0}): {1}".format(errno, strerror))
        except Exception, e:
            raise e

    def __authenticate(self):
        """
        Main method for authentication. It first tries to read a locally saved token. If not available it requests a new one.
        """

        if self.auth_type == 'userpass':
            if self.creds['username'] is None or self.creds['password'] is None:
                raise NoAuthInformation('No username or password passed')
        elif self.auth_type == 'x509':
            if self.creds['client_cert'] is None:
                raise NoAuthInformation('The path to the client certificate is required')
        elif self.auth_type == 'gss':
            pass
        else:
            raise CannotAuthenticate('auth type \'%s\' no supported' % self.auth_type)

        if not self.__read_token():
            self.__get_token()
