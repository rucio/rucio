# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2012-2013
# - Thomas Beermann, <thomas.beermann@cern.ch>, 2012-2013


"""
Client class for callers of the Rucio system
"""

from getpass import getuser
from json import loads
from logging import getLogger, StreamHandler, ERROR
from os import environ, fdopen, path, makedirs
from shutil import move
from tempfile import mkstemp
from urlparse import urlparse

from ConfigParser import NoOptionError, NoSectionError
from requests import delete, get, post, put
from requests.auth import HTTPKerberosAuth
from requests.status_codes import codes, _codes
from requests.exceptions import SSLError

from rucio.common import exception
from rucio.common.config import config_get
from rucio.common.exception import CannotAuthenticate, ClientProtocolNotSupported, NoAuthInformation, MissingClientParameter, RucioException
from rucio.common.utils import build_url

LOG = getLogger(__name__)
sh = StreamHandler()
sh.setLevel(ERROR)
LOG.addHandler(sh)


class BaseClient(object):

    """Main client class for accessing Rucio resources. Handles the authentication."""

    AUTH_RETRIES = 2
    REQUEST_RETRIES = 3
    TOKEN_PATH_PREFIX = '/tmp/' + getuser() + '/.rucio_'
    TOKEN_PREFIX = 'auth_token_'

    def __init__(self, rucio_host=None, auth_host=None, account=None, ca_cert=None, auth_type=None, creds=None, timeout=None):
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
        self.auth_host = auth_host

        try:
            if self.host is None:
                self.host = config_get('client', 'rucio_host')
            if self.auth_host is None:
                self.auth_host = config_get('client', 'auth_host')
        except (NoOptionError, NoSectionError), e:
            raise MissingClientParameter('Section client and Option \'%s\' cannot be found in config file' % e.args[0])

        self.account = account
        self.ca_cert = ca_cert
        self.auth_type = auth_type
        self.creds = creds
        self.auth_token = None
        self.headers = {}
        self.timeout = timeout
        self.request_retries = self.REQUEST_RETRIES

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
                    self.creds['client_cert'] = path.abspath(path.expanduser(path.expandvars(config_get('client', 'client_cert'))))
                    self.creds['client_key'] = path.abspath(path.expanduser(path.expandvars(config_get('client', 'client_key'))))
                elif self.auth_type == 'x509_proxy':
                    self.creds['client_proxy'] = path.abspath(path.expanduser(path.expandvars(config_get('client', 'client_x509_proxy'))))
            except (NoOptionError, NoSectionError), e:
                if e.args[0] != 'client_key':
                    raise MissingClientParameter('Option \'%s\' cannot be found in config file' % e.args[0])

        rucio_scheme = urlparse(self.host).scheme
        auth_scheme = urlparse(self.auth_host).scheme

        if (rucio_scheme != 'http' and rucio_scheme != 'https'):
            raise ClientProtocolNotSupported('\'%s\' not supported' % rucio_scheme)

        if (auth_scheme != 'http' and auth_scheme != 'https'):
            raise ClientProtocolNotSupported('\'%s\' not supported' % auth_scheme)

        if (rucio_scheme == 'https' or auth_scheme == 'https') and ca_cert is None:
            LOG.debug('no ca_cert passed. Trying to get it from the config file.')
            try:
                self.ca_cert = path.expandvars(config_get('client', 'ca_cert'))
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

        try:
            self.request_retries = int(config_get('client', 'request_retries'))
        except NoOptionError:
            LOG.debug('request_retries not specified in config file. Taking default.')
        except ValueError:
            LOG.debug('request_retries must be an integer. Taking default.')

    def _get_exception(self, headers, status_code=None):
        """
        Helper method to parse an error string send by the server and transform it into the corresponding rucio exception.

        :param headers: The http response header containing the Rucio exception details.
        :return: A rucio exception class and an error string.
        """
        if 'ExceptionClass' not in headers:
            if 'ExceptionMessage' not in headers:
                human_http_code = _codes.get(status_code, None)  # NOQA
                return getattr(exception, 'RucioException'), 'no error information passed (http status code: %(status_code)s %(human_http_code)s)' % locals()
            return getattr(exception, 'RucioException'), headers['ExceptionMessage']

        exc_cls = None
        try:
            exc_cls = getattr(exception, headers['ExceptionClass'])
        except AttributeError:
            return getattr(exception, 'RucioException'), headers['ExceptionMessage']

        return exc_cls, headers['ExceptionMessage']

    def _load_json_data(self, response):
        """
        Helper method to correctly load json data based on the content type of the http response.

        :param response: the response received from the server.
        """
        if 'content-type' in response.headers and response.headers['content-type'] == 'application/x-json-stream':
            for line in response.iter_lines():
                if line:
                    yield loads(line)
        elif 'content-type' in response.headers and response.headers['content-type'] == 'application/json':
            yield loads(response.text)
        else:  # Exception ?
            yield response.text

    def _send_request(self, url, headers=None, type='GET', data=None, params=None):
        """
        Helper method to send requests to the rucio server. Gets a new token and retries if an unauthorized error is returned.

        :param url: the http url to use.
        :param headers: additional http headers to send.
        :param type: the http request type to use.
        :param data: post data.
        :param params: (optional) Dictionary or bytes to be sent in the url query string.
        :return: the HTTP return body.
        """

        r = None
        retry = 0
        hds = {'X-Rucio-Auth-Token': self.auth_token, 'X-Rucio-Account': self.account, 'X-Rucio-Appid': ''}

        if headers is not None:
            hds.update(headers)

        while retry < self.request_retries:
            try:
                if type == 'GET':
                    r = get(url, headers=hds, verify=self.ca_cert, timeout=self.timeout, params=params, prefetch=False)  # `stream=True` for newer versions of requests
                elif type == 'PUT':
                    r = put(url, headers=hds, data=data, verify=self.ca_cert, timeout=self.timeout)
                elif type == 'POST':
                    r = post(url, headers=hds, data=data, verify=self.ca_cert, timeout=self.timeout)
                elif type == 'DEL':
                    r = delete(url, headers=hds, data=data, verify=self.ca_cert, timeout=self.timeout)
                else:
                    return
            except SSLError:
                LOG.warning('Couldn\'t verify ca cert. Using unverified connection')
                self.ca_cert = False
                retry += 1
                continue

            if r.status_code == codes.unauthorized:
                self.__get_token()
                hds['X-Rucio-Auth-Token'] = self.auth_token
                retry += 1
            else:
                break

        return r

    def __get_token_userpass(self):
        """
        Sends a request to get an auth token from the server and stores it as a class attribute. Uses username/password.

        :returns: True if the token was successfully received. False otherwise.
        """

        headers = {'X-Rucio-Account': self.account, 'X-Rucio-Username': self.creds['username'], 'X-Rucio-Password': self.creds['password']}
        url = build_url(self.auth_host, path='auth/userpass')

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

        self.auth_token = r.headers['x-rucio-auth-token']
        LOG.debug('got new token \'%s\'' % self.auth_token)
        return True

    def __get_token_x509(self):
        """
        Sends a request to get an auth token from the server and stores it as a class attribute. Uses x509 authentication.

        :returns: True if the token was successfully received. False otherwise.
        """

        headers = {'X-Rucio-Account': self.account}

        client_cert = None
        client_key = None
        if self.auth_type == 'x509':
            url = build_url(self.auth_host, path='auth/x509')
            client_cert = self.creds['client_cert']
            if 'client_key' in self.creds:
                client_key = self.creds['client_key']
        elif self.auth_type == 'x509_proxy':
            url = build_url(self.auth_host, path='auth/x509_proxy')
            client_cert = self.creds['client_proxy']

        if not path.exists(client_cert):
            LOG.error('given client cert (%s) doesn\'t exist' % client_cert)
            return False
        if client_key is not None and not path.exists(client_key):
            LOG.error('given client key (%s) doesn\'t exist' % client_key)

        retry = 0

        if client_key is None:
            cert = client_cert
        else:
            cert = (client_cert, client_key)

        while retry < self.AUTH_RETRIES:
            try:
                r = get(url, headers=headers, cert=cert, verify=self.ca_cert)
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

        self.auth_token = r.headers['x-rucio-auth-token']
        LOG.debug('got new token \'%s\'' % self.auth_token)
        return True

    def __get_token_gss(self):
        """
        Sends a request to get an auth token from the server and stores it as a class attribute. Uses Kerberos authentication.

        :returns: True if the token was successfully received. False otherwise.
        """

        headers = {'X-Rucio-Account': self.account}
        url = build_url(self.auth_host, path='auth/gss')

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

        self.auth_token = r.headers['x-rucio-auth-token']
        LOG.debug('got new token \'%s\'' % self.auth_token)
        return True

    def __get_token(self):
        """
        Calls the corresponding method to receive an auth token depending on the auth type. To be used if a 401 - Unauthorized error is received.
        """

        retry = 0
        LOG.debug('get a new token')
        while retry < self.AUTH_RETRIES:
            if self.auth_type == 'userpass':
                if not self.__get_token_userpass():
                    raise CannotAuthenticate('userpass authentication failed')
            elif self.auth_type == 'x509' or self.auth_type == 'x509_proxy':
                if not self.__get_token_x509():
                    raise CannotAuthenticate('x509 authentication failed')
            elif self.auth_type == 'gss':
                if not self.__get_token_gss():
                    raise CannotAuthenticate('kerberos authentication failed')
            else:
                raise CannotAuthenticate('auth type \'%s\' not supported' % self.auth_type)

            if self.auth_token is not None:
                self.__write_token()
                self.headers['X-Rucio-Auth-Token'] = self.auth_token
                break

            retry += 1

        if self.auth_token is None:
            raise CannotAuthenticate('cannot get an auth token from server')

    def __read_token(self):
        """
        Checks if a local token file exists and reads the token from it.

        :return: True if a token could be read. False if no file exists.
        """

        token_path = self.TOKEN_PATH_PREFIX + self.account
        self.token_file = token_path + '/' + self.TOKEN_PREFIX + self.account

        if not path.exists(self.token_file):
            return False

        try:
            token_file_handler = open(self.token_file, 'r')
            self.auth_token = token_file_handler.readline()
            self.headers['X-Rucio-Auth-Token'] = self.auth_token
        except IOError as (errno, strerror):  # NOQA
            print("I/O error({0}): {1}".format(errno, strerror))
        except Exception, e:
            raise e

        LOG.debug('read token \'%s\' from file' % self.auth_token)
        return True

    def __write_token(self):
        """
        Write the current auth_token to the local token file.
        """

        token_path = self.TOKEN_PATH_PREFIX + self.account
        self.token_file = token_path + '/' + self.TOKEN_PREFIX + self.account

        # check if rucio temp directory is there. If not create it with permissions only for the current user
        if not path.isdir(token_path):
            try:
                LOG.debug('rucio token folder \'%s\' not found. Create it.' % token_path)
                makedirs(token_path, 0700)
            except Exception, e:
                raise e

        # if the file exists check if the stored token is valid. If not request a new one and overwrite the file. Otherwise use the one from the file
        try:
            fd, fn = mkstemp(dir=token_path)
            with fdopen(fd, "w") as f:
                f.write(self.auth_token)
            move(fn, self.token_file)
        except IOError as (errno, strerror):  # NOQA
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
        elif self.auth_type == 'x509_proxy':
            if self.creds['client_proxy'] is None:
                raise NoAuthInformation('The client proxy has to be defined')
        elif self.auth_type == 'gss':
            pass
        else:
            raise CannotAuthenticate('auth type \'%s\' not supported' % self.auth_type)

        if not self.__read_token():
            self.__get_token()
