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

'''
 Client class for callers of the Rucio system
'''

import errno
import getpass
import json
import os
import secrets
import sys
import time
from collections.abc import Mapping  # noqa: TC003 - Used in runtime function signatures
from configparser import NoOptionError, NoSectionError
from os import environ, fdopen, geteuid, makedirs
from shutil import move
from tempfile import mkstemp
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urlparse

import requests
from dogpile.cache.region import make_region
from requests import Response, Session
from requests.exceptions import ConnectionError
from requests.status_codes import codes

from rucio import version
from rucio.common import exception
from rucio.common.config import config_get, config_get_bool, config_get_int, config_has_section
from rucio.common.constants import DEFAULT_VO, HTTPMethod
from rucio.common.exception import CannotAuthenticate, ClientProtocolNotFound, ClientProtocolNotSupported, ConfigNotFound, MissingClientParameter, MissingModuleException, NoAuthInformation, ServerConnectionException
from rucio.common.extra import import_extras
from rucio.common.utils import build_url, get_tmp_dir, my_key_generator, parse_response, setup_logger, ssh_sign, wlcg_token_discovery

if TYPE_CHECKING:
    from collections.abc import Generator
    from logging import Logger

EXTRA_MODULES = import_extras(['requests_kerberos'])

if EXTRA_MODULES['requests_kerberos']:
    from requests_kerberos import HTTPKerberosAuth  # pylint: disable=import-error

LOG = setup_logger(module_name=__name__)

REGION = make_region(function_key_generator=my_key_generator).configure(
    'dogpile.cache.memory',
    expiration_time=60,
)

# HTTP status codes
STATUS_CODES_TO_RETRY = [502, 503, 504]
MAX_RETRY_BACK_OFF_SECONDS = 10

# OIDC authentication constants
OIDC_POLLING_TIMEOUT_SECONDS = 180  # 3 minutes
OIDC_MAX_CODE_ATTEMPTS = 3
OIDC_POLLING_INTERVAL_SECONDS = 2

# HTTP header constants
HEADER_RUCIO_AUTH_TOKEN = 'X-Rucio-Auth-Token'
HEADER_RUCIO_AUTH_TOKEN_EXPIRES = 'X-Rucio-Auth-Token-Expires'
HEADER_RUCIO_OIDC_AUTH_URL = 'X-Rucio-OIDC-Auth-URL'
HEADER_RUCIO_VO = 'X-Rucio-VO'
HEADER_RUCIO_ACCOUNT = 'X-Rucio-Account'
HEADER_RUCIO_SCRIPT = 'X-Rucio-Script'
HEADER_USER_AGENT = 'User-Agent'
HEADER_CONNECTION = 'Connection'


@REGION.cache_on_arguments(namespace='host_to_choose')
def choice(hosts):
    """
    Select randomly a host

    :param hosts: List of hosts
    :return: A randomly selected host.
    """
    return secrets.choice(hosts)


def _expand_path(path: str) -> str:
    """Fully expand path, including ~ and env variables"""
    path = path.strip()
    if path == '':
        return ''
    return os.path.abspath(os.path.expanduser(os.path.expandvars(path)))


class BaseClient:
    """Main client class for accessing Rucio resources. Handles the authentication."""

    AUTH_RETRIES, REQUEST_RETRIES = 2, 3
    TOKEN_PATH_PREFIX = get_tmp_dir() + '/.rucio_'
    TOKEN_PREFIX = 'auth_token_'  # noqa: S105
    TOKEN_EXP_PREFIX = 'auth_token_exp_'  # noqa: S105

    def __init__(
        self,
        rucio_host: Optional[str] = None,
        auth_host: Optional[str] = None,
        account: Optional[str] = None,
        ca_cert: Optional[str] = None,
        auth_type: Optional[str] = None,
        creds: Optional[dict[str, Any]] = None,
        timeout: Optional[int] = 600,
        user_agent: str = 'rucio-clients',
        vo: Optional[str] = None,
        logger: 'Logger' = LOG
    ) -> None:
        """
        Constructor of the BaseClient.

        Parameters
        ----------
        rucio_host :
            The address of the rucio server, if None it is read from the config file.
        auth_host :
            The address of the rucio authentication server, if None it is read from the config file.
        account :
            The account to authenticate to rucio.
        ca_cert :
            The path to the rucio server certificate.
        auth_type :
            The type of authentication (e.g.: 'userpass', 'kerberos' ...)
        creds :
            Dictionary with credentials needed for authentication.
        timeout :
            Timeout for requests.
        user_agent :
            Indicates the client.
        vo :
            The VO to authenticate into.
        logger :
            Logger object to use. If None, use the default LOG created by the module.
        """

        self.logger = logger
        self._setup_session(user_agent)
        self._configure_hosts(rucio_host, auth_host)
        self._configure_account_and_vo(account, vo)

        self.ca_cert = ca_cert
        self.auth_token = ""
        self.headers: dict[str, str] = {}
        self.timeout = timeout
        self.request_retries = self.REQUEST_RETRIES
        self.token_exp_epoch: Optional[int] = None

        self._setup_oidc_config()

        self.auth_type = self._get_auth_type(auth_type)
        self.creds: dict[str, Any] = self._get_creds(creds)

        self._validate_and_configure_tls()

        self._configure_request_retries()
        self.auth_token_file_path, self.token_exp_epoch_file, self.token_file, self.token_path = self._get_auth_tokens()
        self.__authenticate()

    def _get_auth_tokens(self) -> tuple[Optional[str], str, str, str]:
        """Get authentication token file paths."""
        auth_token_file_path = config_get('client', 'auth_token_file_path', False, None)
        token_filename_suffix = "for_default_account" if self.account is None else f"for_account_{self.account}"

        if auth_token_file_path:
            token_file = _expand_path(auth_token_file_path)
            token_path = '/'.join(token_file.split('/')[:-1])
        else:
            token_path = _expand_path(self.TOKEN_PATH_PREFIX + getpass.getuser())
            if self.vo != DEFAULT_VO:
                token_path += f'@{self.vo}'
            token_file = f'{token_path}/{self.TOKEN_PREFIX}{token_filename_suffix}'

        token_exp_epoch_file = f'{token_path}/{self.TOKEN_EXP_PREFIX}{token_filename_suffix}'
        return auth_token_file_path, token_exp_epoch_file, token_file, token_path

    def _get_auth_type(self, auth_type: Optional[str]) -> str:
        """Get authentication type from parameter, environment, or config."""
        if auth_type is None:
            self.logger.debug('No auth_type passed. Trying to get it from the environment variable RUCIO_AUTH_TYPE and config file.')
            if 'RUCIO_AUTH_TYPE' in environ:
                if environ['RUCIO_AUTH_TYPE'] not in ['userpass', 'x509', 'x509_proxy', 'gss', 'ssh', 'saml', 'oidc']:
                    raise MissingClientParameter(f"Possible RUCIO_AUTH_TYPE values: userpass, x509, x509_proxy, gss, ssh, saml, oidc, vs. {environ['RUCIO_AUTH_TYPE']}")
                auth_type = environ['RUCIO_AUTH_TYPE']
            else:
                try:
                    auth_type = config_get('client', 'auth_type')
                except (NoOptionError, NoSectionError) as error:
                    raise MissingClientParameter(f"Option '{error.args[0]}' cannot be found in config file")
        return auth_type

    def _get_creds(self, creds: Optional[dict[str, Any]]) -> dict[str, Any]:
        """Get credentials from parameter or config file."""
        if not creds:
            self.logger.debug('No creds passed. Trying to get it from the config file.')
            creds = {}

        try:
            if self.auth_type == 'oidc':
                self._populate_oidc_creds(creds)
            elif self.auth_type in ['userpass', 'saml']:
                self._populate_userpass_creds(creds)
            elif self.auth_type == 'x509':
                self._populate_x509_creds(creds)
            elif self.auth_type == 'x509_proxy':
                self._populate_x509_proxy_creds(creds)
            elif self.auth_type == 'ssh':
                self._populate_ssh_creds(creds)
        except (NoOptionError, NoSectionError) as error:
            if error.args[0] != 'client_key':
                raise MissingClientParameter(f"Option '{error.args[0]}' cannot be found in config file")

        return creds

    def _get_exception(
            self,
            headers: Mapping[str, str],
            status_code: Optional[int] = None,
            data: Any = None
        ) -> tuple[type[exception.RucioException], str]:
        """
        Parse error string from server and transform into corresponding rucio exception.

        Parameters
        ----------
        headers :
            HTTP response header containing Rucio exception details
        status_code :
            HTTP status code
        data :
            Data with the ExceptionMessage

        Returns
        -------
        tuple
            Rucio exception class and error string
        """
        if data is not None:
            try:
                data = parse_response(data)
            except ValueError:
                data = {}
        else:
            data = {}

        exc_cls = 'RucioException'
        exc_msg = f'no error information passed (http status code: {status_code})'

        if 'ExceptionClass' in data:
            exc_cls = data['ExceptionClass']
        elif 'ExceptionClass' in headers:
            exc_cls = headers['ExceptionClass']
        if 'ExceptionMessage' in data:
            exc_msg = data['ExceptionMessage']
        elif 'ExceptionMessage' in headers:
            exc_msg = headers['ExceptionMessage']

        if hasattr(exception, exc_cls):
            return getattr(exception, exc_cls), exc_msg

        return exception.RucioException, f"{exc_cls}: {exc_msg}"

    def _load_json_data(self, response: requests.Response) -> 'Generator[Any, Any, Any]':
        """
        Load json data based on content type of HTTP response.

        Parameters
        ----------
        response :
            Response received from the server

        Yields
        ------
        Any
            Parsed JSON data
        """
        if 'content-type' in response.headers and response.headers['content-type'] == 'application/x-json-stream':
            for line in response.iter_lines():
                if line:
                    yield parse_response(line)
        elif 'content-type' in response.headers and response.headers['content-type'] == 'application/json':
            yield parse_response(response.text)
        else:
            if response.text:
                yield response.text

    def _reduce_data(self, data: Any, maxlen: int = 132) -> str:
        """Reduce data to maximum length for logging."""
        if isinstance(data, dict):
            data = json.dumps(data)
        text = data if isinstance(data, str) else data.decode("utf-8")
        if len(text) > maxlen:
            text = f"{text[:maxlen - 15]} ... {text[-10:]}"
        return text

    def _back_off(self, retry_number: int, reason: str) -> None:
        """
        Sleep for exponentially increasing time based on retry count.

        Parameters
        ----------
        retry_number :
            The retry iteration
        reason :
            The reason to backoff which will be shown to the user
        """
        sleep_time = min(MAX_RETRY_BACK_OFF_SECONDS, 0.25 * 2 ** retry_number)
        self.logger.warning("Waiting %ss due to reason: %s", sleep_time, reason)
        time.sleep(sleep_time)

    def _send_request(
            self,
            url: str,
            method: HTTPMethod = HTTPMethod.GET,
            headers: Optional[dict[str, str]] = None,
            data: Any = None,
            params: Optional[dict[str, Any]] = None,
            stream: bool = False,
            get_token: bool = False,
            cert: Any = None,
            auth: Any = None,
            verify: Any = None
        ) -> Response:
        """
        Send requests to the rucio server with token refresh on unauthorized.

        Parameters
        ----------
        url :
            HTTP url to use
        headers :
            Additional HTTP headers to send
        method :
            HTTP request type to use
        data :
            POST data
        params :
            Dictionary or bytes to be sent in the url query string
        stream :
            Enable streaming response
        get_token :
            Whether this is called from a get_token function
        cert :
            SSL client cert file path or (cert, key) pair
        auth :
            Auth tuple to enable Basic/Digest/Custom HTTP Auth
        verify :
            Whether to verify server's TLS certificate or path to CA bundle

        Returns
        -------
        Response
            HTTP response body

        Raises
        ------
        ServerConnectionException
            If no result received from server
        """
        hds = {
            HEADER_RUCIO_AUTH_TOKEN: self.auth_token,
            HEADER_RUCIO_VO: self.vo,
            HEADER_CONNECTION: 'Keep-Alive',
            HEADER_USER_AGENT: self.user_agent,
            HEADER_RUCIO_SCRIPT: self.script_id
        }

        if self.account is not None:
            hds[HEADER_RUCIO_ACCOUNT] = self.account

        if headers is not None:
            hds.update(headers)
        if verify is None:
            verify = self.ca_cert or False

        self.logger.debug("HTTP request: %s %s" % (method.value, url))
        for h, v in hds.items():
            if h == HEADER_RUCIO_AUTH_TOKEN:
                v = "[hidden]"
            self.logger.debug("HTTP header:  %s: %s" % (h, v))
        if method != HTTPMethod.GET and data:
            text = self._reduce_data(data)
            self.logger.debug("Request data (length=%d): [%s]", len(data), text)

        result = None
        for retry in range(self.AUTH_RETRIES + 1):
            try:
                if method == HTTPMethod.GET:
                    result = self.session.get(url, headers=hds, verify=verify, timeout=self.timeout, params=params, stream=True, cert=cert, auth=auth)
                elif method == HTTPMethod.PUT:
                    result = self.session.put(url, headers=hds, data=data, verify=verify, timeout=self.timeout)
                elif method == HTTPMethod.POST:
                    result = self.session.post(url, headers=hds, data=data, verify=verify, timeout=self.timeout, stream=stream)
                elif method == HTTPMethod.DELETE:
                    result = self.session.delete(url, headers=hds, data=data, verify=verify, timeout=self.timeout)
                else:
                    self.logger.debug("Unknown request type %s. Request was not sent" % (method))
                    raise ServerConnectionException(f"Invalid HTTP method: {method}")
                self.logger.debug("HTTP Response: %s %s", result.status_code, result.reason)
                if result.status_code in STATUS_CODES_TO_RETRY:
                    self._back_off(retry, f'server returned {result.status_code}')
                    continue
                if result.status_code // 100 != 2 and result.text:
                    self.logger.debug("Response text (length=%d): [%s]", len(result.text), result.text)
            except ConnectionError as error:
                self.logger.error('ConnectionError: %s', error)
                if retry > self.request_retries:
                    raise
                continue
            except OSError as error:
                if getattr(error, 'errno') != errno.EPIPE:
                    raise
                self.logger.error('BrokenPipe: %s', error)
                if retry > self.request_retries:
                    raise
                continue

            if result is not None and result.status_code == codes.unauthorized and not get_token:
                self.session = Session()
                self.__get_token()
                hds[HEADER_RUCIO_AUTH_TOKEN] = self.auth_token
            else:
                break

        if result is None:
            raise ServerConnectionException
        return result

    def __get_token_userpass(self) -> bool:
        """
        Get auth token from server using username/password.

        Returns
        -------
        bool
            True if token successfully received, False otherwise

        Raises
        ------
        CannotAuthenticate
            If authentication fails
        """

        headers = {
            'X-Rucio-Username': self.creds['username'],
            'X-Rucio-Password': self.creds['password']
        }

        url = build_url(self.auth_host, path='auth/userpass')

        result = self._send_request(url, method=HTTPMethod.GET, headers=headers, get_token=True)

        if not result:
            # result is either None or not OK.
            if isinstance(result, Response):
                if 'ExceptionClass' in result.headers and result.headers['ExceptionClass']:
                    if 'ExceptionMessage' in result.headers and result.headers['ExceptionMessage']:
                        exc_msg = result.headers.get('ExceptionMessage', result.headers['ExceptionClass'])
                        raise CannotAuthenticate(f"{result.headers['ExceptionClass']}: {exc_msg}")
                    else:
                        raise CannotAuthenticate(result.headers["ExceptionClass"])
                elif result.text:
                    raise CannotAuthenticate(result.text)
            self.logger.error('Cannot retrieve authentication token!')
            return False

        if result.status_code != codes.ok:  # pylint: disable-msg=E1101
            exc_cls, exc_msg = self._get_exception(headers=result.headers,
                                                   status_code=result.status_code,
                                                   data=result.content)
            raise exc_cls(exc_msg)

        self.auth_token = result.headers[HEADER_RUCIO_AUTH_TOKEN]
        return True

    def __refresh_token_oidc(self) -> bool:
        """
        Check for active refresh token and request new access token if needed.

        Returns
        -------
        bool
            True if token successfully refreshed, False otherwise
        """

        if not self.auth_oidc_refresh_active:
            return False
        if os.path.exists(self.token_exp_epoch_file):
            with open(self.token_exp_epoch_file, 'r') as token_epoch_file:
                try:
                    self.token_exp_epoch = int(token_epoch_file.readline())
                except (ValueError, TypeError) as error:
                    self.logger.debug('Failed to parse token expiration: %s', error)
                    self.token_exp_epoch = None

        if self.token_exp_epoch is None:
            # check expiration time for a new token
            pass
        elif time.time() > self.token_exp_epoch - self.auth_oidc_refresh_before_exp * 60 and time.time() < self.token_exp_epoch:
            # attempt to refresh token
            pass
        else:
            return False

        request_refresh_url = build_url(self.auth_host, path='auth/oidc_refresh')
        refresh_result = self._send_request(request_refresh_url, method=HTTPMethod.GET, get_token=True)
        if refresh_result.status_code == codes.ok:
            if HEADER_RUCIO_AUTH_TOKEN_EXPIRES not in refresh_result.headers or HEADER_RUCIO_AUTH_TOKEN not in refresh_result.headers:
                self.logger.error("Rucio Server response does not contain the expected headers.")
                return False
            else:
                new_token = refresh_result.headers[HEADER_RUCIO_AUTH_TOKEN]
                new_exp_epoch = refresh_result.headers[HEADER_RUCIO_AUTH_TOKEN_EXPIRES]
                if new_token and new_exp_epoch:
                    self.logger.debug("Saving token %s and expiration epoch %s to files", new_token, new_exp_epoch)
                    # save to the file
                    self.auth_token = new_token
                    self.token_exp_epoch = int(new_exp_epoch)
                    self.__write_token()
                    self.headers[HEADER_RUCIO_AUTH_TOKEN] = self.auth_token
                    return True
                self.logger.debug("No new token was received, possibly invalid/expired token or no refresh token in Rucio DB")
                return False
        else:
            self.logger.error("Rucio Client did not succeed to contact the Rucio Auth Server when attempting token refresh.")
            return False

    def __get_token_oidc(self) -> bool:
        """
        Authenticate via OIDC and retrieve an auth token.

        First authenticates the user via an Identity Provider server. By specifying
        oidc_scope, the user agrees to share relevant information with Rucio.
        Access tokens are not stored in Rucio DB. Refresh tokens are granted only
        if no valid access token exists in local storage and oidc_scope includes
        'offline_access'. Refresh tokens are stored in Rucio DB.

        Supports three authentication flows:
        - Auto flow: Automatic authentication with username/password (discouraged)
        - Polling flow: Client polls server while user authenticates in browser
        - Manual code flow: User manually enters code from browser

        Returns
        -------
        bool
            True if token successfully received, False otherwise
        """
        auth_url = self._request_oidc_auth_url()
        if not auth_url:
            return False

        if self.creds['oidc_auto']:
            result = self._handle_oidc_auto_flow(auth_url)
        elif self.creds['oidc_polling']:
            result = self._handle_oidc_polling_flow(auth_url)
        else:
            result = self._handle_oidc_manual_code_flow(auth_url)

        return self._finalize_oidc_token(result)

    def __get_token_x509(self) -> bool:
        """
        Get auth token from server using x509 authentication.

        Returns
        -------
        bool
            True if token successfully received, False otherwise
        """
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

        if client_cert is not None and not os.path.exists(client_cert):
            self.logger.error("Given client cert (%s) doesn't exist", client_cert)
            return False
        if client_key is not None and not os.path.exists(client_key):
            self.logger.error("Given client key (%s) doesn't exist", client_key)
            return False

        cert = client_cert if client_key is None else (client_cert, client_key)

        result = self._send_request(url, method=HTTPMethod.GET, get_token=True, cert=cert)

        # Note a response object for a failed request evaluates to false, so we cannot
        # use "not result" here
        if result is None:
            self.logger.error('Internal error: Request for authentication token returned no result!')
            return False

        if result.status_code != codes.ok:   # pylint: disable-msg=E1101
            exc_cls, exc_msg = self._get_exception(headers=result.headers,
                                                   status_code=result.status_code,
                                                   data=result.content)
            raise exc_cls(exc_msg)

        self.auth_token = result.headers[HEADER_RUCIO_AUTH_TOKEN]
        return True

    def __get_token_ssh(self) -> bool:
        """
        Get auth token from server using SSH key exchange authentication.

        Returns
        -------
        bool
            True if token successfully received, False otherwise
        """
        headers = {}

        private_key_path = self.creds['ssh_private_key']

        if not os.path.exists(private_key_path):
            self.logger.error("Given private key (%s) doesn't exist", private_key_path)
            return False

        url = build_url(self.auth_host, path='auth/ssh_challenge_token')

        result = self._send_request(url, method=HTTPMethod.GET, get_token=True)

        if not result:
            self.logger.error('cannot get ssh_challenge_token')
            return False

        if result.status_code != codes.ok:   # pylint: disable-msg=E1101
            exc_cls, exc_msg = self._get_exception(headers=result.headers,
                                                   status_code=result.status_code,
                                                   data=result.content)
            raise exc_cls(exc_msg)

        self.ssh_challenge_token = result.headers['x-rucio-ssh-challenge-token']
        self.logger.debug("Got new ssh challenge token '%s'", self.ssh_challenge_token)

        # sign the challenge token with the private key
        with open(private_key_path, 'r') as fd_private_key_path:
            private_key = fd_private_key_path.read()
            signature = ssh_sign(private_key, self.ssh_challenge_token)
            headers['X-Rucio-SSH-Signature'] = signature

        url = build_url(self.auth_host, path='auth/ssh')

        result = self._send_request(url, method=HTTPMethod.GET, headers=headers, get_token=True)

        if not result:
            self.logger.error('Cannot retrieve authentication token!')
            return False

        if result.status_code != codes.ok:   # pylint: disable-msg=E1101
            exc_cls, exc_msg = self._get_exception(headers=result.headers,
                                                   status_code=result.status_code,
                                                   data=result.content)
            raise exc_cls(exc_msg)

        self.auth_token = result.headers[HEADER_RUCIO_AUTH_TOKEN]
        return True

    def __get_token_gss(self) -> bool:
        """
        Get auth token from server using Kerberos authentication.

        Returns
        -------
        bool
            True if token successfully received, False otherwise
        """
        if not EXTRA_MODULES['requests_kerberos']:
            raise MissingModuleException('The requests-kerberos module is not installed.')

        url = build_url(self.auth_host, path='auth/gss')

        result = self._send_request(url, method=HTTPMethod.GET, get_token=True, auth=HTTPKerberosAuth())

        if not result:
            self.logger.error('Cannot retrieve authentication token!')
            return False

        if result.status_code != codes.ok:   # pylint: disable-msg=E1101
            exc_cls, exc_msg = self._get_exception(headers=result.headers,
                                                   status_code=result.status_code,
                                                   data=result.content)
            raise exc_cls(exc_msg)

        self.auth_token = result.headers[HEADER_RUCIO_AUTH_TOKEN]
        return True

    def __get_token_saml(self) -> bool:
        """
        Get auth token from server using SAML authentication.

        Returns
        -------
        bool
            True if token successfully received, False otherwise
        """
        userpass = {'username': self.creds['username'], 'password': self.creds['password']}
        url = build_url(self.auth_host, path='auth/saml')

        saml_auth_result = self._send_request(url, method=HTTPMethod.GET, get_token=True)
        if saml_auth_result.headers.get('X-Rucio-Auth-Token'):
            self.auth_token = saml_auth_result.headers['X-Rucio-Auth-Token']
            return True
        saml_auth_url = saml_auth_result.headers['X-Rucio-SAML-Auth-URL']
        result = self._send_request(saml_auth_url, method=HTTPMethod.POST, data=userpass, verify=False)
        result = self._send_request(url, method=HTTPMethod.GET, get_token=True)

        if not result:
            self.logger.error('Cannot retrieve authentication token!')
            return False

        if result.status_code != codes.ok:  # pylint: disable-msg=E1101
            exc_cls, exc_msg = self._get_exception(headers=result.headers,
                                                   status_code=result.status_code,
                                                   data=result.content)
            raise exc_cls(exc_msg)

        self.auth_token = result.headers[HEADER_RUCIO_AUTH_TOKEN]
        return True

    def __get_token(self) -> None:
        """Get auth token based on configured authentication type."""

        self.logger.debug('Getting a new token')
        for retry in range(self.AUTH_RETRIES + 1):
            if self.auth_type == 'userpass':
                if not self.__get_token_userpass():
                    raise CannotAuthenticate(f'userpass authentication failed for account={self.account} with identity={self.creds["username"]}')
            elif self.auth_type in ('x509', 'x509_proxy'):
                if not self.__get_token_x509():
                    raise CannotAuthenticate(f'x509 authentication failed for account={self.account} with identity={self.creds}')
            elif self.auth_type == 'oidc':
                if not self.__get_token_oidc():
                    raise CannotAuthenticate(f'OIDC authentication failed for account={self.account}')

            elif self.auth_type == 'gss':
                if not self.__get_token_gss():
                    raise CannotAuthenticate(f'kerberos authentication failed for account={self.account} with identity={self.creds}')
            elif self.auth_type == 'ssh':
                if not self.__get_token_ssh():
                    raise CannotAuthenticate(f'ssh authentication failed for account={self.account} with identity={self.creds}')
            elif self.auth_type == 'saml':
                if not self.__get_token_saml():
                    raise CannotAuthenticate(f'saml authentication failed for account={self.account} with identity={self.creds["username"]}')
            else:
                raise CannotAuthenticate(f'auth type \'{self.auth_type}\' not supported')

            if self.auth_token is not None:
                self.__write_token()
                self.headers[HEADER_RUCIO_AUTH_TOKEN] = self.auth_token
                break

        if self.auth_token is None:
            raise CannotAuthenticate('cannot get an auth token from server')

    def __read_token(self) -> bool:
        """
        Check if local token file exists and read token from it.

        Returns
        -------
        bool
            True if token could be read, False if no file exists
        """

        if self.auth_type == "oidc":
            token = wlcg_token_discovery()
            if token:
                self.auth_token = token
                self.headers[HEADER_RUCIO_AUTH_TOKEN] = self.auth_token
                return True

        if not os.path.exists(self.token_file):
            return False

        try:
            with open(self.token_file, 'r') as token_file_handler:
                self.auth_token = token_file_handler.readline()
            self.headers[HEADER_RUCIO_AUTH_TOKEN] = self.auth_token
        except OSError as error:
            self.logger.error("I/O error(%s): %s", error.errno, error.strerror)
            raise
        if self.auth_oidc_refresh_active and self.auth_type == 'oidc':
            self.__refresh_token_oidc()
        self.logger.debug('Got token from file')
        return True

    def __write_token(self) -> None:
        """Write current auth_token to local token file."""
        # check if rucio temp directory is there. If not create it with permissions only for the current user
        if not os.path.isdir(self.token_path):
            self.logger.debug("Rucio token folder '%s' not found. Creating it.", self.token_path)
            try:
                makedirs(self.token_path, 0o700)
            except FileExistsError:
                self.logger.debug('Token directory already exists at %s - skipping', self.token_path)
            except OSError as error:
                self.logger.error("Failed to create token directory: %s", error)
                raise

        try:
            file_d, file_n = mkstemp(dir=self.token_path)
            with fdopen(file_d, "w") as f_token:
                f_token.write(self.auth_token)
            move(file_n, self.token_file)
            if self.auth_type == 'oidc' and self.token_exp_epoch and self.auth_oidc_refresh_active:
                file_d, file_n = mkstemp(dir=self.token_path)
                with fdopen(file_d, "w") as f_exp_epoch:
                    f_exp_epoch.write(str(self.token_exp_epoch))
                move(file_n, self.token_exp_epoch_file)
        except OSError as error:
            self.logger.error("I/O error(%s): %s", error.errno, error.strerror)
            raise

    def __authenticate(self) -> None:
        """
        Main authentication method.

        First tries to read a locally saved token. If not available, requests a new one.

        Raises
        ------
        NoAuthInformation
            If required credentials are missing
        CannotAuthenticate
            If authentication type is not supported
        """
        if self.auth_type == 'userpass':
            if self.creds['username'] is None or self.creds['password'] is None:
                raise NoAuthInformation('No username or password passed')
        elif self.auth_type == 'oidc':
            if self.creds['oidc_auto'] and (self.creds['oidc_username'] is None or self.creds['oidc_password'] is None):
                raise NoAuthInformation('For automatic OIDC log-in with your Identity Provider username and password are required.')
        elif self.auth_type == 'x509':
            if self.creds['client_cert'] is None:
                raise NoAuthInformation('The path to the client certificate is required')
        elif self.auth_type == 'x509_proxy':
            if self.creds['client_proxy'] is None:
                raise NoAuthInformation('The client proxy has to be defined')
        elif self.auth_type == 'ssh':
            if self.creds['ssh_private_key'] is None:
                raise NoAuthInformation('The SSH private key has to be defined')
        elif self.auth_type == 'gss':
            pass
        elif self.auth_type == 'saml':
            if self.creds['username'] is None or self.creds['password'] is None:
                raise NoAuthInformation('No SAML username or password passed')
        else:
            raise CannotAuthenticate(f'auth type \'{self.auth_type}\' not supported')

        if not self.__read_token():
            self.__get_token()

    def _setup_session(self, user_agent: str) -> None:
        """
        Initialize HTTP session and user agent string.

        Sets up the requests Session object and constructs the user agent string
        from the provided user agent and Rucio version. Also initializes the script
        identifier from command line arguments.

        Parameters
        ----------
        user_agent :
            Base user agent string (e.g. 'rucio-clients')
        """
        self.session = Session()
        self.user_agent = f"{user_agent}/{version.version_string()}"
        if sys.argv:
            sys.argv[0] = sys.argv[0].split('/')[-1]
            self.script_id = '::'.join(sys.argv[0:2]) or 'python'
        else:
            self.script_id = 'python'

    def _configure_hosts(self, rucio_host: Optional[str], auth_host: Optional[str]) -> None:
        """
        Configure and validate Rucio server and authentication server hosts.

        Sets the main Rucio host, authentication host, and trace host. If hosts are not
        provided, they are read from the configuration file. Falls back to using rucio_host
        as trace_host if no separate trace host is configured.

        Parameters
        ----------
        rucio_host :
            Rucio server address, if None reads from config
        auth_host :
            Authentication server address, if None reads from config

        Raises
        ------
        MissingClientParameter
            If required host configuration cannot be found
        """
        try:
            self.host = rucio_host or config_get('client', 'rucio_host')
        except (NoOptionError, NoSectionError) as error:
            raise MissingClientParameter(f"Section client and Option '{error.args[0]}' cannot be found in config file")

        try:
            self.auth_host = auth_host or config_get('client', 'auth_host')
        except (NoOptionError, NoSectionError) as error:
            raise MissingClientParameter(f"Section client and Option '{error.args[0]}' cannot be found in config file")

        self.trace_host = config_get('trace', 'trace_host', raise_exception=False, default=self.host)
        if self.trace_host == self.host:
            self.logger.debug('No trace_host configured. Using rucio_host instead')

        self.list_hosts = [self.host]

    def _configure_account_and_vo(self, account: Optional[str], vo: Optional[str]) -> None:
        """
        Configure account and Virtual Organization with environment and config fallbacks.

        Tries to determine the account and VO in the following order:
        1. Provided parameter
        2. Environment variable (RUCIO_ACCOUNT, RUCIO_VO)
        3. Configuration file
        4. Default value (for VO only, defaults to DEFAULT_VO)

        Parameters
        ----------
        account :
            Rucio account name
        vo :
            Virtual Organization name
        """
        self.account = (
            account
            or environ.get('RUCIO_ACCOUNT')
            or config_get('client', 'account', raise_exception=False, default=None)
        )

        if vo is not None:
            self.vo = vo
        else:
            self.vo = (
                environ.get('RUCIO_VO')
                or config_get('client', 'vo', raise_exception=False, default=None)
                or DEFAULT_VO
            )
            if self.vo == DEFAULT_VO:
                self.logger.debug('No VO found. Using default VO.')

    def _setup_oidc_config(self) -> None:
        """
        Setup OIDC-specific configuration parameters.

        Reads OIDC refresh configuration from the config file, including whether
        OIDC token refresh is active and how many minutes before expiration the
        refresh should begin.
        """
        self.auth_oidc_refresh_active = config_get_bool('client', 'auth_oidc_refresh_active', False, False)
        self.auth_oidc_refresh_before_exp = config_get_int('client', 'auth_oidc_refresh_before_exp', False, 20)

    def _validate_and_configure_tls(self) -> None:
        """
        Validate URL schemes and configure TLS certificates.

        Validates that both rucio_host and auth_host use allowed URL schemes (http/https).
        If HTTPS is used and no CA certificate is provided, attempts to discover it from:
        1. X509_CERT_DIR environment variable
        2. Configuration file
        3. Falls back to certifi's Mozilla CA bundle

        Raises
        ------
        ClientProtocolNotFound
            If URL has no scheme
        ClientProtocolNotSupported
            If URL scheme is not in allowed list
        """
        rucio_scheme = self._get_valid_url_scheme(self.host, ['http', 'https'])
        auth_scheme = self._get_valid_url_scheme(self.auth_host, ['http', 'https'])

        if (rucio_scheme == 'https' or auth_scheme == 'https') and self.ca_cert is None:
            self.ca_cert = self._discover_ca_cert()

    def _get_valid_url_scheme(self, host: str, allowed_schemes: list[str]) -> str:
        """
        Validate and return the URL scheme.

        Parameters
        ----------
        host :
            URL to validate
        allowed_schemes :
            List of allowed URL schemes

        Returns
        -------
        str
            The validated URL scheme

        Raises
        ------
        ClientProtocolNotFound
            If URL has no scheme
        ClientProtocolNotSupported
            If URL scheme is not in allowed list
        """
        scheme = urlparse(host).scheme
        if not scheme:
            raise ClientProtocolNotFound(host=host, protocols_allowed=allowed_schemes)
        if scheme not in allowed_schemes:
            raise ClientProtocolNotSupported(host=host, protocol=scheme, protocols_allowed=allowed_schemes)
        return scheme

    def _discover_ca_cert(self) -> Any:
        """
        Discover CA certificate from environment, config, or use default.

        Attempts to find a CA certificate in the following order:
        1. X509_CERT_DIR environment variable
        2. client.ca_cert configuration value
        3. Mozilla CA bundle (certifi) as fallback

        Returns
        -------
            Path to CA certificate file, directory, or True for default certifi bundle
        """
        self.logger.debug('HTTPS is required, but no ca_cert was passed. Trying to get it from X509_CERT_DIR.')
        ca_cert = os.environ.get('X509_CERT_DIR')

        if ca_cert is None:
            self.logger.debug('X509_CERT_DIR not defined. Trying config file.')
            try:
                ca_cert = _expand_path(config_get('client', 'ca_cert'))
            except (NoOptionError, NoSectionError, ConfigNotFound):
                self.logger.debug('No ca_cert found in configuration. Falling back to Mozilla default CA bundle (certifi).')
                ca_cert = True

        return ca_cert

    def _configure_request_retries(self) -> None:
        """
        Configure request retry count from configuration file.

        Attempts to read the request_retries setting from the config file.
        Falls back to the default REQUEST_RETRIES value if not configured
        or if the value is invalid.
        """
        try:
            self.request_retries = config_get_int('client', 'request_retries')
        except (NoOptionError, NoSectionError, ConfigNotFound):
            self.logger.debug('request_retries not specified in config file. Taking default.')
        except ValueError:
            self.logger.debug('request_retries must be an integer. Taking default.')

    def _populate_oidc_creds(self, creds: dict[str, Any]) -> None:
        """Populate OIDC credentials from config."""
        if 'oidc_refresh_lifetime' not in creds or creds['oidc_refresh_lifetime'] is None:
            creds['oidc_refresh_lifetime'] = config_get('client', 'oidc_refresh_lifetime', False, None)
        if 'oidc_issuer' not in creds or creds['oidc_issuer'] is None:
            creds['oidc_issuer'] = config_get('client', 'oidc_issuer', False, None)
        if 'oidc_audience' not in creds or creds['oidc_audience'] is None:
            creds['oidc_audience'] = config_get('client', 'oidc_audience', False, None)
        if 'oidc_auto' not in creds or creds['oidc_auto'] is False:
            creds['oidc_auto'] = config_get_bool('client', 'oidc_auto', False, False)
        if creds['oidc_auto']:
            if 'oidc_username' not in creds or creds['oidc_username'] is None:
                creds['oidc_username'] = config_get('client', 'oidc_username', False, None)
            if 'oidc_password' not in creds or creds['oidc_password'] is None:
                creds['oidc_password'] = config_get('client', 'oidc_password', False, None)
        if 'oidc_scope' not in creds or creds['oidc_scope'] is None or creds['oidc_scope'] == 'openid profile':
            creds['oidc_scope'] = config_get('client', 'oidc_scope', False, 'openid profile')
        if 'oidc_polling' not in creds or creds['oidc_polling'] is False:
            creds['oidc_polling'] = config_get_bool('client', 'oidc_polling', False, False)

    def _populate_userpass_creds(self, creds: dict[str, Any]) -> None:
        """Populate username/password credentials from config."""
        if 'username' not in creds or creds['username'] is None:
            creds['username'] = config_get('client', 'username')
        if 'password' not in creds or creds['password'] is None:
            creds['password'] = config_get('client', 'password')

    def _populate_x509_creds(self, creds: dict[str, Any]) -> None:
        """Populate X509 credentials from config."""
        if 'client_cert' not in creds or creds['client_cert'] is None:
            creds['client_cert'] = environ.get("RUCIO_CLIENT_CERT") or config_get('client', 'client_cert')

        creds['client_cert'] = _expand_path(creds['client_cert'])
        if not os.path.exists(creds['client_cert']):
            raise MissingClientParameter(f"X.509 client certificate not found: {creds['client_cert']!r}")

        if 'client_key' not in creds or creds['client_key'] is None:
            creds['client_key'] = environ.get("RUCIO_CLIENT_KEY") or config_get('client', 'client_key')

        creds['client_key'] = _expand_path(creds['client_key'])
        if not os.path.exists(creds['client_key']):
            raise MissingClientParameter(f"X.509 client key not found: {creds['client_key']!r}")

        perms = oct(os.stat(creds['client_key']).st_mode)[-3:]
        if perms not in ['400', '600']:
            raise CannotAuthenticate(
                f"X.509 authentication selected, but private key ({creds['client_key']}) "
                f"permissions are liberal (required: 400 or 600, found: {perms})"
            )

    def _populate_x509_proxy_creds(self, creds: dict[str, Any]) -> None:
        """Populate X509 proxy credentials from config."""
        gsi_proxy_path = f'/tmp/x509up_u{geteuid()}'
        if 'client_proxy' not in creds or creds['client_proxy'] is None:
            if 'RUCIO_CLIENT_PROXY' in environ:
                creds['client_proxy'] = environ['RUCIO_CLIENT_PROXY']
            elif config_has_section('client') and config_get('client', 'client_x509_proxy', default='') != '':
                creds['client_proxy'] = config_get('client', 'client_x509_proxy')
            elif 'X509_USER_PROXY' in environ:
                creds['client_proxy'] = environ['X509_USER_PROXY']
            elif os.path.isfile(gsi_proxy_path):
                creds['client_proxy'] = gsi_proxy_path

        creds['client_proxy'] = _expand_path(creds['client_proxy'])
        if not os.path.isfile(creds['client_proxy']):
            raise MissingClientParameter(
                f'Cannot find a valid X509 proxy; checked $RUCIO_CLIENT_PROXY, $X509_USER_PROXY '
                f'client/client_x509_proxy config and default path: {gsi_proxy_path!r}'
            )

    def _populate_ssh_creds(self, creds: dict[str, Any]) -> None:
        """Populate SSH credentials from config."""
        if 'ssh_private_key' not in creds or creds['ssh_private_key'] is None:
            creds['ssh_private_key'] = config_get('client', 'ssh_private_key')

        creds['ssh_private_key'] = _expand_path(creds['ssh_private_key'])
        if not os.path.isfile(creds["ssh_private_key"]):
            raise CannotAuthenticate(f'Provided ssh private key {creds["ssh_private_key"]!r} does not exist')

    def _request_oidc_auth_url(self) -> Optional[str]:
        """
        Request authorization URL from Rucio authentication server.

        Returns
        -------
        Optional[str]
            Authorization URL from identity provider, or None if request failed
        """
        headers = self._build_oidc_request_headers()
        request_auth_url = build_url(self.auth_host, path='auth/oidc')

        self.logger.debug("Initial auth URL request headers %s", headers)
        oidc_auth_res = self._send_request(request_auth_url, headers=headers, get_token=True)
        self.logger.debug("Response headers %s and text %s", oidc_auth_res.headers, oidc_auth_res.text)

        if HEADER_RUCIO_OIDC_AUTH_URL not in oidc_auth_res.headers:
            self.logger.error("Failed to get AuthN/Z URL from Rucio Auth Server. Check scope, audience, or issuer configuration.")
            return None

        return oidc_auth_res.headers[HEADER_RUCIO_OIDC_AUTH_URL]

    def _build_oidc_request_headers(self) -> dict[str, str]:
        """
        Build HTTP headers for OIDC authentication request.

        Returns
        -------
        dict
            Dictionary of HTTP headers for OIDC request
        """
        headers = {
            'X-Rucio-Client-Authorize-Auto': str(self.creds['oidc_auto']),
            'X-Rucio-Client-Authorize-Polling': str(self.creds['oidc_polling']),
            'X-Rucio-Client-Authorize-Scope': str(self.creds['oidc_scope']),
            'X-Rucio-Client-Authorize-Refresh-Lifetime': str(self.creds['oidc_refresh_lifetime'])
        }

        if self.creds['oidc_audience']:
            headers['X-Rucio-Client-Authorize-Audience'] = str(self.creds['oidc_audience'])
        if self.creds['oidc_issuer']:
            headers['X-Rucio-Client-Authorize-Issuer'] = str(self.creds['oidc_issuer'])

        return headers

    def _handle_oidc_polling_flow(self, auth_url: str) -> Optional[Response]:
        """
        Handle OIDC authentication with polling flow.

        Parameters
        ----------
        auth_url :
            Authorization URL for authentication

        Returns
        -------
        Optional[Response]
            Response containing auth token if successful, None otherwise
        """
        self.logger.info("Please use your internet browser and go to:\n\n    %s\n", auth_url)
        self.logger.info("and authenticate with your Identity Provider.")
        self.logger.info("Rucio Client will poll the auth server for %d minutes.", OIDC_POLLING_TIMEOUT_SECONDS // 60)
        self.logger.info("----------------------------------------------")

        headers = {'X-Rucio-Client-Fetch-Token': 'True'}
        start_time = time.time()

        while time.time() - start_time < OIDC_POLLING_TIMEOUT_SECONDS:
            result = self._send_request(auth_url, headers=headers, get_token=True)
            if HEADER_RUCIO_AUTH_TOKEN in result.headers and result.status_code == codes.ok:
                return result
            time.sleep(OIDC_POLLING_INTERVAL_SECONDS)

        self.logger.error("OIDC polling timeout after %d seconds", OIDC_POLLING_TIMEOUT_SECONDS)
        return None

    def _handle_oidc_manual_code_flow(self, auth_url: str) -> Optional[Response]:
        """
        Handle OIDC authentication with manual code entry flow.

        Parameters
        ----------
        auth_url :
            Authorization URL for authentication

        Returns
        -------
        Optional[Response]
            Response containing auth token if successful, None otherwise
        """
        self.logger.info("Please use your internet browser and go to:\n\n    %s\n", auth_url)
        self.logger.info("and authenticate with your Identity Provider.")
        self.logger.info("Copy paste the code from the browser to the terminal and press enter:")

        headers = {'X-Rucio-Client-Fetch-Token': 'True'}

        for attempt in range(OIDC_MAX_CODE_ATTEMPTS):
            fetchcode = input()
            fetch_url = build_url(self.auth_host, path='auth/oidc_redirect', params=fetchcode)
            result = self._send_request(fetch_url, headers=headers, get_token=True)

            if HEADER_RUCIO_AUTH_TOKEN in result.headers and result.status_code == codes.ok:
                return result

            if attempt < OIDC_MAX_CODE_ATTEMPTS - 1:
                self.logger.warning("Auth server did not respond as expected. Please try again with the correct code.")

        self.logger.error("Failed to authenticate after %d attempts", OIDC_MAX_CODE_ATTEMPTS)
        return None

    def _handle_oidc_auto_flow(self, auth_url: str) -> Optional[Response]:
        """
        Handle automatic OIDC authentication flow (discouraged).

        Parameters
        ----------
        auth_url :
            Authorization URL for authentication

        Returns
        -------
        Optional[Response]
            Response containing auth token if successful, None otherwise
        """
        self.logger.warning(
            "Automatic OIDC authentication shares credentials with 3rd party. "
            "This violates OAuth2/OIDC best practices and is strongly discouraged."
        )

        userpass = {'username': self.creds['oidc_username'], 'password': self.creds['oidc_password']}
        auth_res = self._send_request(auth_url, get_token=True)

        result = self._send_request(auth_res.url, method=HTTPMethod.POST, data=userpass)

        if 'OAuth Error' in result.text:
            self.logger.error('Identity Provider rejected request. Check OIDC Client configuration.')
            return None

        if result.url == auth_url:
            result = self._auto_authorize_oidc_scopes(result.url)

        return result

    def _auto_authorize_oidc_scopes(self, url: str) -> Response:
        """
        Automatically authorize OIDC scope request on behalf of user.

        Parameters
        ----------
        url :
            Authorization form URL

        Returns
        -------
        Response
            Response from authorization request
        """
        form_data = {f"scope_{scope}": scope for scope in self.creds['oidc_scope'].split()}
        form_data.update({
            "remember": "until-revoked",
            "user_oauth_approval": True,
            "authorize": "Authorize"
        })

        self.logger.warning('Auto-authorizing scope request: %s', form_data)
        return self._send_request(url, method=HTTPMethod.POST, data=form_data)

    def _finalize_oidc_token(self, result: Optional[Response]) -> bool:
        """
        Extract and store OIDC auth token from response.

        Parameters
        ----------
        result :
            Response from OIDC authentication

        Returns
        -------
        bool
            True if token successfully extracted, False otherwise
        """
        if not result:
            self.logger.error('Cannot retrieve authentication token!')
            return False

        if result.status_code != codes.ok:
            exc_cls, exc_msg = self._get_exception(
                headers=result.headers,
                status_code=result.status_code,
                data=result.content
            )
            raise exc_cls(exc_msg)

        self.auth_token = result.headers['x-rucio-auth-token']

        if self.auth_oidc_refresh_active:
            self.logger.debug("Resetting token expiration epoch file.")
            self.token_exp_epoch = None
            file_d, file_n = mkstemp(dir=self.token_path)
            with fdopen(file_d, "w") as f_exp_epoch:
                f_exp_epoch.write(str(self.token_exp_epoch))
            move(file_n, self.token_exp_epoch_file)
            self.__refresh_token_oidc()

        return True
