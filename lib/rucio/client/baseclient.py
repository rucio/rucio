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
from configparser import NoOptionError, NoSectionError
from os import environ, fdopen, geteuid, makedirs
from shutil import move
from tempfile import mkstemp
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urlparse

import requests
from dogpile.cache import make_region
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

STATUS_CODES_TO_RETRY = [502, 503, 504]
MAX_RETRY_BACK_OFF_SECONDS = 10


@REGION.cache_on_arguments(namespace='host_to_choose')
def choice(hosts):
    """
    Select randomly a host

    :param hosts: Lost of hosts
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

    def __init__(self,
                 rucio_host: Optional[str] = None,
                 auth_host: Optional[str] = None,
                 account: Optional[str] = None,
                 ca_cert: Optional[str] = None,
                 auth_type: Optional[str] = None,
                 creds: Optional[dict[str, Any]] = None,
                 timeout: Optional[int] = 600,
                 user_agent: Optional[str] = 'rucio-clients',
                 vo: Optional[str] = None,
                 logger: 'Logger' = LOG) -> None:
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
        self.session = Session()
        self.user_agent = "%s/%s" % (user_agent, version.version_string())  # e.g. "rucio-clients/0.2.13"
        sys.argv[0] = sys.argv[0].split('/')[-1]
        self.script_id = '::'.join(sys.argv[0:2])
        if self.script_id == '':  # Python interpreter used
            self.script_id = 'python'
        try:
            if rucio_host is not None:
                self.host = rucio_host
            else:
                self.host = config_get('client', 'rucio_host')
        except (NoOptionError, NoSectionError) as error:
            raise MissingClientParameter('Section client and Option \'%s\' cannot be found in config file' % error.args[0])

        try:
            if auth_host is not None:
                self.auth_host = auth_host
            else:
                self.auth_host = config_get('client', 'auth_host')
        except (NoOptionError, NoSectionError) as error:
            raise MissingClientParameter('Section client and Option \'%s\' cannot be found in config file' % error.args[0])

        try:
            self.trace_host = config_get('trace', 'trace_host')
        except (NoOptionError, NoSectionError, ConfigNotFound):
            self.trace_host = self.host
            self.logger.debug('No trace_host passed. Using rucio_host instead')

        self.list_hosts = [self.host]
        self.account = account
        self.ca_cert = ca_cert
        self.auth_token = ""
        self.headers = {}
        self.timeout = timeout
        self.request_retries = self.REQUEST_RETRIES
        self.token_exp_epoch = None
        self.auth_oidc_refresh_active = config_get_bool('client', 'auth_oidc_refresh_active', False, False)

        # defining how many minutes before token expires, oidc refresh (if active) should start
        self.auth_oidc_refresh_before_exp = config_get_int('client', 'auth_oidc_refresh_before_exp', False, 20)

        self.auth_type = self._get_auth_type(auth_type)
        self.creds = self._get_creds(creds)

        rucio_scheme = urlparse(self.host).scheme
        auth_scheme = urlparse(self.auth_host).scheme

        rucio_scheme_allowed = ['http', 'https']
        auth_scheme_allowed = ['http', 'https']

        if not rucio_scheme:
            raise ClientProtocolNotFound(host=self.host, protocols_allowed=rucio_scheme_allowed)
        elif rucio_scheme not in rucio_scheme_allowed:
            raise ClientProtocolNotSupported(host=self.host, protocol=rucio_scheme, protocols_allowed=rucio_scheme_allowed)

        if not auth_scheme:
            raise ClientProtocolNotFound(host=self.auth_host, protocols_allowed=auth_scheme_allowed)
        elif auth_scheme not in auth_scheme_allowed:
            raise ClientProtocolNotSupported(host=self.auth_host, protocol=auth_scheme, protocols_allowed=auth_scheme_allowed)

        if (rucio_scheme == 'https' or auth_scheme == 'https') and ca_cert is None:
            self.logger.debug('HTTPS is required, but no ca_cert was passed. Trying to get it from X509_CERT_DIR.')
            self.ca_cert = os.environ.get('X509_CERT_DIR', None)
            if self.ca_cert is None:
                self.logger.debug('HTTPS is required, but no ca_cert was passed and X509_CERT_DIR is not defined. Trying to get it from the config file.')
                try:
                    self.ca_cert = _expand_path(config_get('client', 'ca_cert'))
                except (NoOptionError, NoSectionError):
                    self.logger.debug('No ca_cert found in configuration. Falling back to Mozilla default CA bundle (certifi).')
                    self.ca_cert = True
                except ConfigNotFound:
                    self.logger.debug('No configuration found. Falling back to Mozilla default CA bundle (certifi).')
                    self.ca_cert = True

        if account is None:
            self.logger.debug('No account passed. Trying to get it from the RUCIO_ACCOUNT environment variable or the config file.')
            try:
                self.account = environ['RUCIO_ACCOUNT']
            except KeyError:
                try:
                    self.account = config_get('client', 'account')
                except (NoOptionError, NoSectionError):
                    pass

        if vo is not None:
            self.vo = vo
        else:
            self.logger.debug('No VO passed. Trying to get it from environment variable RUCIO_VO.')
            try:
                self.vo = environ['RUCIO_VO']
            except KeyError:
                self.logger.debug('No VO found. Trying to get it from the config file.')
                try:
                    self.vo = config_get('client', 'vo')
                except (NoOptionError, NoSectionError):
                    self.logger.debug('No VO found. Using default VO.')
                    self.vo = DEFAULT_VO
                except ConfigNotFound:
                    self.logger.debug('No configuration found. Using default VO.')
                    self.vo = DEFAULT_VO

        self.auth_token_file_path, self.token_exp_epoch_file, self.token_file, self.token_path = self._get_auth_tokens()
        self.__authenticate()

        try:
            self.request_retries = config_get_int('client', 'request_retries')
        except (NoOptionError, ConfigNotFound):
            self.logger.debug('request_retries not specified in config file. Taking default.')
        except ValueError:
            self.logger.debug('request_retries must be an integer. Taking default.')

    def _get_auth_tokens(self) -> tuple[Optional[str], str, str, str]:
        # if token file path is defined in the rucio.cfg file, use that file. Currently this prevents authenticating as another user or VO.
        auth_token_file_path = config_get('client', 'auth_token_file_path', False, None)
        token_filename_suffix = "for_default_account" if self.account is None else "for_account_" + self.account

        if auth_token_file_path:
            token_file = auth_token_file_path
            token_path = '/'.join(auth_token_file_path.split('/')[:-1])

        else:
            token_path = self.TOKEN_PATH_PREFIX + getpass.getuser()
            if self.vo != DEFAULT_VO:
                token_path += '@%s' % self.vo

            token_file = token_path + '/' + self.TOKEN_PREFIX + token_filename_suffix

        token_exp_epoch_file = token_path + '/' + self.TOKEN_EXP_PREFIX + token_filename_suffix
        return auth_token_file_path, token_exp_epoch_file, token_file, token_path

    def _get_auth_type(self, auth_type: Optional[str]) -> str:
        if auth_type is None:
            self.logger.debug('No auth_type passed. Trying to get it from the environment variable RUCIO_AUTH_TYPE and config file.')
            if 'RUCIO_AUTH_TYPE' in environ:
                if environ['RUCIO_AUTH_TYPE'] not in ['userpass', 'x509', 'x509_proxy', 'gss', 'ssh', 'saml', 'oidc']:
                    raise MissingClientParameter('Possible RUCIO_AUTH_TYPE values: userpass, x509, x509_proxy, gss, ssh, saml, oidc, vs. ' + environ['RUCIO_AUTH_TYPE'])
                auth_type = environ['RUCIO_AUTH_TYPE']
            else:
                try:
                    auth_type = config_get('client', 'auth_type')
                except (NoOptionError, NoSectionError) as error:
                    raise MissingClientParameter('Option \'%s\' cannot be found in config file' % error.args[0])
        return auth_type

    def _get_creds(self, creds: Optional[dict[str, Any]]) -> dict[str, Any]:
        if not creds:
            self.logger.debug('No creds passed. Trying to get it from the config file.')
            creds = {}

        try:
            if self.auth_type == 'oidc':
                # if there are default values, check if rucio.cfg does not specify them, otherwise put default
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
                if 'oidc_scope' not in creds or creds['oidc_scope'] == 'openid profile':
                    creds['oidc_scope'] = config_get('client', 'oidc_scope', False, 'openid profile')
                if 'oidc_polling' not in creds or creds['oidc_polling'] is False:
                    creds['oidc_polling'] = config_get_bool('client', 'oidc_polling', False, False)

            elif self.auth_type in ['userpass', 'saml']:
                if 'username' not in creds or creds['username'] is None:
                    creds['username'] = config_get('client', 'username')
                if 'password' not in creds or creds['password'] is None:
                    creds['password'] = config_get('client', 'password')

            elif self.auth_type == 'x509':
                if 'client_cert' not in creds or creds['client_cert'] is None:
                    if "RUCIO_CLIENT_CERT" in environ:
                        creds['client_cert'] = environ["RUCIO_CLIENT_CERT"]
                    else:
                        creds['client_cert'] = config_get('client', 'client_cert')

                creds['client_cert'] = _expand_path(creds['client_cert'])

                if not os.path.exists(creds['client_cert']):
                    raise MissingClientParameter('X.509 client certificate not found: %r' % creds['client_cert'])

                if 'client_key' not in creds or creds['client_key'] is None:
                    if "RUCIO_CLIENT_KEY" in environ:
                        creds['client_key'] = environ["RUCIO_CLIENT_KEY"]
                    else:
                        creds['client_key'] = config_get('client', 'client_key')

                creds['client_key'] = _expand_path(creds['client_key'])
                if not os.path.exists(creds['client_key']):
                    raise MissingClientParameter('X.509 client key not found: %r' % creds['client_key'])

                perms = oct(os.stat(creds['client_key']).st_mode)[-3:]
                if perms not in ['400', '600']:
                    raise CannotAuthenticate('X.509 authentication selected, but private key (%s) permissions are liberal (required: 400 or 600, found: %s)' % (creds['client_key'], perms))

            elif self.auth_type == 'x509_proxy':
                # rucio specific configuration takes precedence over GSI logic
                # environment variables take precedence over config values
                # So we check in order:
                # RUCIO_CLIENT_PROXY env variable
                # client.client_x509_proxy rucio cfg variable
                # X509_USER_PROXY env variable
                # /tmp/x509up_u`id -u` if exists

                gsi_proxy_path = '/tmp/x509up_u%d' % geteuid()
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
                        'Cannot find a valid X509 proxy; checked $RUCIO_CLIENT_PROXY, $X509_USER_PROXY'
                        'client/client_x509_proxy config and default path: %r' % gsi_proxy_path
                    )

            elif self.auth_type == 'ssh':
                if 'ssh_private_key' not in creds or creds['ssh_private_key'] is None:
                    creds['ssh_private_key'] = config_get('client', 'ssh_private_key')

                creds['ssh_private_key'] = _expand_path(creds['ssh_private_key'])
                if not os.path.isfile(creds["ssh_private_key"]):
                    raise CannotAuthenticate('Provided ssh private key %r does not exist' % creds['ssh_private_key'])

        except (NoOptionError, NoSectionError) as error:
            if error.args[0] != 'client_key':
                raise MissingClientParameter('Option \'%s\' cannot be found in config file' % error.args[0])

        return creds

    def _get_exception(self, headers: dict[str, str], status_code: Optional[int] = None, data=None) -> tuple[type[exception.RucioException], str]:
        """
        Helper method to parse an error string send by the server and transform it into the corresponding rucio exception.

        :param headers: The http response header containing the Rucio exception details.
        :param status_code: The http status code.
        :param data: The data with the ExceptionMessage.

        :return: A rucio exception class and an error string.
        """
        if data is not None:
            try:
                data = parse_response(data)
            except ValueError:
                data = {}
        else:
            data = {}

        exc_cls = 'RucioException'
        exc_msg = 'no error information passed (http status code: %s)' % status_code
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
        else:
            return exception.RucioException, "%s: %s" % (exc_cls, exc_msg)

    def _load_json_data(self, response: requests.Response) -> 'Generator[Any, Any, Any]':
        """
        Helper method to correctly load json data based on the content type of the http response.

        :param response: the response received from the server.
        """
        if 'content-type' in response.headers and response.headers['content-type'] == 'application/x-json-stream':
            for line in response.iter_lines():
                if line:
                    yield parse_response(line)
        elif 'content-type' in response.headers and response.headers['content-type'] == 'application/json':
            yield parse_response(response.text)
        else:  # Exception ?
            if response.text:
                yield response.text

    def _reduce_data(self, data, maxlen: int = 132) -> str:
        if isinstance(data, dict):
            data = json.dumps(data)
        text = data if isinstance(data, str) else data.decode("utf-8")
        if len(text) > maxlen:
            text = "%s ... %s" % (text[:maxlen - 15], text[-10:])
        return text

    def _back_off(self, retry_number: int, reason: str) -> None:
        """
        Sleep a certain amount of time which increases with the retry count
        :param retry_number: the retry iteration
        :param reason: the reason to backoff which will be shown to the user
        """
        sleep_time = min(MAX_RETRY_BACK_OFF_SECONDS, 0.25 * 2 ** retry_number)
        self.logger.warning("Waiting %ss due to reason: %s", sleep_time, reason)
        time.sleep(sleep_time)

    def _send_request(self, url, method, headers=None, data=None, params=None, stream=False, get_token=False,
                      cert=None, auth=None, verify=None):
        """
        Helper method to send requests to the rucio server. Gets a new token and retries if an unauthorized error is returned.

        :param url: the http url to use.
        :param headers: additional http headers to send.
        :param method: the http request type to use.
        :param data: post data.
        :param params: (optional) Dictionary or bytes to be sent in the url query string.
        :param get_token: (optional) if it is called from a _get_token function.
        :param cert: (optional) if String, path to the SSL client cert file (.pem). If Tuple, (cert, key) pair.
        :param auth: (optional) auth tuple to enable Basic/Digest/Custom HTTP Auth.
        :param verify: (optional) either a boolean, in which case it controls whether we verify the server's TLS
                       certificate, or a string, in which case it must be a path to a CA bundle to use.
        :return: the HTTP return body.
        """
        hds = {'X-Rucio-Auth-Token': self.auth_token, 'X-Rucio-VO': self.vo,
               'Connection': 'Keep-Alive', 'User-Agent': self.user_agent,
               'X-Rucio-Script': self.script_id}

        if self.account is not None:
            hds['X-Rucio-Account'] = self.account

        if headers is not None:
            hds.update(headers)
        if verify is None:
            verify = self.ca_cert or False  # Maybe unnecessary but make sure to convert "" -> False

        self.logger.debug("HTTP request: %s %s", method.value, url)
        for h, v in hds.items():
            if h == 'X-Rucio-Auth-Token':
                v = "[hidden]"
            self.logger.debug("HTTP header:  %s: %s", h, v)
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
                    self.logger.debug("Unknown request type %s. Request was not sent", method,)
                    return None
                self.logger.debug("HTTP Response: %s %s", result.status_code, result.reason)
                if result.status_code in STATUS_CODES_TO_RETRY:
                    self._back_off(retry, 'server returned {}'.format(result.status_code))
                    continue
                if result.status_code // 100 != 2 and result.text:
                    # do not do this for successful requests because the caller may be expecting streamed response
                    self.logger.debug("Response text (length=%d): [%s]", len(result.text), result.text)
            except ConnectionError as error:
                self.logger.error('ConnectionError: %s', error)
                if retry > self.request_retries:
                    raise
                continue
            except OSError as error:
                # Handle Broken Pipe
                # While in python3 we can directly catch 'BrokenPipeError', in python2 it doesn't exist.
                if getattr(error, 'errno') != errno.EPIPE:
                    raise
                self.logger.error('BrokenPipe: %s', error)
                if retry > self.request_retries:
                    raise
                continue

            if result is not None and result.status_code == codes.unauthorized and not get_token:  # pylint: disable-msg=E1101
                self.session = Session()
                self.__get_token()
                hds['X-Rucio-Auth-Token'] = self.auth_token
            else:
                break

        if result is None:
            raise ServerConnectionException
        return result

    def __get_token_userpass(self) -> bool:
        """
        Sends a request to get an auth token from the server and stores it as a class attribute. Uses username/password.

        :returns: True if the token was successfully received. False otherwise.
        """

        headers = {'X-Rucio-Username': self.creds['username'],
                   'X-Rucio-Password': self.creds['password']}

        url = build_url(self.auth_host, path='auth/userpass')

        result = self._send_request(url, method=HTTPMethod.GET, headers=headers, get_token=True)

        if not result:
            # result is either None or not OK.
            if isinstance(result, Response):
                if 'ExceptionClass' in result.headers and result.headers['ExceptionClass']:
                    if 'ExceptionMessage' in result.headers and result.headers['ExceptionMessage']:
                        raise CannotAuthenticate('%s: %s' % (result.headers['ExceptionClass'], result.headers['ExceptionMessage']))
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

        self.auth_token = result.headers['x-rucio-auth-token']
        return True

    def __refresh_token_oidc(self) -> bool:
        """
        Checks if there is active refresh token and if so returns
        either active token with expiration timestamp or requests a new
        refresh and returns new access token with new expiration timestamp
        and saves these in the token directory.

        :returns: True if the token was successfully received. False otherwise.
        """

        if not self.auth_oidc_refresh_active:
            return False
        if os.path.exists(self.token_exp_epoch_file):
            with open(self.token_exp_epoch_file, 'r') as token_epoch_file:
                try:
                    self.token_exp_epoch = int(token_epoch_file.readline())
                except Exception:
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
            if 'X-Rucio-Auth-Token-Expires' not in refresh_result.headers or \
                    'X-Rucio-Auth-Token' not in refresh_result.headers:
                print("Rucio Server response does not contain the expected headers.")
                return False
            else:
                new_token = refresh_result.headers['X-Rucio-Auth-Token']
                new_exp_epoch = refresh_result.headers['X-Rucio-Auth-Token-Expires']
                if new_token and new_exp_epoch:
                    self.logger.debug("Saving token %s and expiration epoch %s to files", str(new_token), str(new_exp_epoch))
                    # save to the file
                    self.auth_token = new_token
                    self.token_exp_epoch = new_exp_epoch
                    self.__write_token()
                    self.headers['X-Rucio-Auth-Token'] = self.auth_token
                    return True
                self.logger.debug("No new token was received, possibly invalid/expired \
                           \ntoken or a token with no refresh token in Rucio DB")
                return False
        else:
            print("Rucio Client did not succeed to contact the \
                   \nRucio Auth Server when attempting token refresh.")
            return False

    def __get_token_oidc(self) -> bool:
        """
        First authenticates the user via a Identity Provider server
        (with user's username & password), by specifying oidc_scope,
        user agrees to share the relevant information with Rucio.
        If all proceeds well, an access token is requested from the Identity Provider.
        Access Tokens are not stored in Rucio DB.
        Refresh Tokens are granted only in case no valid access token exists in user's
        local storage, oidc_scope includes 'offline_access'. In such case, refresh token
        is stored in Rucio DB.

        :returns: True if the token was successfully received. False otherwise.
        """
        oidc_scope = str(self.creds['oidc_scope'])
        headers = {'X-Rucio-Client-Authorize-Auto': str(self.creds['oidc_auto']),
                   'X-Rucio-Client-Authorize-Polling': str(self.creds['oidc_polling']),
                   'X-Rucio-Client-Authorize-Scope': str(self.creds['oidc_scope']),
                   'X-Rucio-Client-Authorize-Refresh-Lifetime': str(self.creds['oidc_refresh_lifetime'])}
        if self.creds['oidc_audience']:
            headers['X-Rucio-Client-Authorize-Audience'] = str(self.creds['oidc_audience'])
        if self.creds['oidc_issuer']:
            headers['X-Rucio-Client-Authorize-Issuer'] = str(self.creds['oidc_issuer'])
        if self.creds['oidc_auto']:
            userpass = {'username': self.creds['oidc_username'], 'password': self.creds['oidc_password']}

        result = None
        request_auth_url = build_url(self.auth_host, path='auth/oidc')
        # requesting authorization URL specific to the user & Rucio OIDC Client
        self.logger.debug("Initial auth URL request headers %s to files", str(headers))
        oidc_auth_res = self._send_request(request_auth_url, method=HTTPMethod.GET, headers=headers, get_token=True)
        self.logger.debug("Response headers %s and text %s", str(oidc_auth_res.headers), str(oidc_auth_res.text))
        # with the obtained authorization URL we will contact the Identity Provider to get to the login page
        if 'X-Rucio-OIDC-Auth-URL' not in oidc_auth_res.headers:
            print("Rucio Client did not succeed to get AuthN/Z URL from the Rucio Auth Server. \
                                   \nThis could be due to wrongly requested/configured scope, audience or issuer.")
            return False
        auth_url = oidc_auth_res.headers['X-Rucio-OIDC-Auth-URL']
        if not self.creds['oidc_auto']:
            print("\nPlease use your internet browser, go to:")
            print("\n    " + auth_url + "    \n")
            print("and authenticate with your Identity Provider.")

            headers['X-Rucio-Client-Fetch-Token'] = 'True'
            if self.creds['oidc_polling']:
                timeout = 180
                start = time.time()
                print("In the next 3 minutes, Rucio Client will be polling \
                                           \nthe Rucio authentication server for a token.")
                print("----------------------------------------------")
                while time.time() - start < timeout:
                    result = self._send_request(auth_url, method=HTTPMethod.GET, headers=headers, get_token=True)
                    if 'X-Rucio-Auth-Token' in result.headers and result.status_code == codes.ok:
                        break
                    time.sleep(2)
            else:
                print("Copy paste the code from the browser to the terminal and press enter:")
                count = 0
                while count < 3:
                    fetchcode = input()
                    fetch_url = build_url(self.auth_host, path='auth/oidc_redirect', params=fetchcode)
                    result = self._send_request(fetch_url, method=HTTPMethod.GET, headers=headers, get_token=True)
                    if 'X-Rucio-Auth-Token' in result.headers and result.status_code == codes.ok:
                        break
                    else:
                        print("The Rucio Auth Server did not respond as expected. Please, "
                              + "try again and make sure you typed the correct code.")
                        count += 1

        else:
            print("\nAccording to the OAuth2/OIDC standard you should NOT be sharing \n"
                  + "your password with any 3rd party application, therefore, \n"
                  + "we strongly discourage you from following this --oidc-auto approach.")
            print("-------------------------------------------------------------------------")
            auth_res = self._send_request(auth_url, method=HTTPMethod.GET, get_token=True)
            # getting the login URL and logging in the user
            login_url = auth_res.url
            start = time.time()
            result = self._send_request(login_url, method=HTTPMethod.POST, data=userpass)

            # if the Rucio OIDC Client configuration does not match the one registered at the Identity Provider
            # the user will get an OAuth error
            if 'OAuth Error' in result.text:
                self.logger.error('Identity Provider does not allow to proceed. Could be due \
                           \nto misconfigured redirection server name of the Rucio OIDC Client.')
                return False
            # In case Rucio Client is not authorized to request information about this user yet,
            # it will automatically authorize itself on behalf of the user.
            if result.url == auth_url:
                form_data = {}
                for scope_item in oidc_scope.split():
                    form_data["scope_" + scope_item] = scope_item
                default_data = {"remember": "until-revoked",
                                "user_oauth_approval": True,
                                "authorize": "Authorize"}
                form_data.update(default_data)
                print('Automatically authorising request of the following info on behalf of user: %s', str(form_data))
                self.logger.warning('Automatically authorising request of the following info on behalf of user: %s',
                                    str(form_data))
                # authorizing info request on behalf of the user until he/she revokes this authorization !
                result = self._send_request(result.url, method=HTTPMethod.POST, data=form_data)

        if not result:
            self.logger.error('Cannot retrieve authentication token!')
            return False

        if result.status_code != codes.ok:  # pylint: disable-msg=E1101
            exc_cls, exc_msg = self._get_exception(headers=result.headers,
                                                   status_code=result.status_code,
                                                   data=result.content)
            raise exc_cls(exc_msg)

        self.auth_token = result.headers['x-rucio-auth-token']
        if self.auth_oidc_refresh_active:
            self.logger.debug("Resetting the token expiration epoch file content.")
            # reset the token expiration epoch file content
            # at new CLI OIDC authentication
            self.token_exp_epoch = None
            file_d, file_n = mkstemp(dir=self.token_path)
            with fdopen(file_d, "w") as f_exp_epoch:
                f_exp_epoch.write(str(self.token_exp_epoch))
            move(file_n, self.token_exp_epoch_file)
            self.__refresh_token_oidc()
        return True

    def __get_token_x509(self) -> bool:
        """
        Sends a request to get an auth token from the server and stores it as a class attribute. Uses x509 authentication.

        :returns: True if the token was successfully received. False otherwise.
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

        if (client_cert is not None) and not (os.path.exists(client_cert)):
            self.logger.error('given client cert (%s) doesn\'t exist', client_cert)
            return False
        if client_key is not None and not os.path.exists(client_key):
            self.logger.error('given client key (%s) doesn\'t exist', client_key)

        if client_key is None:
            cert = client_cert
        else:
            cert = (client_cert, client_key)

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

        self.auth_token = result.headers['x-rucio-auth-token']
        return True

    def __get_token_ssh(self) -> bool:
        """
        Sends a request to get an auth token from the server and stores it as a class attribute. Uses SSH key exchange authentication.

        :returns: True if the token was successfully received. False otherwise.
        """
        headers = {}

        private_key_path = self.creds['ssh_private_key']
        if not os.path.exists(private_key_path):
            self.logger.error('given private key (%s) doesn\'t exist', private_key_path)
            return False
        if private_key_path is not None and not os.path.exists(private_key_path):
            self.logger.error('given private key (%s) doesn\'t exist', private_key_path)
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
        self.logger.debug('got new ssh challenge token \'%s\'', self.ssh_challenge_token)

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

        self.auth_token = result.headers['x-rucio-auth-token']
        return True

    def __get_token_gss(self) -> bool:
        """
        Sends a request to get an auth token from the server and stores it as a class attribute. Uses Kerberos authentication.

        :returns: True if the token was successfully received. False otherwise.
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

        self.auth_token = result.headers['x-rucio-auth-token']
        return True

    def __get_token_saml(self) -> bool:
        """
        Sends a request to get an auth token from the server and stores it as a class attribute. Uses saml authentication.

        :returns: True if the token was successfully received. False otherwise.
        """
        userpass = {'username': self.creds['username'], 'password': self.creds['password']}
        url = build_url(self.auth_host, path='auth/saml')

        result = None
        saml_auth_result = self._send_request(url, method=HTTPMethod.GET, get_token=True)
        if saml_auth_result.headers['X-Rucio-Auth-Token']:
            return saml_auth_result.headers['X-Rucio-Auth-Token']
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

        self.auth_token = result.headers['X-Rucio-Auth-Token']
        return True

    def __get_token(self) -> None:
        """
        Calls the corresponding method to receive an auth token depending on the auth type. To be used if a 401 - Unauthorized error is received.
        """

        self.logger.debug('get a new token')
        for retry in range(self.AUTH_RETRIES + 1):
            if self.auth_type == 'userpass':
                if not self.__get_token_userpass():
                    raise CannotAuthenticate('userpass authentication failed for account=%s with identity=%s' % (self.account,
                                                                                                                 self.creds['username']))
            elif self.auth_type == 'x509' or self.auth_type == 'x509_proxy':
                if not self.__get_token_x509():
                    raise CannotAuthenticate('x509 authentication failed for account=%s with identity=%s' % (self.account,
                                                                                                             self.creds))
            elif self.auth_type == 'oidc':
                if not self.__get_token_oidc():
                    raise CannotAuthenticate('OIDC authentication failed for account=%s' % self.account)

            elif self.auth_type == 'gss':
                if not self.__get_token_gss():
                    raise CannotAuthenticate('kerberos authentication failed for account=%s with identity=%s' % (self.account,
                                                                                                                 self.creds))
            elif self.auth_type == 'ssh':
                if not self.__get_token_ssh():
                    raise CannotAuthenticate('ssh authentication failed for account=%s with identity=%s' % (self.account,
                                                                                                            self.creds))
            elif self.auth_type == 'saml':
                if not self.__get_token_saml():
                    raise CannotAuthenticate('saml authentication failed for account=%s with identity=%s' % (self.account,
                                                                                                             self.creds))
            else:
                raise CannotAuthenticate('auth type \'%s\' not supported' % self.auth_type)

            if self.auth_token is not None:
                self.__write_token()
                self.headers['X-Rucio-Auth-Token'] = self.auth_token
                break

        if self.auth_token is None:
            raise CannotAuthenticate('cannot get an auth token from server')

    def __read_token(self) -> bool:
        """
        Checks if a local token file exists and reads the token from it.

        :return: True if a token could be read. False if no file exists.
        """

        if self.auth_type == "oidc":
            token = wlcg_token_discovery()
            if token:
                self.auth_token = token
                self.headers['X-Rucio-Auth-Token'] = self.auth_token
                return True

        if not os.path.exists(self.token_file):
            return False

        try:
            with open(self.token_file, 'r') as token_file_handler:
                self.auth_token = token_file_handler.readline()
            self.headers['X-Rucio-Auth-Token'] = self.auth_token
        except OSError as error:
            print("I/O error({0}): {1}".format(error.errno, error.strerror))
        except Exception:
            raise
        if self.auth_oidc_refresh_active and self.auth_type == 'oidc':
            self.__refresh_token_oidc()
        self.logger.debug('got token from file')
        return True

    def __write_token(self) -> None:
        """
        Write the current auth_token to the local token file.
        """
        # check if rucio temp directory is there. If not create it with permissions only for the current user
        if not os.path.isdir(self.token_path):
            try:
                self.logger.debug("rucio token folder '%s' not found. Create it.", self.token_path)
                try:
                    makedirs(self.token_path, 0o700)
                except FileExistsError:
                    msg = f'Token directory already exists at {self.token_path} - skipping'
                    self.logger.debug(msg)
            except Exception:
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
            print("I/O error({0}): {1}".format(error.errno, error.strerror))
        except Exception:
            raise

    def __authenticate(self) -> None:
        """
        Main method for authentication. It first tries to read a locally saved token. If not available it requests a new one.
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
            raise CannotAuthenticate('auth type \'%s\' not supported' % self.auth_type)

        if not self.__read_token():
            self.__get_token()
