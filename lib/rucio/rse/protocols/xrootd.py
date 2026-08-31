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

from __future__ import annotations

import logging
import os
import threading
from importlib import import_module
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from rucio.common import exception
from rucio.common.checksum import GLOBALLY_SUPPORTED_CHECKSUMS, PREFERRED_CHECKSUM
from rucio.common.config import config_get
from rucio.rse.protocols import protocol

if TYPE_CHECKING:
    from types import ModuleType

    from rucio.common.types import LoggerFunction, RSESettingsDict


try:
    _xrootd_client: ModuleType | None = import_module('XRootD.client')
except Exception:
    _xrootd_client = None


def _client() -> ModuleType:
    """Return bindings which provide the application-level storage API."""
    required_api = (
        'AuthContext',
        'StorageClient',
        'XRootDAlreadyExistsError',
        'XRootDAuthorizationError',
        'XRootDChecksumError',
        'XRootDError',
        'XRootDNotFoundError',
        'XRootDTimeoutError',
    )
    if _xrootd_client is None or any(not hasattr(_xrootd_client, name) for name in required_api):
        raise exception.MissingDependency(
            "Missing dependency: a version of xrootd containing the high-level "
            "StorageClient API is required. Install the 'xrootd' extra for your "
            "Rucio distribution."
        )
    return _xrootd_client


class Default(protocol.RSEProtocol):
    """Access XRootD and WebDAV RSEs through the native Python bindings."""

    _DEFAULT_TIMEOUT = 300
    _ROOT_SCHEMES = frozenset(('root', 'roots', 'xroot', 'xroots'))
    _HTTP_SCHEMES = frozenset(('http', 'https', 'dav', 'davs'))

    def __init__(
            self,
            protocol_attr: dict[str, Any],
            rse_settings: RSESettingsDict,
            logger: LoggerFunction = logging.log,
    ) -> None:
        super().__init__(protocol_attr, rse_settings, logger=logger)
        self.scheme = self.attributes['scheme']
        self.hostname = self.attributes['hostname']
        self.port = str(self.attributes['port'])
        self.__client: Any | None = None
        self.__auth_context: Any | None = None
        self.__client_lock = threading.Lock()

    @property
    def _endpoint(self) -> str:
        return '{}://{}:{}'.format(self.scheme, self.hostname, self.port)

    def check_dependencies(self) -> None:
        """Validate the optional transport without affecting URL translation."""
        _client()

    def prepare_credentials(self) -> None:
        """Create the immutable, object-scoped authentication context."""
        self._storage_client()

    def _storage_client(self) -> Any:
        if self.__client is not None:
            return self.__client
        with self.__client_lock:
            if self.__client is None:
                xrootd = _client()
                self.__auth_context = self._make_auth_context(xrootd)
                self.__client = xrootd.StorageClient(
                    auth=self.__auth_context,
                    timeout=self._DEFAULT_TIMEOUT,
                )
        return self.__client

    def _make_auth_context(self, xrootd: ModuleType) -> Any:
        tls_options = self._tls_options()
        if self.auth_token:
            return xrootd.AuthContext.bearer(token=self.auth_token, **tls_options)

        proxy = self._valid_x509_proxy()
        if proxy is not None:
            return xrootd.AuthContext.x509(proxy=proxy, **tls_options)

        cert, key = self._valid_x509_cert_key()
        if cert is not None and key is not None:
            return xrootd.AuthContext.x509(cert=cert, key=key, **tls_options)

        if self.scheme in self._HTTP_SCHEMES:
            return xrootd.AuthContext.anonymous(**tls_options)

        # Explicitly select an unusable proxy instead of allowing the native
        # client to fall through to an unrelated ambient identity.
        return xrootd.AuthContext.x509(proxy=os.devnull, **tls_options)

    @staticmethod
    def _tls_options() -> dict[str, Any]:
        options: dict[str, Any] = {}
        ca_file = os.environ.get('X509_CERT_FILE') or os.environ.get('SSL_CERT_FILE')
        ca_dir = os.environ.get('X509_CERT_DIR') or os.environ.get('SSL_CERT_DIR')
        if ca_file:
            ca_file = os.path.expandvars(os.path.expanduser(ca_file))
            if os.path.isfile(ca_file):
                options['ca_file'] = ca_file
        if ca_dir:
            ca_dir = os.path.expandvars(os.path.expanduser(ca_dir))
            if os.path.isdir(ca_dir):
                options['ca_dir'] = ca_dir
        return options

    def _valid_x509_proxy(self) -> str | None:
        # Presence is significant: an explicitly empty or unusable credential
        # must fail closed instead of selecting a lower-priority identity.
        if 'RUCIO_CLIENT_PROXY' in os.environ:
            return self._existing_file(os.environ['RUCIO_CLIENT_PROXY'])
        if 'XrdSecGSIUSERPROXY' in os.environ:
            return self._existing_file(os.environ['XrdSecGSIUSERPROXY'])

        configured_proxy = self._configured_x509_proxy()
        if configured_proxy is not None:
            return self._existing_file(configured_proxy)

        if 'X509_USER_PROXY' in os.environ:
            return self._existing_file(os.environ['X509_USER_PROXY'])
        if any(variable in os.environ for variable in (
                'X509_USER_CERT', 'X509_USER_KEY',
                'XrdSecGSIUSERCERT', 'XrdSecGSIUSERKEY')):
            return None
        return self._existing_file(self._default_x509_proxy())

    def _valid_x509_cert_key(self) -> tuple[str | None, str | None]:
        if any(variable in os.environ for variable in (
                'RUCIO_CLIENT_PROXY', 'X509_USER_PROXY', 'XrdSecGSIUSERPROXY')):
            return None, None
        if self._configured_x509_proxy() is not None:
            return None, None
        cert_selector = (
            os.environ.get('XrdSecGSIUSERCERT')
            if 'XrdSecGSIUSERCERT' in os.environ
            else os.environ.get('X509_USER_CERT')
            if 'X509_USER_CERT' in os.environ
            else self._default_x509_cert()
        )
        key_selector = (
            os.environ.get('XrdSecGSIUSERKEY')
            if 'XrdSecGSIUSERKEY' in os.environ
            else os.environ.get('X509_USER_KEY')
            if 'X509_USER_KEY' in os.environ
            else self._default_x509_key()
        )
        cert = self._existing_file(cert_selector)
        key = self._existing_file(key_selector)
        if cert is None or key is None:
            return None, None
        return cert, key

    @staticmethod
    def _configured_x509_proxy() -> str | None:
        try:
            configured_proxy = config_get(
                'client', 'client_x509_proxy', default=None, raise_exception=False)
        except Exception:
            return None
        if configured_proxy in ('$X509_USER_PROXY', '${X509_USER_PROXY}'):
            return os.environ.get('X509_USER_PROXY')
        return configured_proxy

    @staticmethod
    def _default_x509_proxy() -> str | None:
        if hasattr(os, 'geteuid'):
            return '/tmp/x509up_u%d' % os.geteuid()
        return None

    @staticmethod
    def _default_x509_cert() -> str:
        return os.path.join(os.path.expanduser('~'), '.globus', 'usercert.pem')

    @staticmethod
    def _default_x509_key() -> str:
        return os.path.join(os.path.expanduser('~'), '.globus', 'userkey.pem')

    @staticmethod
    def _existing_file(path: str | None) -> str | None:
        if not path:
            return None
        expanded = os.path.expandvars(os.path.expanduser(path))
        if '$' in expanded or not os.path.isfile(expanded):
            return None
        return expanded

    def _as_url(self, path: str) -> str:
        parsed = urlsplit(str(path))
        if parsed.scheme and parsed.netloc:
            return str(path)
        return self.path2pfn(str(path))

    def _translate_error(
            self,
            error: Exception,
            *,
            source_not_found: bool = False,
            destination: bool = False,
    ) -> None:
        xrootd = _client()
        if isinstance(error, xrootd.XRootDNotFoundError) and source_not_found:
            raise exception.SourceNotFound(str(error)) from error
        if isinstance(error, xrootd.XRootDAuthorizationError):
            raise exception.RSEAccessDenied(str(error)) from error
        if isinstance(error, xrootd.XRootDChecksumError):
            raise exception.RSEChecksumUnavailable(str(error)) from error
        if destination and isinstance(error, xrootd.XRootDAlreadyExistsError):
            raise exception.DestinationNotAccessible(str(error)) from error
        raise exception.ServiceUnavailable(str(error)) from error

    def path2pfn(self, path: str) -> str:
        """Return a fully qualified PFN for ``path``."""
        self.logger(logging.DEBUG, 'xrootd.path2pfn: path: %s', path)
        parsed = urlsplit(str(path))
        if parsed.scheme and parsed.netloc:
            return str(path)
        path = str(path).lstrip('/')
        separator = '//' if self.scheme in self._ROOT_SCHEMES else '/'
        return '{}{}{}'.format(self._endpoint, separator, path)

    def pfn2path(self, pfn: str) -> str:
        """Return the remote path component of a PFN."""
        self.logger(logging.DEBUG, 'xrootd.pfn2path: pfn: %s', pfn)
        parsed = urlsplit(str(pfn))
        if parsed.scheme and parsed.netloc:
            return parsed.path
        return str(pfn)

    def connect(self) -> None:
        """Prepare the native client and its object-scoped credentials."""
        self.logger(
            logging.DEBUG, 'xrootd.connect: port: %s, hostname %s',
            self.port, self.hostname)
        try:
            self._storage_client()
        except exception.RucioException:
            raise
        except Exception as error:
            self._translate_error(error)

    def close(self) -> None:
        """Release credentials owned by this protocol instance."""
        with self.__client_lock:
            auth_context = self.__auth_context
            self.__client = None
            self.__auth_context = None
        if auth_context is not None:
            auth_context.close()

    def exists(self, pfn: str | None) -> bool:
        """Return whether ``pfn`` exists on the RSE."""
        self.logger(logging.DEBUG, 'xrootd.exists: pfn: %s', pfn)
        if pfn is None:
            return False
        try:
            return bool(self._storage_client().exists(self._as_url(pfn)))
        except exception.RucioException:
            raise
        except Exception as error:
            self._translate_error(error)
        return False

    def stat(self, path: str) -> dict[str, str]:
        """Return file size and, when enabled, a supported checksum."""
        self.logger(logging.DEBUG, 'xrootd.stat: path: %s', path)
        url = self._as_url(path)
        try:
            info = self._storage_client().stat(url)
        except exception.RucioException:
            raise
        except Exception as error:
            self._translate_error(error, source_not_found=True)

        size = info['size'] if isinstance(info, dict) else info.size
        result = {'filesize': str(size)}
        if not self.rse.get('verify_checksum', True):
            return result

        errors = []
        algorithms = [PREFERRED_CHECKSUM]
        algorithms.extend(
            algorithm for algorithm in GLOBALLY_SUPPORTED_CHECKSUMS
            if algorithm != PREFERRED_CHECKSUM)
        for algorithm in algorithms:
            try:
                returned_algorithm, value = self._storage_client().checksum(
                    url, algorithm=algorithm)
            except Exception as error:
                xrootd = _client()
                if isinstance(error, xrootd.XRootDNotFoundError):
                    self._translate_error(error, source_not_found=True)
                errors.append('{}: {}'.format(algorithm, error))
                continue
            returned_algorithm = returned_algorithm.lower()
            if returned_algorithm in GLOBALLY_SUPPORTED_CHECKSUMS:
                result[returned_algorithm] = value
                return result
            errors.append('{}: endpoint returned {}'.format(
                algorithm, returned_algorithm))

        raise exception.RSEChecksumUnavailable('\n'.join(errors))

    def get(self, pfn: str, dest: str, transfer_timeout: int | str | None = None) -> None:
        """Download ``pfn`` to a local destination."""
        self.logger(logging.DEBUG, 'xrootd.get: pfn: %s', pfn)
        try:
            self._storage_client().get(
                self._as_url(pfn), dest,
                timeout=int(transfer_timeout) if transfer_timeout is not None else None,
                force=True)
        except exception.RucioException:
            raise
        except Exception as error:
            self._translate_error(error, source_not_found=True, destination=True)

    def put(
            self,
            filename: str,
            target: str,
            source_dir: str | None,
            transfer_timeout: int | str | None = None,
    ) -> None:
        """Upload one local file, creating missing remote parents."""
        source = os.path.join(source_dir or '.', filename)
        self.logger(
            logging.DEBUG, 'xrootd.put: source: %s target: %s', source, target)
        if not os.path.exists(source):
            raise exception.SourceNotFound(source)
        try:
            self._storage_client().put(
                os.path.abspath(source), self._as_url(target),
                timeout=int(transfer_timeout) if transfer_timeout is not None else None,
                force=True, create_parents=True)
        except exception.RucioException:
            raise
        except Exception as error:
            self._translate_error(error, destination=True)

    def delete(self, pfn: str) -> None:
        """Delete one file or WebDAV collection."""
        self.logger(logging.DEBUG, 'xrootd.delete: pfn: %s', pfn)
        try:
            self._storage_client().delete(self._as_url(pfn))
        except exception.RucioException:
            raise
        except Exception as error:
            self._translate_error(error, source_not_found=True)

    def rename(self, pfn: str, new_pfn: str) -> None:
        """Atomically move a resource and create destination parents."""
        self.logger(
            logging.DEBUG, 'xrootd.rename: pfn: %s new_pfn: %s', pfn, new_pfn)
        try:
            self._storage_client().move(
                self._as_url(pfn), self._as_url(new_pfn), create_parents=True)
        except exception.RucioException:
            raise
        except Exception as error:
            self._translate_error(error, source_not_found=True, destination=True)

    def get_space_usage(self) -> tuple[int, int]:
        """Return total and unused bytes for the configured namespace."""
        endpoint_basepath = self.path2pfn(self.attributes['prefix'])
        self.logger(
            logging.DEBUG, 'xrootd.get_space_usage: endpoint: %s',
            endpoint_basepath)
        try:
            usage = self._storage_client().space(endpoint_basepath)
            return int(usage['total']), int(usage['free'])
        except exception.RucioException:
            raise
        except Exception as error:
            self._translate_error(error)
        raise exception.ServiceUnavailable('Space usage could not be retrieved')
