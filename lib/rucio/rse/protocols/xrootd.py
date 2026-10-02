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
        'STORAGE_CLIENT_API_VERSION',
        'StorageClient',
        'XRootDAlreadyExistsError',
        'XRootDAuthorizationError',
        'XRootDChecksumError',
        'XRootDError',
        'XRootDNotFoundError',
        'XRootDTimeoutError',
    )
    if (
            _xrootd_client is None
            or any(not hasattr(_xrootd_client, name) for name in required_api)
            or _xrootd_client.STORAGE_CLIENT_API_VERSION < 2
    ):
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
                self.__client = xrootd.StorageClient.from_environment(
                    timeout=self._DEFAULT_TIMEOUT,
                    token=self.auth_token,
                    proxy=self._auth_proxy_override(),
                    fallback='anonymous' if self.scheme in self._HTTP_SCHEMES else 'none',
                    use_bearer_environment=False,
                )
        return self.__client

    def _auth_proxy_override(self) -> str | None:
        for variable in ('RUCIO_CLIENT_PROXY', 'XrdSecGSIUSERPROXY'):
            if variable in os.environ:
                return os.environ[variable]
        return self._configured_x509_proxy()

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
        """Prepare credentials and verify bounded access to the RSE prefix."""
        self.logger(
            logging.DEBUG, 'xrootd.connect: port: %s, hostname %s',
            self.port, self.hostname)
        try:
            self._storage_client().probe(
                self.path2pfn(self.attributes['prefix']), timeout=10)
        except exception.RucioException:
            raise
        except Exception as error:
            self._translate_error(error)

    def close(self) -> None:
        """Release credentials owned by this protocol instance."""
        with self.__client_lock:
            client = self.__client
            self.__client = None
        if client is not None:
            client.close()

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
        verify_checksum = self.rse.get('verify_checksum', True)
        algorithms = [PREFERRED_CHECKSUM]
        algorithms.extend(
            algorithm for algorithm in GLOBALLY_SUPPORTED_CHECKSUMS
            if algorithm != PREFERRED_CHECKSUM)
        try:
            info = self._storage_client().info(
                url,
                checksum_algorithms=algorithms if verify_checksum else (),
                require_checksum=verify_checksum,
            )
        except exception.RucioException:
            raise
        except Exception as error:
            self._translate_error(error, source_not_found=True)

        result = {'filesize': str(info.size)}
        if info.checksum is not None:
            result[info.checksum.algorithm] = info.checksum.value
        return result

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
