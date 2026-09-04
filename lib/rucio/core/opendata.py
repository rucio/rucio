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

import hashlib
import json
import logging
import time
from re import match, search
from typing import TYPE_CHECKING, Any, Optional, Union, cast
from urllib.parse import urlencode, urlparse

import requests
from dogpile.cache.api import NoValue
from sqlalchemy import and_, delete, func, insert, update
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.sql.expression import bindparam, select

from rucio.common import exception
from rucio.common.cache import MemcacheRegion
from rucio.common.config import config_get, config_get_bool, config_get_int
from rucio.common.constants import DEFAULT_VO
from rucio.common.exception import OpenDataError, OpenDataInvalidStateUpdate
from rucio.common.types import InternalAccount
from rucio.core.did import list_files
from rucio.core.monitor import MetricManager
from rucio.core.replica import list_replicas
from rucio.core.rule import add_rule
from rucio.db.sqla import models
from rucio.db.sqla.constants import DIDType, OpenDataDIDState

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from sqlalchemy.orm import Session

    from rucio.common.constants import OPENDATA_DID_STATE_LITERAL
    from rucio.common.types import InternalScope

logger = logging.getLogger(__name__)

METRICS = MetricManager(module=__name__)
REGION = MemcacheRegion(expiration_time=7200)
EOS_PROBE_REGION = MemcacheRegion(expiration_time=86400)
EOS_PROBE_NEGATIVE_REGION = MemcacheRegion(expiration_time=300)

# Default lifetime of the EOS download tokens. It must be longer than the
# expiration time of the file listing cache (REGION above) so that download
# URLs served from the cache always carry a still-valid token.
DEFAULT_EOS_TOKEN_LIFETIME_SECONDS = 4 * 3600
OPENDATA_DID_FILES_CACHE_VERSION = 2


def is_valid_opendata_did_state(state: str) -> bool:
    """
    Checks if the provided state string corresponds to a valid Opendata DID state.

    Parameters:
        state: The state string to validate (e.g., 'draft', 'public', 'suspended').

    Returns:
        True if the state is valid, False otherwise.
    """

    try:
        _ = OpenDataDIDState[state.upper()]
        return True
    except KeyError:
        return False


def validate_opendata_did_state(state: str) -> "OPENDATA_DID_STATE_LITERAL":
    """
    Validate the provided Opendata DID state string and return it in a consistent format.
    If the state is invalid, raise an OpenDataError with a message listing valid states.

    Parameters:
        state: The state string to validate (e.g., 'draft', 'public', 'suspended').

    Returns:
        The validated state string in lowercase.
    """

    state = state.lower()
    if not is_valid_opendata_did_state(state):
        raise OpenDataError(
            f"Invalid state '{state}'. Valid opendata states are: {', '.join([s.name.lower() for s in OpenDataDIDState])}")

    return cast("OPENDATA_DID_STATE_LITERAL", state)


def opendata_state_str_to_enum(state: "OPENDATA_DID_STATE_LITERAL") -> OpenDataDIDState:
    """
    Convert a string representation of an Opendata DID state to the corresponding OpenDataDIDState enum.
    If the state is invalid, raise an OpenDataError with a message listing valid states.

    Parameters:
        state: The state string to convert (e.g., 'draft', 'public', 'suspended').

    Returns:
        The corresponding OpenDataDIDState enum value.
    """

    return OpenDataDIDState[validate_opendata_did_state(state).upper()]


def _check_opendata_did_exists(
        *,
        scope: "InternalScope",
        name: str,
        session: "Session",
) -> bool:
    """
    Check if an Opendata DID does exist in the database.
    """

    query = select(models.OpenDataDid).where(
        and_(
            models.OpenDataDid.scope == scope,
            models.OpenDataDid.name == name
        )
    )
    result = session.execute(query).scalar()
    return result is not None


def list_opendata_dids(
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        state: Optional[OpenDataDIDState] = None,
        session: "Session",
) -> dict[str, Any]:
    """
    List Opendata DIDs with optional filtering by state, limit, and offset.

    Parameters:
        limit: Maximum number of DIDs to return.
        offset: Offset for pagination.
        state: Filter by Opendata DID state.
        session: SQLAlchemy session to use for the query.

    Returns:
        A dictionary containing the total count, offset, and a list of DIDs.
    """

    count_query = select(func.count()).select_from(models.OpenDataDid)
    query = select(
        models.OpenDataDid.scope,
        models.OpenDataDid.name,
        models.OpenDataDid.state,
        models.OpenDataDid.created_at,
        models.OpenDataDid.updated_at,
    ).order_by(
        models.OpenDataDid.updated_at
    )

    if state is not None:
        count_query = count_query.where(models.OpenDataDid.state == state)
        query = query.where(models.OpenDataDid.state == state)

    total = session.execute(count_query).scalar_one()

    if limit is not None:
        query = query.limit(limit)

    if offset is not None:
        query = query.offset(offset)

    dids = [{"scope": scope, "name": name, "state": state, "created_at": created_at, "updated_at": updated_at} for
            scope, name, state, created_at, updated_at in session.execute(query)]

    response = {
        "total": total,
        "offset": offset if offset is not None else 0,
        "dids": dids,
    }

    return response


def get_opendata_meta(
        *,
        scope: "InternalScope",
        name: str,
        session: "Session",
) -> dict:
    """
    Retrieve the metadata associated with an Opendata DID.

    Parameters:
        scope: The scope of the Opendata DID.
        name: The name of the Opendata DID.
        session: SQLAlchemy session to use for the query.

    Returns:
        A dictionary containing the metadata for the specified Opendata DID.
    """

    query = select(
        models.OpenDataMeta.meta,
    ).where(
        and_(
            models.OpenDataMeta.name == name,
            models.OpenDataMeta.scope == scope,
        )
    )

    result = session.execute(query).mappings().fetchone()

    if not result:
        return {}
    else:
        return result["meta"]


def get_opendata_doi(
        *,
        scope: "InternalScope",
        name: str,
        session: "Session",
) -> Optional[str]:
    """
    Retrieve the DOI (Digital Object Identifier) associated with an Opendata DID.

    Parameters:
        scope: The scope of the Opendata DID.
        name: The name of the Opendata DID.
        session: SQLAlchemy session to use for the query.

    Returns:
        The DOI associated with the Opendata DID, or None if not found.
    """

    query = select(
        models.OpenDataDOI.doi,
    ).where(
        and_(
            models.OpenDataDOI.name == name,
            models.OpenDataDOI.scope == scope,
        )
    )

    result = session.execute(query).mappings().fetchone()

    if not result:
        return None
    else:
        return result["doi"]


def get_opendata_record_id(
        *,
        scope: "InternalScope",
        name: str,
        session: "Session",
) -> Optional[int]:
    """
    Retrieve the record ID associated with an Opendata DID.

    Parameters:
        scope: The scope of the Opendata DID.
        name: The name of the Opendata DID.
        session: SQLAlchemy session to use for the query.

    Returns:
        The Record ID associated with the Opendata DID, or None if not found.
    """

    query = select(
        models.OpenDataRecord.record_id,
    ).where(
        and_(
            models.OpenDataRecord.name == name,
            models.OpenDataRecord.scope == scope,
        )
    )

    result = session.execute(query).mappings().fetchone()

    if not result:
        return None
    else:
        return int(result["record_id"])


def _raise_on_temporary_http_error(
    response: requests.Response,
    *,
    operation: str,
    host: str,
) -> None:
    """
    Raise an exception when an HTTP response represents a temporary failure.

    HTTP 408 (Request Timeout), 429 (Too Many Requests), and all 5xx responses
    are considered temporary failures and are reported as
    ``ResourceTemporaryUnavailable``.

    Args:
        response: HTTP response to inspect.
        operation: Description of the operation being performed.
        host: Host against which the operation was performed.

    Raises:
        ResourceTemporaryUnavailable: If the response status code indicates
            a temporary HTTP failure.
    """
    if response.status_code in {408, 429} or response.status_code >= 500:
        raise exception.ResourceTemporaryUnavailable(
            f"{operation} is temporarily unavailable for {host}."
        )


def _is_eos_host(host: str) -> bool:
    """
    Probe ``host`` to determine whether it exposes the EOS REST gateway.

    Calls the documented ``version_cmd`` endpoint of the EOS REST gateway.
    A genuine EOS instance returns its standard command envelope
    ``{"retc": "0", "stdOut": "...", "stdErr": ""}``, where ``stdOut``
    contains an ``EOS_SERVER_VERSION=`` line.

    Positive and confirmed negative results are cached. Transient transport,
    server, or response-decoding failures are propagated as
    ``ResourceTemporaryUnavailable`` and are not negative-cached.

    Args:
        host: Host authority to probe, including the port if present
            (e.g. ``eospilot.cern.ch:8444``).

    Returns:
        True if the host is confirmed to expose an EOS REST gateway,
        False if it is confirmed not to expose one.

    Raises:
        ResourceTemporaryUnavailable: If the probe cannot be completed due
            to a temporary transport or server failure, an invalid response,
            or a failed EOS probe command.
    """
    cached = EOS_PROBE_REGION.get(host)
    if not isinstance(cached, NoValue):
        return bool(cached)

    cached_neg = EOS_PROBE_NEGATIVE_REGION.get(host)
    if not isinstance(cached_neg, NoValue):
        return bool(cached_neg)

    ca_bundle = config_get(
        "opendata",
        "eos_ca_bundle",
        raise_exception=False,
        default="/etc/grid-security/ca.pem",
    )
    timeout = config_get_int(
        "opendata",
        "eos_probe_timeout",
        raise_exception=False,
        default=3,
    )

    # The EOS REST gateway is always exposed over HTTPS. This is independent
    # from the replica PFN scheme.
    url = f"https://{host}/v1/eos/rest/gateway/version_cmd"

    try:
        response = requests.post(
            url,
            json={},
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            verify=ca_bundle,
            timeout=timeout,
            allow_redirects=False,
        )
    except (requests.exceptions.RequestException, OSError) as error:
        logger.warning(
            "Failed to probe host %s for EOS REST gateway support: %s",
            host,
            error,
        )
        raise exception.ResourceTemporaryUnavailable(
            f"Unable to probe {host} for EOS REST gateway support."
        ) from error

    _raise_on_temporary_http_error(
        response,
        operation="REST gateway probe",
        host=host,
    )

    if response.status_code != 200:
        logger.info(
            "Host %s did not respond as an EOS REST gateway "
            "(status=%s).",
            host,
            response.status_code,
        )
        EOS_PROBE_NEGATIVE_REGION.set(host, False)
        return False

    try:
        payload = response.json()
    except ValueError as error:
        logger.warning(
            "Failed to decode REST gateway probe response from %s: %s",
            host,
            error,
        )
        raise exception.ResourceTemporaryUnavailable(
            f"REST gateway probe returned an invalid response for {host}."
        ) from error

    if not isinstance(payload, dict):
        logger.warning(
            "REST gateway probe for %s returned an unexpected response type.",
            host,
        )
        raise exception.ResourceTemporaryUnavailable(
            f"REST gateway probe returned an invalid response for {host}."
        )

    if "retc" in payload and str(payload["retc"]) != "0":
        logger.warning(
            "EOS probe command failed for %s: retc=%s, stderr=%s",
            host,
            payload.get("retc"),
            payload.get("stdErr", ""),
        )
        raise exception.ResourceTemporaryUnavailable(
            f"REST gateway probe command failed for {host}."
        )

    std_out = payload.get("stdOut", "")

    is_eos = (
        str(payload.get("retc")) == "0"
        and isinstance(std_out, str)
        and "EOS_SERVER_VERSION=" in std_out
    )

    if is_eos:
        EOS_PROBE_REGION.set(host, True)
    else:
        EOS_PROBE_NEGATIVE_REGION.set(host, False)

    return is_eos


def _eos_grpc_gateway_token_command(
    eos_host: str,
    filename: str,
    lifetime_seconds: int,
) -> str:
    """
    Send a POST request to the EOS GRPC REST gateway to generate an access token.

    The EOS REST gateway is always contacted over HTTPS, independently of the
    replica PFN scheme.

    Args:
        eos_host: EOS REST gateway authority, including the port if present
            (e.g. ``eospilot.cern.ch:8444``).
        filename: Path the token should grant read access to.
        lifetime_seconds: Number of seconds the token should remain valid.

    Returns:
        The raw token string when token generation succeeds.

    Raises:
        ResourceTemporaryUnavailable: If the EOS token service cannot be
            contacted, returns a temporary HTTP failure, or returns an invalid
            response.
        OpenDataError: If the EOS token service returns a non-temporary HTTP
            error, rejects the token-generation command, or returns unexpected
            token output.
    """
    expires_at = int(time.time()) + lifetime_seconds

    eos_host = eos_host.rstrip("/")
    url = f"https://{eos_host}/v1/eos/rest/gateway/token_cmd"

    payload = {
        "path": filename,
        "expires": str(expires_at),
        "permission": "r",
    }

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    cert = key = config_get(
        "opendata",
        "eos_proxy_path",
        raise_exception=False,
        default="/opt/proxy/x509up",
    )

    ca_bundle = config_get(
        "opendata",
        "eos_ca_bundle",
        raise_exception=False,
        default="/etc/grid-security/ca.pem",
    )

    timeout = config_get_int(
        "opendata",
        "eos_token_request_timeout",
        raise_exception=False,
        default=5,
    )

    try:
        response = requests.post(
            url,
            json=payload,
            headers=headers,
            cert=(cert, key),
            verify=ca_bundle,
            timeout=timeout,
            allow_redirects=False,
        )
    except (requests.exceptions.RequestException, OSError) as error:
        logger.warning(
            "Failed to request EOS token for '%s' on %s: %s",
            filename,
            eos_host,
            error,
        )
        raise exception.ResourceTemporaryUnavailable(
            f"EOS token request could not be completed for {eos_host}."
        ) from error

    _raise_on_temporary_http_error(
        response,
        operation="EOS token service",
        host=eos_host,
    )

    if response.status_code != 200:
        logger.warning(
            "EOS token service returned HTTP %s for '%s' on %s.",
            response.status_code,
            filename,
            eos_host,
        )
        raise exception.OpenDataError(
            f"EOS token generation failed for {eos_host}: "
            f"HTTP {response.status_code}."
        )

    try:
        response_data = response.json()
    except ValueError as error:
        logger.warning(
            "Failed to decode EOS token response for '%s' on %s: %s",
            filename,
            eos_host,
            error,
        )
        raise exception.ResourceTemporaryUnavailable(
            f"EOS token service returned an invalid response for {eos_host}."
        ) from error

    if not isinstance(response_data, dict):
        logger.warning(
            "EOS token service returned an unexpected response type "
            "for '%s' on %s.",
            filename,
            eos_host,
        )
        raise exception.ResourceTemporaryUnavailable(
            f"EOS token service returned an invalid response for {eos_host}."
        )

    try:
        retc = int(response_data["retc"])
    except (KeyError, TypeError, ValueError) as error:
        logger.warning(
            "EOS token service returned an invalid return code "
            "for '%s' on %s.",
            filename,
            eos_host,
        )
        raise exception.ResourceTemporaryUnavailable(
            f"EOS token service returned an invalid response for {eos_host}."
        ) from error

    if retc != 0:
        logger.warning(
            "EOS token command failed for '%s' on %s: retc=%s, stderr=%s",
            filename,
            eos_host,
            retc,
            response_data.get("stdErr", ""),
        )
        raise OpenDataError(
            f"EOS token generation failed for {eos_host}: retc={retc}."
        )

    token_output = response_data.get("stdOut", "")

    if not isinstance(token_output, str) or not token_output.strip():
        logger.warning(
            "EOS token service returned an empty token for '%s' on %s.",
            filename,
            eos_host,
        )
        raise exception.ResourceTemporaryUnavailable(
            f"EOS token generation failed for {eos_host}."
        )

    token_lines = [
        line.strip()
        for line in token_output.splitlines()
        if line.strip()
    ]

    token = token_lines[0] if len(token_lines) == 1 else ""

    if (
        not token.startswith("zteos64:")
        or len(token) <= len("zteos64:")
    ):
        logger.warning(
            "EOS token service returned unexpected token output "
            "for '%s' on %s.",
            filename,
            eos_host,
        )
        raise OpenDataError(
            f"EOS token generation returned unexpected output for {eos_host}."
        )

    return token


def _format_url_authority(host: str, port: Optional[int]) -> str:
    """
    Format a hostname and optional port as a valid URL authority.

    IPv6 hostnames returned by urlparse().hostname do not contain the
    brackets required when used inside a URL.
    """
    if ":" in host:
        host = f"[{host}]"

    if port is not None:
        return f"{host}:{port}"

    return host


def _append_authz_query_parameter(uri: str, token: str) -> str:
    """
    Append an authz parameter without reparsing or rebuilding the existing query.

    The original query string is preserved verbatim so repeated parameters,
    valueless flags, ordering, and existing percent-encoding are not changed.
    """
    parsed = urlparse(uri)
    authz_query = urlencode({"authz": token})

    if parsed.query:
        query = f"{parsed.query}&{authz_query}"
    else:
        query = authz_query

    return parsed._replace(query=query).geturl()


def _generate_download_urls(uris: list[str]) -> list[str]:
    """
    Build tokenized download URLs for the given replica URIs.

    Only valid HTTP(S) or DAV(S) URIs whose host exposes an EOS REST gateway are
    considered. For each eligible URI, a read-only EOS token scoped to the
    file path is requested and appended as an ``authz`` query parameter.

    Malformed URIs, unsupported schemes, and confirmed non-EOS hosts are
    skipped. Temporary EOS failures are tolerated while other independent
    replicas are tried and are propagated if no download URL can be generated.

    Args:
        uris: Replica URIs to process.

    Returns:
        The successfully generated tokenized download URLs. The list may be
        empty if none of the provided URIs can be used.

    Raises:
        ResourceTemporaryUnavailable: If no download URL can be generated
            and at least one EOS backend operation failed temporarily.
        OpenDataError: If no download URL can be generated and at least one
            EOS backend operation failed permanently.
    """
    lifetime = config_get_int("opendata", "eos_token_lifetime", raise_exception=False,
                              default=DEFAULT_EOS_TOKEN_LIFETIME_SECONDS)

    download_urls = []

    # The token lifetime and permission are constant within this invocation.
    # Therefore, authority and normalized path identify the authorization scope.
    token_cache: dict[tuple[str, str], Optional[str]] = {}

    temporary_error: Optional[
        exception.ResourceTemporaryUnavailable
    ] = None
    permanent_error: Optional[OpenDataError] = None

    for uri in uris:
        try:
            parsed = urlparse(uri)
            host = parsed.hostname
            port = parsed.port
        except ValueError:
            logger.warning("Skipping malformed replica URI '%s'.", uri)
            continue

        if parsed.scheme not in {"http", "https", "dav", "davs"} or not host:
            logger.debug(
                "Skipping replica URI '%s': only HTTP(S) and DAV(S) replicas are supported.",
                uri,
            )
            continue

        eos_authority = _format_url_authority(host, port)

        path = parsed.path

        # PFNs such as https://host:8444//eos/path contain a double
        # slash between the authority and EOS path.
        if path.startswith("//"):
            path = path[1:]

        token_scope = (eos_authority, path)

        try:
            if token_scope not in token_cache:
                if not _is_eos_host(eos_authority):
                    token_cache[token_scope] = None
                else:
                    token_cache[token_scope] = (
                        _eos_grpc_gateway_token_command(
                            eos_host=eos_authority,
                            filename=path,
                            lifetime_seconds=lifetime,
                        )
                    )
        except exception.ResourceTemporaryUnavailable as error:
            # Do not immediately fail: another independent replica may work.
            token_cache[token_scope] = None

            if temporary_error is None:
                temporary_error = error
            continue
        except OpenDataError as error:
            # A non-retryable failure for one replica must not prevent
            # trying other independent replicas.
            token_cache[token_scope] = None
            if permanent_error is None:
                permanent_error = error
            continue

        token = token_cache[token_scope]

        if not token:
            continue

        download_urls.append(
            _append_authz_query_parameter(uri, token)
        )

    # If at least one independent replica worked, return it. Otherwise,
    # preserve the temporary nature of any EOS backend outage.
    if not download_urls:
        if temporary_error is not None:
            raise temporary_error

        if permanent_error is not None:
            raise permanent_error

    return download_urls


def _extract_disk_uris(
    replicas: "Iterable[dict[str, Any]]",
) -> list[str]:
    """
    Extract DISK replica URIs from ``list_replicas`` results.

    Args:
        replicas: Replica entries returned by ``list_replicas``.

    Returns:
        The PFN URIs whose replica type is ``DISK``.
    """
    uris = []

    for replica in replicas:
        for uri, data in replica["pfns"].items():
            if data["type"] != "DISK":
                continue
            uris.append(uri)

    return uris


def _index_disk_uris_by_did(
    replicas: "Iterable[dict[str, Any]]",
) -> dict[tuple["InternalScope", str], list[str]]:
    """
    Index DISK PFNs by DID.
    """
    result: dict[tuple["InternalScope", str], list[str]] = {}

    for replica in replicas:
        key = (replica["scope"], replica["name"])
        result.setdefault(key, []).extend(
            _extract_disk_uris([replica])
        )

    return result


def _make_opendata_did_files_cache_key(
    scope: "InternalScope",
    name: str,
    include_download_urls: bool,
) -> str:
    """
    Build a bounded and unambiguous cache key for Open Data DID file listings.

    The complete internal scope is included so cache entries remain isolated
    between VOs. The structured identity is hashed to avoid ambiguous field
    concatenation and Memcached's 250-byte key limit.
    """
    cache_identity = json.dumps(
        {
            "scope": scope.internal,
            "name": name,
            "include_download_urls": include_download_urls,
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    digest = hashlib.sha256(
        cache_identity.encode("utf-8")
    ).hexdigest()

    return (
        f"opendata_did_files_v"
        f"{OPENDATA_DID_FILES_CACHE_VERSION}_{digest}"
    )


def get_opendata_did_files(
        *,
        scope: "InternalScope",
        name: str,
        use_cache: bool = False,
        include_download_urls: bool = False,
        session: "Session",
) -> dict[str, Any]:
    """
    Retrieve the files and replicas associated with an OpenData DID.

    When ``include_download_urls`` is enabled, HTTP(S) and DAV(S) replicas are retrieved
    separately and used to generate tokenized EOS download URLs.

    Parameters:
        scope: The scope of the OpenData DID.
        name: The name of the OpenData DID.
        use_cache: If True, use caching to store/retrieve the result. Defaults to False.
        include_download_urls: If True, include tokenized download URLs for the files.
        session: SQLAlchemy session to use for the query.

    Returns:
        A dictionary containing the files and their replica URIs, together
        with cache-hit information and elapsed request time.

    Raises:
        OpenDataDataIdentifierNotFound: If the OpenData DID does not exist.
        ReplicaNotFound: If download URLs are requested but no suitable
            replica is available.
        OpenDataError: If download URL generation fails due to a
            non-temporary EOS backend error.
        ResourceTemporaryUnavailable: If download URL generation cannot
            complete because an EOS backend operation failed temporarily.
    """

    time_start = time.perf_counter()

    # Build a cache key which uniquely identifies the DID, VO, and
    # download URL inclusion mode.
    cache_key = _make_opendata_did_files_cache_key(
        scope,
        name,
        include_download_urls,
    )

    if use_cache:
        file_list = REGION.get(cache_key)

        if not isinstance(file_list, NoValue):
            result = {
                "files": file_list,
                "cache_hit": True,
                "time_elapsed_millis": (time.perf_counter() - time_start) * 1000,
            }
            return result

    query = select(
        models.OpenDataDid.scope,
        models.OpenDataDid.name,
    ).where(
        and_(
            models.OpenDataDid.scope == scope,
            models.OpenDataDid.name == name,
        )
    )

    query_result = session.execute(query).mappings().fetchone()

    if not query_result:
        raise exception.OpenDataDataIdentifierNotFound(f"OpenData DID {scope}:{name} not found.")

    files = list_files(scope=scope, name=name)
    file_list = [
        {
            "scope": file["scope"],
            "name": file["name"],
            "bytes": file["bytes"],
            "adler32": file["adler32"],
        }
        for file in files
    ]

    rse_expression = config_get("opendata", "rse_expression", raise_exception=True)

    dids = [
        {
            "scope": file["scope"],
            "name": file["name"],
        }
        for file in file_list
    ]

    regular_uris_by_did: dict[tuple["InternalScope", str], list[str]] = {}
    download_uris_by_did: dict[tuple["InternalScope", str], list[str]] = {}

    if dids:
        regular_uris_by_did = _index_disk_uris_by_did(
            list_replicas(
                dids=dids,
                rse_expression=rse_expression,
                session=session,
            )
        )

        if include_download_urls:
            download_uris_by_did = _index_disk_uris_by_did(
                list_replicas(
                    dids=dids,
                    rse_expression=rse_expression,
                    schemes=["http", "https", "dav", "davs"],
                    resolve_archives=False,
                    session=session,
                )
            )

    if include_download_urls:
        for file in file_list:
            did_key = (file["scope"], file["name"])
            download_uris = download_uris_by_did.get(did_key, [])

            if not download_uris:
                logger.error(
                    "No HTTP(S) or DAV(S) DISK replica URI available "
                    "for OpenData file %s:%s.",
                    file["scope"],
                    file["name"],
                )

                raise exception.ReplicaNotFound(
                    f"No HTTP(S) or DAV(S) DISK replica URI available "
                    f"for OpenData file {file['scope']}:{file['name']}."
                )

    for file in file_list:
        did_key = (file["scope"], file["name"])

        # Missing regular replicas are represented by an empty URI list.
        # A suitable replica is required only when download URLs are requested.
        uris = regular_uris_by_did.get(did_key, [])
        file["uris"] = uris

        if not include_download_urls:
            continue

        download_uris = download_uris_by_did[did_key]
        download_urls = _generate_download_urls(download_uris)

        if not download_urls:
            logger.error(
                "Failed to generate download URL for OpenData file %s:%s.",
                file["scope"],
                file["name"],
            )

            raise exception.ReplicaNotFound(
                f"No suitable EOS download replica available "
                f"for OpenData file {file['scope']}:{file['name']}."
            )

        file["download_urls"] = download_urls

    # Now that the file_list is fully built (with or without download URLs), cache it
    if use_cache:
        REGION.set(cache_key, file_list)

    result = {
        "files": file_list,
        "cache_hit": False,
        "time_elapsed_millis": (time.perf_counter() - time_start) * 1000,
    }

    return result


def get_opendata_did(
        *,
        scope: "InternalScope",
        name: str,
        state: Optional[OpenDataDIDState] = None,
        include_files: bool = True,
        include_metadata: bool = False,
        include_doi: bool = True,
        include_rule: bool = True,
        include_record_id: bool = True,
        include_download_urls: bool = False,
        session: "Session",
) -> dict[str, Any]:
    """
    Retrieve information about an Opendata DID (Data Identifier).

    Parameters:
        scope: The scope under which the DID is registered.
        name: The name of the DID.
        state: Filter by Opendata DID state.
        include_files: If True, include a list of associated files. Defaults to True.
        include_metadata: If True, include extended metadata. Defaults to False.
        include_doi: If True, include DOI (Digital Object Identifier) information. Defaults to True.
        include_rule: If True, include the Opendata replication rule. Defaults to True.
        include_record_id: If True, include the record ID of the DID. Defaults to True.
        include_download_urls: If True, include download URLs for the files. Defaults to False.
        session: SQLAlchemy session to use for the query.

    Returns:
        A dictionary containing info about the specified DID which include "scope", "name", "state", "meta" (if requested), etc.
    Raises:
        OpenDataDataIdentifierNotFound: If the OpenData DID does not exist.
        InvalidRequest: If download URLs are requested without including files.
        ReplicaNotFound: If download URLs are requested but no suitable
            replica is available.
        OpenDataError: If download URL generation fails due to a
            non-temporary EOS backend error.
        ResourceTemporaryUnavailable: If download URL generation cannot
            complete because an EOS backend operation failed temporarily.
    """

    if include_download_urls and not include_files:
        raise exception.InvalidRequest(
            "Download URLs require files to be included."
        )

    query = select(
        models.OpenDataDid.scope,
        models.OpenDataDid.name,
        models.OpenDataDid.state,
        models.OpenDataDid.created_at,
        models.OpenDataDid.updated_at,
    ).where(
        and_(
            models.OpenDataDid.scope == scope,
            models.OpenDataDid.name == name,
        )
    )

    if state is not None:
        query = query.where(models.OpenDataDid.state == state)

    result = session.execute(query).mappings().fetchone()

    if not result:
        raise exception.OpenDataDataIdentifierNotFound(f"OpenData DID {scope}:{name} not found.")

    result = dict(result)

    if include_doi:
        result["doi"] = get_opendata_doi(scope=scope, name=name, session=session)
    if include_record_id:
        result["record_id"] = get_opendata_record_id(scope=scope, name=name, session=session)
    if include_metadata:
        result["meta"] = get_opendata_meta(scope=scope, name=name, session=session)
    if include_rule:
        result["rule"] = _fetch_opendata_rule(scope=scope, name=name, session=session)
    if include_files:
        opendata_files = get_opendata_did_files(scope=scope, name=name, use_cache=True,
                                                include_download_urls=include_download_urls, session=session)
        result["files"] = opendata_files["files"]

        bytes_sum = sum(file["bytes"] for file in result["files"])
        extensions = set()
        replicas_missing = 0
        for file in result["files"]:
            if "uris" not in file or not file["uris"]:
                replicas_missing += 1
                continue
            for replica in file["uris"]:
                filename = replica.split("/")[-1]
                if "." in filename:
                    extensions.add(filename.split(".")[-1])

        result["files_summary"] = {
            "length": len(result["files"]),
            "bytes": bytes_sum,
            "extensions": list(extensions),
            "replicas_missing": replicas_missing,
            "request_cache_hit": opendata_files["cache_hit"],
            "request_time_elapsed_millis": opendata_files["time_elapsed_millis"],
        }

    return result


def add_opendata_did(
        *,
        scope: "InternalScope",
        name: str,
        session: "Session",
) -> None:
    """
    Add an existing DID to the Opendata catalog.

    Parameters:
        scope: The scope under which the DID is registered.
        name: The name of the DID.
        session: SQLAlchemy session to use for the operation.

    Raises:
        DataIdentifierNotFound: If the DID does not exist.
        OpenDataDataIdentifierAlreadyExists: If the Opendata DID already exists in the catalog.
    """

    try:
        return add_opendata_dids([{"scope": scope, "name": name}], session=session)
    except exception.DataIdentifierNotFound:
        raise exception.DataIdentifierNotFound(f"OpenData DID {scope}:{name} not found.")
    except exception.OpenDataDataIdentifierAlreadyExists:
        raise exception.OpenDataDataIdentifierAlreadyExists(f"OpenData DID {scope}:{name} already exists.")


def add_opendata_dids(
        dids: "Sequence[dict[str, Any]]",
        *,
        session: "Session",
) -> None:
    """
    Add multiple Opendata DIDs to the catalog.

    Parameters:
        dids: A sequence of dictionaries, each containing 'scope' and 'name' keys for the DIDs to be added.
        session: SQLAlchemy session to use for the operation.

    Raises:
        InputValidationError: If any DID does not have 'scope' or 'name' keys.
        OpenDataDataIdentifierAlreadyExists: If any of the DIDs already exist in the catalog.
        DataIdentifierNotFound: If any of the DIDs do not exist in the database.
    """

    for did in dids:
        if "scope" not in did or "name" not in did:
            raise exception.InputValidationError("DID must have 'scope' and 'name' keys.")

    try:
        # The default state is DRAFT, set in the model
        session.execute(
            insert(models.OpenDataDid),
            [
                {
                    "scope": did["scope"],
                    "name": did["name"],
                }
                for did in dids]
        )
    except IntegrityError as error:
        msg = str(error)

        if (
                search(r'ORA-00001: unique constraint \([^)]+DIDS_OPENDATA_PK\) violated', msg)
                or search(r'UNIQUE constraint failed: dids_opendata\.scope, dids_opendata\.name', msg)
                or search(r'1062.*Duplicate entry.*for key', msg)
                or search(r'duplicate key value violates unique constraint', msg)
                or search(r'UniqueViolation.*duplicate key value violates unique constraint', msg)
                or search(r'columns?.*not unique', msg)
        ):
            raise exception.OpenDataDataIdentifierAlreadyExists()

        raise exception.DataIdentifierNotFound()


def delete_opendata_did(
        *,
        scope: "InternalScope",
        name: str,
        session: "Session",
) -> None:
    """
    Delete an Opendata DID from the catalog.

    Parameters:
        scope: The scope under which the DID is registered.
        name: The name of the DID to be deleted.
        session: SQLAlchemy session to use for the operation.

    Raises:
        OpenDataDataIdentifierNotFound: If the Opendata DID does not exist.
        OpenDataInvalidState: If the Opendata DID is not in a valid state for deletion (must be DRAFT).
        ValueError: If there is an error during the deletion process.
    """

    query = select(
        models.OpenDataDid.scope,
        models.OpenDataDid.name,
        models.OpenDataDid.state,
    ).where(
        and_(
            models.OpenDataDid.scope == scope,
            models.OpenDataDid.name == name
        )
    )

    result = session.execute(query).mappings().fetchone()
    if not result:
        raise exception.OpenDataDataIdentifierNotFound(f"OpenData DID '{scope}:{name}' not found.")

    # state needs to be draft to be deleted
    if result["state"] != OpenDataDIDState.DRAFT:
        raise exception.OpenDataInvalidState(
            f"OpenData entry '{scope}:{name}' not in a valid state for deletion. State: {result['state']}, expected: {OpenDataDIDState.DRAFT}")

    delete_stmt = delete(models.OpenDataDid).where(
        and_(
            models.OpenDataDid.scope == bindparam("scope"),
            models.OpenDataDid.name == bindparam("name")
        )
    )

    result = session.execute(delete_stmt, {"scope": scope, "name": name})

    if result.rowcount == 0:
        raise ValueError(f"Error deleting Opendata entry '{scope}:{name}'.")


def update_opendata_did(
        *,
        scope: "InternalScope",
        name: str,
        state: Optional[OpenDataDIDState] = None,
        meta: Optional[Union[dict, str]] = None,
        doi: Optional[str] = None,
        record_id: Optional[int] = None,
        session: "Session",
) -> dict[str, Any]:
    """
    Update an existing Opendata DID in the catalog.

    Parameters:
        scope: The scope under which the DID is registered.
        name: The name of the DID to be updated.
        state: The new state to set for the DID.
        meta: Metadata to update for the DID. Must be a valid JSON object or string.
        doi: DOI to associate with the DID. Must be a valid DOI string (e.g., "10.1234/foo.bar").
        record_id: The record ID of the DID to update. This can be used to cross-reference with external systems.
        session: SQLAlchemy session to use for the operation.

    Returns:
        A dictionary containing the scope and name of the DID and details of the updates performed. (e.g., new/old state, new/old DOI, etc.)

    Raises:
        InputValidationError: If none of 'state', 'meta', or 'doi' are provided, or if the provided data is invalid.
        OpenDataDataIdentifierNotFound: If the Opendata DID does not exist.
        OpenDataInvalidStateUpdate: If the state update is not valid (e.g., trying to set DRAFT after PUBLIC).
        ValueError: If there is an error during the update process.
    """

    if not any(x is not None for x in [state, meta, doi, record_id]):
        raise exception.InputValidationError(
            "Either 'state', 'meta', 'doi', or 'record_id' must be provided to update the Opendata DID.")
    if not _check_opendata_did_exists(scope=scope, name=name, session=session):
        raise exception.OpenDataDataIdentifierNotFound(f"OpenData DID '{scope}:{name}' not found.")

    result = {}

    if state is not None:
        result |= update_opendata_state(scope=scope, name=name, state=state, session=session)

    if meta is not None:
        result |= update_opendata_meta(scope=scope, name=name, meta=meta, session=session)

    if doi is not None:
        result |= update_opendata_doi(scope=scope, name=name, doi=doi, session=session)

    if record_id is not None:
        result |= update_opendata_record_id(scope=scope, name=name, record_id=record_id, session=session)

    return result


def update_opendata_meta(
        *,
        scope: "InternalScope",
        name: str,
        meta: Union[dict, str],
        session: "Session",
) -> dict[str, Any]:
    """
    Update the metadata associated with an Opendata DID.

    Parameters:
        scope: The scope under which the Opendata DID is registered.
        name: The name of the Opendata DID.
        meta: Metadata to update for the DID. Must be a valid JSON object or string.
        session: SQLAlchemy session to use for the operation.

    Returns:
        A dictionary containing the scope, name, and updated metadata of the Opendata DID.

    Raises:
        InputValidationError: If 'meta' is not a dictionary or a valid JSON string.
        OpenDataDataIdentifierNotFound: If the Opendata DID does not exist.
        ValueError: If there is an error during the update or insert process.
    """

    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except ValueError as error:
            raise exception.InputValidationError(f"Invalid JSON data: {error}")

    if not isinstance(meta, dict):
        raise exception.InputValidationError("'meta' must be a dictionary.")

    try:
        stmt = update(models.OpenDataMeta).where(
            and_(
                models.OpenDataMeta.scope == scope,
                models.OpenDataMeta.name == name
            )
        ).values(meta=meta).execution_options(synchronize_session="fetch")
        result = session.execute(stmt)

        if result.rowcount == 0:
            # If no rows were updated, insert a new row
            insert_stmt = insert(models.OpenDataMeta).values(
                scope=scope,
                name=name,
                meta=meta
            )
            result = session.execute(insert_stmt)

        if result.rowcount == 0:
            raise ValueError(f"Error inserting Opendata meta for DID '{scope}:{name}'.")

    except DataError as error:
        raise exception.InputValidationError(f"Invalid data: {error}")

    return {"scope": scope, "name": name, "meta_new": meta}


def _fetch_opendata_rule(scope: "InternalScope",
                         name: str,
                         session: "Session"
                         ) -> Optional[str]:
    """
    Retrieves the replication rule ID associated with an Opendata DID, if it exists.
    The rule is searched for in the rules table by matching the scope, name, account (root), rse_expression,
    and copies (1) based on the configuration used for creating the rule.

    Parameters:
        scope: The scope under which the Opendata DID is registered.
        name: The name of the Opendata DID.
        session: SQLAlchemy session to use for the query.
    Returns:
        The replication rule ID if it exists, otherwise None.
    """

    rule_rse_expression = config_get("opendata", "rule_rse_expression", raise_exception=False, default=None)
    if not rule_rse_expression:
        return None

    rule_account = config_get("opendata", "rule_account", raise_exception=False, default="root")
    rule_vo = config_get("opendata", "rule_vo", raise_exception=False, default=DEFAULT_VO)
    rule_copies = config_get_int("opendata", "rule_copies", raise_exception=False, default=1)

    return session.execute(
        select(models.ReplicationRule.id).where(
            and_(
                models.ReplicationRule.scope == scope,
                models.ReplicationRule.name == name,
                models.ReplicationRule.account == InternalAccount(account=rule_account, vo=rule_vo),
                models.ReplicationRule.rse_expression == rule_rse_expression,
                models.ReplicationRule.copies == rule_copies,
            )
        )
    ).scalar()


def _add_opendata_rule(
        scope: "InternalScope",
        name: str,
        session: "Session"
) -> str:
    """
    Create a replication rule for an Opendata DID.
    The rule is created with parameters defined in the configuration file under the [opendata] section.

    Parameters:
        scope: The scope under which the Opendata DID is registered.
        name: The name of the Opendata DID.
        session: SQLAlchemy session to use for the operation.
    Returns:
        The ID of the created replication rule.
    Raises:
        ValueError: If there is an error during the rule creation process.
    """

    rule_asynchronous = config_get_bool("opendata", "rule_asynchronous", raise_exception=False, default=False)
    rule_activity = config_get("opendata", "rule_activity", raise_exception=False, default=None)
    rule_account = config_get("opendata", "rule_account", raise_exception=False, default="root")
    rule_vo = config_get("opendata", "rule_vo", raise_exception=False, default=DEFAULT_VO)
    rule_copies = config_get_int("opendata", "rule_copies", raise_exception=False, default=1)

    # The `rse_expression` can be defined either in the more specific `rule_rse_expression` (first choice, override)
    # or in the more general `rse_expression` (second choice) in the [opendata] section of the config file.
    rule_rse_expression = config_get("opendata", "rule_rse_expression", raise_exception=False, default=None)
    if not rule_rse_expression:
        rule_rse_expression = config_get("opendata", "rse_expression", raise_exception=True)

    add_rule_result = add_rule(
        dids=[{"scope": scope, "name": name}],
        # We need an account, perhaps we should pass the issuer argument around like in other methods with account
        account=InternalAccount(account=rule_account, vo=rule_vo),
        copies=rule_copies,
        rse_expression=rule_rse_expression,
        grouping="DATASET",
        weight=None,
        lifetime=None,
        locked=False,
        subscription_id=None,
        activity=rule_activity,
        asynchronous=rule_asynchronous,
        session=session,
    )
    if len(add_rule_result) != 1:
        raise ValueError(f"Error adding Open Data rule: {add_rule_result}")

    return add_rule_result[0]


def update_opendata_state(
        *,
        scope: "InternalScope",
        name: str,
        state: OpenDataDIDState,
        session: "Session",
) -> dict[str, Any]:
    """
    Update the state of an Opendata DID.
    If the new state is PUBLIC, a replication rule may be created based on configuration.

    Parameters:
        scope: The scope under which the Opendata DID is registered.
        name: The name of the Opendata DID.
        state: The new state to set for the Opendata DID.
        session: SQLAlchemy session to use for the operation.

    Returns:
        A dictionary with the scope and name of the DID and the rule id if a rule was created and the old and new state.

    Raises:
        InputValidationError: If the provided state is not a valid OpenDataDIDState.
        OpenDataDataIdentifierNotFound: If the Opendata DID does not exist.
        OpenDataInvalidStateUpdate: If the state update is not valid (e.g., trying to set DRAFT after PUBLIC).
        ValueError: If there is an error during the update process.
    """

    if not isinstance(state, OpenDataDIDState):
        raise exception.InputValidationError(
            f"Invalid state '{state}'. Valid opendata states are: {', '.join([s.name for s in OpenDataDIDState])}")

    state_before = session.execute(
        select(models.OpenDataDid.state).where(
            and_(
                models.OpenDataDid.scope == scope,
                models.OpenDataDid.name == name
            )
        )
    ).scalar()

    update_query = update(models.OpenDataDid).where(
        and_(
            models.OpenDataDid.scope == scope,
            models.OpenDataDid.name == name
        )
    ).values({"state": state})

    if state == OpenDataDIDState.DRAFT:
        if state_before != OpenDataDIDState.DRAFT:
            raise OpenDataInvalidStateUpdate(
                "Cannot set state to DRAFT. Once a DID is made public, it cannot be reverted to DRAFT.")
    elif state == OpenDataDIDState.PUBLIC:
        # All states can be set to PUBLIC
        # DID needs to be closed before going public

        did_is_file = session.execute(
            select(models.DataIdentifier.did_type).where(
                and_(
                    models.DataIdentifier.scope == scope,
                    models.DataIdentifier.name == name
                )
            )
        ).scalar() == DIDType.FILE

        if not did_is_file:
            did_is_open = session.execute(
                select(models.DataIdentifier.is_open).where(
                    and_(
                        models.DataIdentifier.scope == scope,
                        models.DataIdentifier.name == name
                    )
                )
            ).scalar()

            if did_is_open:
                raise OpenDataInvalidStateUpdate(
                    "Cannot set state to PUBLIC. The DID must be closed first.")
    elif state == OpenDataDIDState.SUSPENDED:
        if state_before == OpenDataDIDState.DRAFT:
            raise OpenDataInvalidStateUpdate("Cannot set state to SUSPENDED from DRAFT. First set it to PUBLIC.")

    output = {"scope": scope, "name": name, "state_old": state_before, "state_new": state}

    try:
        result = session.execute(update_query)

        if result.rowcount == 0:
            raise ValueError(f"Error updating Opendata state for DID '{scope}:{name}'.")

        if state == OpenDataDIDState.PUBLIC:
            rule_enable = config_get_bool("opendata", "rule_enable", raise_exception=False, default=False)
            if rule_enable:
                rule_id = _fetch_opendata_rule(scope=scope, name=name, session=session)
                if rule_id:
                    output["rule"] = rule_id
                    output["comments"] = "Replication rule already exists"
                else:
                    output["rule"] = _add_opendata_rule(scope=scope, name=name, session=session)
                    output["comments"] = "Replication rule created"

    except DataError as error:
        raise exception.InputValidationError(f"Invalid data: {error}")

    return output


def update_opendata_doi(
        *,
        scope: "InternalScope",
        name: str,
        doi: str,
        session: "Session",
) -> dict[str, Any]:
    """
    Update the DOI (Digital Object Identifier) associated with an Opendata DID.

    Parameters:
        scope: The scope under which the Opendata DID is registered.
        name: The name of the Opendata DID.
        doi: The new DOI to associate with the Opendata DID. Must be a valid DOI string.
        session: SQLAlchemy session to use for the operation.

    Returns:
        A dictionary containing the scope, name, new DOI, and previous DOI of the Opendata DID.

    Raises:
        InputValidationError: If the provided DOI is not a valid string or does not match the expected format.
        OpenDataDataIdentifierNotFound: If the Opendata DID does not exist.
        ValueError: If there is an error during the update process.
    """

    if not _check_opendata_did_exists(scope=scope, name=name, session=session):
        raise exception.OpenDataDataIdentifierNotFound(f"OpenData DID '{scope}:{name}' not found.")

    if not isinstance(doi, str):
        raise exception.InputValidationError("DOI must be a string.")
    if not match(r'^10\.\d{4,9}/[-._;()/:A-Za-z0-9]+$', doi):
        raise exception.InputValidationError("Invalid DOI format.")

    # insert on the DOI table if it does not exist, otherwise update it
    doi_before = session.execute(select(models.OpenDataDOI.doi).where(
        and_(
            models.OpenDataDOI.scope == scope,
            models.OpenDataDOI.name == name
        )
    )).scalar()
    if doi_before is None:
        update_query = insert(models.OpenDataDOI).values(scope=scope, name=name, doi=doi)
    else:
        # TODO: do not freely prevent DOI updates? To be discussed
        update_query = update(models.OpenDataDOI).where(
            and_(
                models.OpenDataDOI.scope == scope,
                models.OpenDataDOI.name == name
            )
        ).values(doi=doi)

    try:
        result = session.execute(update_query)

        if result.rowcount == 0:
            raise ValueError(f"Error updating Opendata DOI for DID '{scope}:{name}'.")

    except IntegrityError as error:
        msg = str(error)

        if (
                search(r'ORA-00001: unique constraint \([^)]+\) violated', msg)
                or search(r'UNIQUE constraint failed: dids_opendata_doi\.doi', msg)
                or search(r'1062.*Duplicate entry.*for key', msg)
                or search(r'duplicate key value violates unique constraint', msg)
                or search(r'columns?.*not unique', msg)
        ):
            raise exception.OpenDataDuplicateDOI(doi=doi)

        raise exception.OpenDataError()
    except DataError as error:
        raise exception.InputValidationError(f"Invalid data: {error}")

    return {"scope": scope, "name": name, "doi_new": doi, "doi_old": doi_before}


def update_opendata_record_id(
        *,
        scope: "InternalScope",
        name: str,
        record_id: int,
        session: "Session",
) -> dict[str, Any]:
    """
    Update the Record ID associated with an Opendata DID.

    Parameters:
        scope: The scope under which the Opendata DID is registered.
        name: The name of the Opendata DID.
        record_id: The new Record ID to associate with the Opendata DID. Must be a valid integer.
        session: SQLAlchemy session to use for the operation.

    Returns:
        A dictionary containing the scope, name, new Record ID, and previous Record ID of the Opendata DID.

    Raises:
        InputValidationError: If the provided DOI is not a valid string or does not match the expected format.
        OpenDataDataIdentifierNotFound: If the Opendata DID does not exist.
        ValueError: If there is an error during the update process.
    """

    if not _check_opendata_did_exists(scope=scope, name=name, session=session):
        raise exception.OpenDataDataIdentifierNotFound(f"OpenData DID '{scope}:{name}' not found.")

    if not isinstance(record_id, int) or record_id < 0:
        raise exception.InputValidationError("Record ID must be a non-negative integer.")

    # insert on the table if it does not exist, otherwise update it
    record_id_before = session.execute(select(models.OpenDataRecord.record_id).where(
        and_(
            models.OpenDataRecord.scope == scope,
            models.OpenDataRecord.name == name
        )
    )).scalar()
    if record_id_before is None:
        update_query = insert(models.OpenDataRecord).values(scope=scope, name=name, record_id=record_id)
    else:
        update_query = update(models.OpenDataRecord).where(
            and_(
                models.OpenDataRecord.scope == scope,
                models.OpenDataRecord.name == name
            )
        ).values(record_id=record_id)

    try:
        result = session.execute(update_query)

        if result.rowcount == 0:
            raise ValueError(f"Error updating Opendata Record ID for DID '{scope}:{name}'.")

    except IntegrityError as error:
        msg = str(error)

        if (
                search(r'ORA-00001: unique constraint \([^)]+\) violated', msg)
                or search(r'UNIQUE constraint failed: dids_opendata_record\.record_id', msg)
                or search(r'1062.*Duplicate entry.*for key', msg)
                or search(r'duplicate key value violates unique constraint', msg)
                or search(r'columns?.*not unique', msg)
        ):
            raise exception.OpenDataDuplicateRecordID(record_id=record_id)

        raise exception.OpenDataError()

    except DataError as error:
        raise exception.InputValidationError(f"Invalid data: {error}")

    return {"scope": scope, "name": name, "record_id_new": record_id, "record_id_old": record_id_before}
