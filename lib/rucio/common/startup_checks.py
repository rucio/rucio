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

import inspect
import logging
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Protocol

from rucio.common.config import config_get_bool, config_get_int, config_get_list
from rucio.common.exception import StartupCheckError

if TYPE_CHECKING:
    from collections.abc import Collection, Iterable, Mapping


class StartupCheckCallback(Protocol):
    def __call__(self) -> None: ...


@dataclass(frozen=True)
class StartupCheck:
    """
    Definition of a startup diagnostic.

    Attributes
    ----------
    name:
        Unique identifier of the diagnostic.
    callback:
        Callable invoked to run the diagnostic.
    tags:
        Normalised set of tags describing the environments where the
        diagnostic should execute.
    description:
        Optional human readable text describing the diagnostic. Logged when
        the check runs so that operators know what is happening.
    """

    name: str
    callback: StartupCheckCallback
    tags: frozenset[str]
    description: Optional[str] = None


_registry: dict[str, StartupCheck] = {}
_registry_lock = threading.Lock()


def _normalize_name(name: str) -> str:
    """
    Canonicalise a diagnostic name.

    A lot of the public API accepts free-form strings. Before storing the
    value we trim surrounding whitespace to avoid treating ``" db "`` as a
    distinct check. The same helper is used for validation when registering
    new checks and when processing configuration overrides, which keeps the
    matching logic consistent.

    Parameters
    ----------
    name:
        Raw name supplied by the caller.

    Returns
    -------
    str
        The trimmed diagnostic name.

    Raises
    ------
    ValueError
        If the normalised name would be empty.
    """

    normalized = name.strip()
    if not normalized:
        raise ValueError("Startup check name cannot be empty")
    return normalized


def _normalize_tags(tags: Optional[Iterable[str]]) -> frozenset[str]:
    """
    Normalise a collection of tags.

    Tags are used to scope checks to specific services (for example ``daemon``
    or ``rest``). We trim whitespace and fold everything to lowercase. The return
    type is a :class:`frozenset` so the result can be safely cached and shared
    between helpers without the risk of accidental mutation.

    Parameters
    ----------
    tags:
        Iterable containing the raw tag identifiers. ``None`` or empty values
        result in an empty set.

    Returns
    -------
    frozenset of str
        The cleaned, lower-cased tags with surrounding whitespace removed.
    """

    if not tags:
        return frozenset()
    return frozenset(tag.strip().lower() for tag in tags if tag and tag.strip())


def _collect_configured_names(
        option: str,
        tags: frozenset[str],
        tag_suffixes: Mapping[str, Collection[str]]
) -> set[str]:
    """
    Collect the check names configured for a given option.

    Configuration may list checks under generic ``enabled`` / ``disabled``
    keys as well as under tag specific variants such as ``enabled_daemon``.
    This helper gathers all the possible spellings for the requested tags and
    collates the configured check names into a single cleaned set. The caller
    is still responsible for reconciling these names with the registry.

    Parameters
    ----------
    option:
        Name of the configuration option (``"enabled"`` or ``"disabled"``).
    tags:
        Set of tags describing the current service.

    Returns
    -------
    set of str
        Cleaned set of check names extracted from the configuration.
    """

    # ConfigParser normalizes option names, but config table lookups are case-sensitive,
    # so query common case variants to avoid missing mixed-case entries.
    options_to_query = {
        option,
        option.lower(),
        option.upper(),
    }

    for tag in tags:
        suffixes = tag_suffixes.get(tag)
        if not suffixes:
            suffixes = {tag}
        for suffix in suffixes:
            tag_option = f'{option}_{suffix}'
            options_to_query.add(tag_option)
            options_to_query.add(tag_option.lower())
            options_to_query.add(tag_option.upper())

    values: set[str] = set()
    for config_option in options_to_query:
        values.update(config_get_list(
            'startup_checks',
            config_option,
            raise_exception=False,
            default=[],
            check_config_table=False,
        ))
    return {value.strip() for value in values if value and value.strip()}


def _select_checks(tags: frozenset[str]) -> tuple[list[StartupCheck], set[str]]:
    """
    Return the set of checks applicable to the supplied tags.

    The registry is protected by a lock during iteration so that late
    registrations do not race with an ongoing startup check run. The function
    returns a snapshot rather than a live view because the caller will filter
    the list based on configuration overrides.

    Parameters
    ----------
    tags:
        Set of normalised tags describing the current service.

    Returns
    -------
    tuple
        Two elements where the first item is the list of registered checks
        whose tag set intersects *tags* (or which are unscoped) and the
        second item is the set of all registered check names.
    """

    with _registry_lock:
        checks = list(_registry.values())
        all_names = set(_registry)

    if not tags:
        return checks, all_names

    return [
        check for check in checks
        if not check.tags or check.tags.intersection(tags)
    ], all_names


def _prepare_tags(tags: Optional[Iterable[str]]) -> tuple[frozenset[str], dict[str, frozenset[str]]]:
    """
    Normalise tags and compute the variants used for configuration lookups.

    Besides producing the cleaned :class:`frozenset` of tags, this helper also
    pre-computes a map of case variants for each tag. Configuration files may
    spell options with different casing (``ENABLED_DAEMON`` vs ``enabled_daemon``),
    so keeping all the candidate variants upfront avoids repeating that work in
    the hot path.
    """

    if not tags:
        return frozenset(), {}

    normalized: set[str] = set()
    suffixes: dict[str, set[str]] = {}

    for raw_tag in tags:
        if not raw_tag:
            continue
        trimmed = raw_tag.strip()
        if not trimmed:
            continue
        normalized_tag = trimmed.lower()
        normalized.add(normalized_tag)
        variants = suffixes.setdefault(normalized_tag, set())
        variants.add(normalized_tag)
        variants.add(trimmed)
        variants.add(trimmed.lower())
        variants.add(trimmed.upper())

    return frozenset(normalized), {tag: frozenset(variants) for tag, variants in suffixes.items()}


def run_startup_checks(
        *,
        tags: Optional[Iterable[str]] = None,
        logger: Optional[logging.Logger] = None
) -> None:
    """
    Run startup diagnostics applicable to the given service tags.

    Collects all registered checks that apply to ``tags`` (plus untagged ones),
    optionally filters them according to the ``[startup_checks]`` section in
    ``rucio.cfg``, and executes them. On any failure, raises
    :class:`~rucio.common.exception.StartupCheckError`.

    Parameters
    ----------
    tags : Collection[str]
        Tags describing the current service(s). Common values are ``{"daemon"}`` and ``{"rest"}``.
    logger : logging.Logger | Callable[..., None] | None, optional
        Component‑specific logger. If omitted, uses the module logger ``rucio.startup_checks``.

    Behavior
    --------
    - **Default selection**: all checks whose tag set intersects the supplied ``tags``,
      plus untagged checks.
    - **Config filters (optional)** from ``[startup_checks]`` in ``rucio.cfg``:
        * ``enabled`` / ``enabled_<TAG>`` restrict the set (union) after tag filtering.
        * ``disabled`` / ``disabled_<TAG>`` remove names. **Disabled wins** when both apply.
        * Name and tag comparisons are case‑insensitive; duplicates are deduplicated.
        * Unknown names are ignored with a warning (or fail in strict mode).
        * If enabled lists select nothing applicable, the runner falls back to the default set
          and logs that fallback (unless strict mode is on).
    - **Soft time budget**: ``startup_checks.timeout_ms`` sets a soft limit for the whole run.
      Exceeding the cumulative runtime logs a warning once and execution continues.
    - **Strict mode**: ``startup_checks.strict = true`` turns these into hard errors:
        * unknown names in any ``enabled*``/``disabled*``,
        * enabled lists containing only non‑applicable names,
        * configuration that removes all applicable checks.

    Returns
    -------
    None

    Raises
    ------
    StartupCheckError
        If any check fails, or if configuration is invalid under strict mode.

    Logging
    -------
    - Logs each check's ``description`` (if provided) before execution.
    - Logs a completion summary like:
      ``Startup checks completed successfully: N ran, M disabled by config``.

    Examples
    --------
    >>> run_startup_checks(tags={"daemon"})
    """

    normalized_tags, tag_suffixes = _prepare_tags(tags)
    tags_display = ', '.join(sorted(normalized_tags)) or 'default'
    log = logger or logging.getLogger('rucio.startup_checks')

    checks_snapshot, all_registered_names = _select_checks(normalized_tags)
    checks = list(checks_snapshot)

    strict_mode = config_get_bool(
        'startup_checks',
        'strict',
        raise_exception=False,
        default=False,
        check_config_table=False,
    )
    soft_timeout_ms = config_get_int(
        'startup_checks',
        'timeout_ms',
        raise_exception=False,
        default=0,
        check_config_table=False,
    )
    if soft_timeout_ms <= 0:
        soft_timeout_ms = None

    enabled = _collect_configured_names('enabled', normalized_tags, tag_suffixes)
    disabled = _collect_configured_names('disabled', normalized_tags, tag_suffixes)

    registered_names = {check.name for check in checks}
    lower_all_registered_names = {name.lower(): name for name in all_registered_names}
    all_registered_lower_names = set(lower_all_registered_names.keys())

    disabled_applied_lower: set[str] = set()

    if enabled:
        configured_enabled_map = {name.lower(): name for name in enabled}
        enabled_lower = set(configured_enabled_map)
        unknown = enabled_lower - all_registered_lower_names
        if unknown:
            unknown_enabled_display = sorted(configured_enabled_map[name] for name in unknown)
            log.warning(
                'Unknown startup check(s) in `startup_checks.enabled`: %s - ignored',
                ', '.join(unknown_enabled_display),
            )
            if strict_mode:
                raise StartupCheckError(
                    'Strict startup checks mode rejected unknown check(s) configured in '
                    '`startup_checks.enabled`: '
                    f"{', '.join(unknown_enabled_display)}"
                )
        registered_names_lower = {name.lower() for name in registered_names}
        missing = (enabled_lower - registered_names_lower) - unknown
        missing_display: list[str] = []
        if missing:
            missing_display = [
                configured_enabled_map.get(name)
                or lower_all_registered_names.get(name, name)
                for name in sorted(missing)
            ]
            log.info(
                'Startup check(s) in `startup_checks.enabled` are not applicable to tags %s - ignored: %s',
                tags_display,
                ', '.join(missing_display),
            )
        enabled_effective = enabled_lower & registered_names_lower
        checks = [check for check in checks if check.name.lower() in enabled_effective]
        if not checks:
            if strict_mode:
                details = f' Non-applicable enabled check(s): {", ".join(missing_display)}.' if missing_display else ''
                raise StartupCheckError(
                    'Strict startup checks mode requires that `startup_checks.enabled` selects at least one '
                    f'check applicable to tags {tags_display}.{details}'
                )
            log.warning(
                'All configured `startup_checks.enabled` names were unknown or not applicable; '
                'falling back to default checks for tags %s',
                tags_display,
            )
            checks = list(checks_snapshot)

    if disabled:
        configured_disabled_map = {name.lower(): name for name in disabled}
        disabled_lower = set(configured_disabled_map)
        checks_before_disabled = {check.name.lower() for check in checks}
        checks = [check for check in checks if check.name.lower() not in disabled_lower]
        disabled_applied_lower = checks_before_disabled - {check.name.lower() for check in checks}
        unknown_disabled = disabled_lower - all_registered_lower_names
        if unknown_disabled:
            unknown_disabled_display = sorted(configured_disabled_map[name] for name in unknown_disabled)
            log.warning(
                'Unknown startup check(s) in `startup_checks.disabled`: %s - ignored',
                ', '.join(unknown_disabled_display),
            )
            if strict_mode:
                raise StartupCheckError(
                    'Strict startup checks mode rejected unknown check(s) configured in '
                    '`startup_checks.disabled`: '
                    f"{', '.join(unknown_disabled_display)}"
                )

    if disabled_applied_lower and log.isEnabledFor(logging.DEBUG):
        disabled_applied_display = [
            lower_all_registered_names.get(name, name)
            for name in sorted(disabled_applied_lower)
        ]
        log.debug('Startup checks disabled by config: %s', ', '.join(disabled_applied_display))

    if not checks:
        if strict_mode and (enabled or disabled):
            raise StartupCheckError(
                'No startup checks remain after applying enabled/disabled filters for tags '
                f'{tags_display} in strict mode'
            )
        log.info('No startup checks to run for tags %s', tags_display)
        return

    log.info('Running startup checks%s', f' [{tags_display}]' if normalized_tags else '')

    checks = sorted(checks, key=lambda check: check.name.casefold())

    durations: list[tuple[str, float]] = []

    run_start_time = time.perf_counter()
    soft_timeout_logged = False

    for check in checks:
        description = f' ({check.description})' if check.description else ''
        log.info('Running startup check %s%s', check.name, description)
        start_time = time.perf_counter()
        try:
            result = check.callback()
            if inspect.isawaitable(result):
                if inspect.iscoroutine(result):
                    result.close()
                raise StartupCheckError(
                    f'Startup check "{check.name}" returned an awaitable; asynchronous callbacks are not supported'
                )
        except StartupCheckError:
            duration_ms = (time.perf_counter() - start_time) * 1000
            log.critical('Startup check %s failed after %.1f ms', check.name, duration_ms, exc_info=True)
            raise
        except Exception as error:  # pylint: disable=broad-exception-caught
            duration_ms = (time.perf_counter() - start_time) * 1000
            log.critical(
                'Startup check %s raised an unexpected exception after %.1f ms',
                check.name,
                duration_ms,
                exc_info=True,
            )
            raise StartupCheckError(
                f'Startup check "{check.name}" failed with unexpected error: {error}'
            ) from error
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000
        log.debug('Startup check "%s" passed in %.1f ms', check.name, duration_ms)
        total_runtime_ms = (end_time - run_start_time) * 1000
        if soft_timeout_ms is not None and not soft_timeout_logged and total_runtime_ms > soft_timeout_ms:
            log.warning(
                'Startup checks exceeded soft timeout after "%s" (%.0f > %d ms)',
                check.name,
                total_runtime_ms,
                soft_timeout_ms,
            )
            soft_timeout_logged = True
        durations.append((check.name, duration_ms))

    disabled_count = len(disabled_applied_lower)
    if durations:
        slowest_name, slowest_duration = max(durations, key=lambda item: item[1])
        log.info(
            'Startup checks completed successfully: %d ran, %d disabled by config, '
            'slowest=%s (%.1f ms)',
            len(durations),
            disabled_count,
            slowest_name,
            slowest_duration,
        )
    else:
        log.info(
            'Startup checks completed successfully: no checks ran, %d disabled by config',
            disabled_count,
        )


__all__ = ['run_startup_checks', 'StartupCheck', 'StartupCheckCallback']
