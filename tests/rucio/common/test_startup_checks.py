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

# ruff: noqa: UP007, UP045

"""
Tests for :mod:`rucio.common.startup_checks`.

This suite exercises the startup-check registry and runner contract:
- registration validation (names, callability, async rejection, replace semantics, tag normalization)
- tag-based selection (scoped vs unscoped checks, multi-tag intersection, snapshot semantics for late registration)
- config-driven filtering (enabled/disabled lists, per-tag overrides, case-insensitive matching, deduping, fallback behaviour, strict mode)
- runtime/observability guarantees (exception wrapping as StartupCheckError, awaitable return rejection, soft-timeout warnings, summary log counts)

Implementation notes:
- Config accessors are monkeypatched to an in-memory store and must not consult the config table/DB.
- The internal registry is isolated per test to avoid cross-test coupling.
- Log assertions focus on operator-facing warnings/info rather than implementation details.
"""

from __future__ import annotations

import logging
from typing import Optional

import pytest

from rucio.common import startup_checks
from rucio.common.exception import StartupCheckError

LOGGER_NAME = 'rucio.startup_checks'


class FakeConfigValues(dict):  # type: ignore[type-arg]
    """
    In-memory configuration storage for startup_checks tests.

    The real Rucio configuration layer normalizes option names to lowercase when
    reading from the file-based config. We mimic that here so tests use the same
    "public" behaviour seen in production.

    The object acts like a dict for list-valued options and exposes `.bools` and
    `.ints` for boolean/integer options.
    """

    def __init__(self) -> None:
        super().__init__()
        self.bools = {}
        self.ints = {}

    def __setitem__(self, key, value) -> None:  # type: ignore[override]
        super().__setitem__(str(key).lower(), value)

    def get_list(self, option: str) -> list[str]:
        return list(super().get(option.lower(), []))

    def get_bool(self, option: str) -> Optional[bool]:
        return self.bools.get(option.lower())

    def get_int(self, option: str) -> Optional[int]:
        return self.ints.get(option.lower())


def _messages(caplog, *, min_level: int) -> list[str]:
    """
    Extract captured messages from the startup_checks logger."""
    return [
        record.getMessage()
        for record in caplog.records
        if record.name == LOGGER_NAME and record.levelno >= min_level
    ]


# ---------------------------
# Fixtures
# ---------------------------

@pytest.fixture(autouse=True)
def isolated_registry(monkeypatch) -> None:
    """
    Isolate startup check registrations per test.

    We replace the module-level registry with a fresh dict for the duration of each
    test and let monkeypatch restore the original afterwards. This avoids polluting
    other tests in the suite which may rely on registrations performed elsewhere.
    """
    monkeypatch.setattr(startup_checks, '_registry', {})  # type: ignore[attr-defined]
    yield


@pytest.fixture
def config_values(monkeypatch) -> FakeConfigValues:
    """Patch config accessors used by startup_checks to read from an in-memory dict."""
    values = FakeConfigValues()

    def fake_config_get_list(
            section: str,
            option: str,
            *,
            raise_exception: bool = True,
            default=None,
            check_config_table: bool = True,
            **kwargs,
    ) -> list[str]:
        assert section == 'startup_checks'
        # Startup checks should not require DB access during startup.
        assert check_config_table is False
        result = values.get_list(option)
        if result:
            return result
        return [] if default is None else default

    def fake_config_get_bool(
            section: str,
            option: str,
            raise_exception: bool = True,
            default=None,
            check_config_table: bool = True,
            **kwargs,
    ):
        assert section == 'startup_checks'
        assert check_config_table is False
        result = values.get_bool(option)
        if result is not None:
            return result
        if raise_exception:
            raise RuntimeError(f'No boolean config for {option}')
        return default

    def fake_config_get_int(
            section: str,
            option: str,
            raise_exception: bool = True,
            default=None,
            check_config_table: bool = True,
            **kwargs,
    ):
        assert section == 'startup_checks'
        assert check_config_table is False
        result = values.get_int(option)
        if result is not None:
            return result
        if raise_exception:
            raise RuntimeError(f'No integer config for {option}')
        return default

    monkeypatch.setattr(startup_checks, 'config_get_list', fake_config_get_list)
    monkeypatch.setattr(startup_checks, 'config_get_bool', fake_config_get_bool)
    monkeypatch.setattr(startup_checks, 'config_get_int', fake_config_get_int)
    return values


# ---------------------------
# Helper
# ---------------------------

def _register(name: str, callback, *, tags: Optional[set[str]] = None) -> None:
    startup_checks.register_startup_check(name=name, callback=callback, tags=tags, replace=False)


# ---------------------------
# Config override tests
# ---------------------------

def test_enabled_restricts_set(config_values) -> None:
    executed: list[str] = []

    _register('alpha', lambda: executed.append('alpha'), tags={'daemon'})
    _register('beta', lambda: executed.append('beta'), tags={'daemon'})
    _register('gamma', lambda: executed.append('gamma'), tags={'daemon'})

    config_values['enabled'] = ['beta']  # only beta should run

    startup_checks.run_startup_checks(tags={'daemon'})
    assert executed == ['beta']


def test_enabled_option_name_is_case_insensitive(config_values) -> None:
    executed: list[str] = []

    _register('alpha', lambda: executed.append('alpha'), tags={'daemon'})
    _register('beta', lambda: executed.append('beta'), tags={'daemon'})
    config_values['EnAbLeD'] = ['beta']  # config access normalizes option names

    startup_checks.run_startup_checks(tags={'daemon'})
    assert executed == ['beta']


def test_enabled_check_names_are_case_insensitive(config_values) -> None:
    executed: list[str] = []

    _register('NeTwOrK', lambda: executed.append('NeTwOrK'), tags={'daemon'})
    _register('beta', lambda: executed.append('beta'), tags={'daemon'})

    config_values['enabled'] = ['network']  # name matching should be case-insensitive

    startup_checks.run_startup_checks(tags={'daemon'})
    assert executed == ['NeTwOrK']


def test_disabled_global_excludes_when_no_enabled(config_values) -> None:
    executed: list[str] = []

    _register('alpha', lambda: executed.append('alpha'), tags={'daemon'})
    _register('beta', lambda: executed.append('beta'), tags={'daemon'})

    config_values['disabled'] = ['beta']

    startup_checks.run_startup_checks(tags={'daemon'})
    assert executed == ['alpha']


def test_disabled_can_remove_all_checks_and_logs_info(config_values, caplog) -> None:
    executed: list[str] = []

    _register('alpha', lambda: executed.append('alpha'), tags={'daemon'})
    _register('beta', lambda: executed.append('beta'), tags={'daemon'})

    config_values['disabled'] = ['alpha', 'beta']

    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        startup_checks.run_startup_checks(tags={'daemon'})

    assert executed == []
    assert any('No startup checks to run for tags daemon' in m for m in _messages(caplog, min_level=logging.INFO))


def test_disable_overrides_enable_per_tag(config_values) -> None:
    executed: list[str] = []

    _register('alpha', lambda: executed.append('alpha'), tags={'rest'})
    _register('beta', lambda: executed.append('beta'), tags={'rest'})

    config_values['enabled'] = ['alpha', 'beta']
    config_values['disabled_REST'] = ['beta']  # per-tag disabled wins over enabled

    startup_checks.run_startup_checks(tags={'rest'})
    assert executed == ['alpha']


def test_enabled_per_tag_suffix_is_honoured(config_values) -> None:
    executed = False

    def _cb() -> None:
        nonlocal executed
        executed = True

    _register('network', _cb, tags={'rest'})
    config_values['enabled_REST'] = ['network']

    startup_checks.run_startup_checks(tags={'rest'})
    assert executed is True


def test_unknown_names_in_config_are_ignored(config_values, caplog) -> None:
    executed: list[str] = []
    _register('alpha', lambda: executed.append('alpha'), tags={'daemon'})

    config_values['enabled'] = ['ghost']  # does not exist

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        startup_checks.run_startup_checks(tags={'daemon'})

    assert executed == ['alpha']
    warning_messages = _messages(caplog, min_level=logging.WARNING)
    assert any('Unknown startup check(s) in `startup_checks.enabled`' in m for m in warning_messages)
    assert any('falling back to default checks' in m for m in warning_messages)


def test_unknown_disabled_names_raise_warning(config_values, caplog) -> None:
    executed: list[str] = []
    _register('alpha', lambda: executed.append('alpha'), tags={'daemon'})

    config_values['disabled'] = ['ghost']

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        startup_checks.run_startup_checks(tags={'daemon'})

    assert executed == ['alpha']
    warning_messages = _messages(caplog, min_level=logging.WARNING)
    assert any('Unknown startup check(s) in `startup_checks.disabled`' in m for m in warning_messages)


def test_enabled_not_applicable_names_fall_back_to_defaults(config_values, caplog) -> None:
    executed: list[str] = []

    _register('alpha', lambda: executed.append('alpha'), tags={'daemon'})
    _register('beta', lambda: executed.append('beta'), tags={'rest'})

    config_values['enabled'] = ['beta']  # valid check but not for daemon tag

    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        startup_checks.run_startup_checks(tags={'daemon'})

    assert executed == ['alpha']
    info_messages = _messages(caplog, min_level=logging.INFO)
    assert any('not applicable to tags' in m for m in info_messages)
    assert any('falling back to default checks' in m for m in info_messages)


def test_strict_mode_unknown_names_fail(config_values) -> None:
    _register('alpha', lambda: None, tags={'daemon'})
    config_values['enabled'] = ['ghost']
    config_values.bools['strict'] = True

    with pytest.raises(StartupCheckError):
        startup_checks.run_startup_checks(tags={'daemon'})


def test_strict_mode_unknown_disabled_names_fail(config_values) -> None:
    _register('alpha', lambda: None, tags={'daemon'})
    config_values['disabled'] = ['ghost']
    config_values.bools['strict'] = True

    with pytest.raises(StartupCheckError):
        startup_checks.run_startup_checks(tags={'daemon'})


def test_strict_mode_missing_names_fail(config_values) -> None:
    _register('alpha', lambda: None, tags={'rest'})
    config_values['enabled'] = ['alpha']
    config_values.bools['strict'] = True

    with pytest.raises(StartupCheckError):
        startup_checks.run_startup_checks(tags={'daemon'})


def test_strict_mode_filters_removing_all_checks_fail(config_values) -> None:
    _register('alpha', lambda: None, tags={'daemon'})
    config_values['enabled'] = ['alpha']
    config_values['disabled'] = ['alpha']
    config_values.bools['strict'] = True

    with pytest.raises(StartupCheckError):
        startup_checks.run_startup_checks(tags={'daemon'})


def test_enabled_may_list_names_from_other_tags_but_only_current_tags_run(config_values) -> None:
    executed: list[str] = []

    _register('alpha', lambda: executed.append('alpha'), tags={'rest'})
    _register('beta', lambda: executed.append('beta'), tags={'daemon'})

    # both listed, but we run with 'rest' only; expect only alpha
    config_values['enabled'] = ['alpha', 'beta']

    startup_checks.run_startup_checks(tags={'rest'})
    assert executed == ['alpha']


# ---------------------------
# Error handling tests
# ---------------------------

def test_callback_exception_is_wrapped(config_values) -> None:
    def _boom() -> None:
        raise RuntimeError('boom')

    _register('explodes', _boom, tags={'daemon'})
    with pytest.raises(StartupCheckError) as excinfo:
        startup_checks.run_startup_checks(tags={'daemon'})

    # Ensure we keep a useful exception chain for debugging/observability
    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert 'explodes' in str(excinfo.value)


def test_callback_requiring_arguments_is_wrapped(config_values) -> None:
    def _needs_arg(x: int) -> None:
        # Will raise TypeError when called without args
        return None

    _register('bad-sig', _needs_arg, tags={'daemon'})
    with pytest.raises(StartupCheckError) as excinfo:
        startup_checks.run_startup_checks(tags={'daemon'})

    assert isinstance(excinfo.value.__cause__, TypeError)
    assert 'bad-sig' in str(excinfo.value)


def test_async_return_value_is_rejected(config_values) -> None:
    async def _async_inner() -> None:
        # no asyncio dependency needed; returning a coroutine is enough
        return None

    def _callback():
        return _async_inner()

    # Untagged -> applicable everywhere; run under 'daemon' to execute it.
    _register('async-return', _callback)

    with pytest.raises(StartupCheckError) as excinfo:
        startup_checks.run_startup_checks(tags={'daemon'})

    assert 'async-return' in str(excinfo.value)
    assert 'returned an awaitable' in str(excinfo.value)


# ---------------------------
# Runner behavior / logging tests
# ---------------------------

# NOTE: This overlaps with `test_disable_overrides_enable_per_tag`, but kept as a
# "readable example" of enabled+disabled filters coexisting.
def test_enable_and_disable_lists_can_coexist(config_values) -> None:
    executed: list[str] = []

    def _make_callback(name: str):
        def _callback() -> None:
            executed.append(name)
        return _callback

    _register('alpha', _make_callback('alpha'), tags={'daemon'})
    _register('beta', _make_callback('beta'), tags={'daemon'})

    config_values['enabled'] = ['alpha', 'beta']
    config_values['disabled_DAEMON'] = ['beta']

    startup_checks.run_startup_checks(tags={'daemon'})
    assert executed == ['alpha']


def test_duplicate_names_in_config_lists_are_deduplicated(config_values) -> None:
    executed: list[str] = []

    _register('alpha', lambda: executed.append('alpha'), tags={'daemon'})

    # duplicates (including different case) must not cause multiple runs
    config_values['enabled'] = ['alpha', 'ALPHA', 'alpha']

    startup_checks.run_startup_checks(tags={'daemon'})
    assert executed == ['alpha']


def test_soft_timeout_logs_warning(config_values, caplog, monkeypatch) -> None:
    executed: list[str] = []

    _register('alpha', lambda: executed.append('alpha'), tags={'daemon'})
    config_values.ints['timeout_ms'] = 150

    # perf_counter call sequence in run_startup_checks:
    #   run_start_time, start_time, end_time
    times = iter([100.0, 100.2, 100.2])  # total runtime 200ms -> exceeds 150ms
    monkeypatch.setattr(startup_checks.time, 'perf_counter', lambda: next(times))

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        startup_checks.run_startup_checks(tags={'daemon'})

    assert executed == ['alpha']

    warning_messages = _messages(caplog, min_level=logging.WARNING)
    assert any('Startup checks exceeded soft timeout' in m for m in warning_messages)


def test_summary_logs_include_counts(config_values, caplog) -> None:
    executed: list[str] = []

    def _make_cb(name: str):
        def _cb() -> None:
            executed.append(name)
        return _cb

    _register('alpha', _make_cb('alpha'), tags={'daemon'})
    _register('beta', _make_cb('beta'), tags={'daemon'})

    config_values['disabled'] = ['beta']

    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        startup_checks.run_startup_checks(tags={'daemon'})

    assert executed == ['alpha']

    info_messages = [r.getMessage() for r in caplog.records if r.name == LOGGER_NAME and r.levelno == logging.INFO]
    assert any('Startup checks completed successfully: 1 ran, 1 disabled by config' in m for m in info_messages)


# ---------------------------
# Registration tests
# ---------------------------

def test_register_rejects_non_callable() -> None:
    with pytest.raises(TypeError, match='callable'):
        startup_checks.register_startup_check(name='bad', callback=42)  # type: ignore[arg-type]


def test_register_rejects_whitespace_name() -> None:
    with pytest.raises(ValueError, match='cannot be empty'):
        startup_checks.register_startup_check(name='   ', callback=lambda: None)


def test_register_async_function_rejected() -> None:
    async def _async_check() -> None:
        return None

    with pytest.raises(TypeError, match='asynchronous'):
        startup_checks.register_startup_check(name='async-check', callback=_async_check)  # type: ignore[arg-type]


def test_register_async_callable_object_rejected() -> None:
    class _AsyncCallable:
        async def __call__(self) -> None:
            return None

    with pytest.raises(TypeError, match='asynchronous'):
        startup_checks.register_startup_check(name='async-callable', callback=_AsyncCallable())  # type: ignore[arg-type]


def test_case_insensitive_duplicates_are_rejected() -> None:
    _register('Example', lambda: None)
    with pytest.raises(ValueError, match='already registered'):
        _register('example', lambda: None)


def test_replace_allows_case_insensitive_overwrite(config_values) -> None:
    executed: list[str] = []

    def _v1() -> None:
        executed.append('v1')

    def _v2() -> None:
        executed.append('v2')

    startup_checks.register_startup_check('DB', _v1)
    # Replace using different case; should not raise and should call new callback
    startup_checks.register_startup_check('db', _v2, replace=True)

    startup_checks.run_startup_checks(tags={'daemon'})
    assert executed == ['v2']


def test_replace_runs_new_callback_without_affecting_others(config_values) -> None:
    executed: list[str] = []

    def _alpha_v1() -> None:
        executed.append('alpha-v1')

    def _alpha_v2() -> None:
        executed.append('alpha-v2')

    def _beta() -> None:
        executed.append('beta')

    _register('alpha', _alpha_v1, tags={'daemon'})
    _register('beta', _beta, tags={'daemon'})

    startup_checks.register_startup_check(name='alpha', callback=_alpha_v2, tags={'daemon'}, replace=True)

    startup_checks.run_startup_checks(tags={'daemon'})

    assert 'alpha-v2' in executed
    assert 'beta' in executed
    assert 'alpha-v1' not in executed


# ---------------------------
# Tag behavior tests
# ---------------------------

@pytest.mark.usefixtures("config_values")
def test_tags_normalized_and_matched_case_insensitively() -> None:
    executed = False

    def _cb() -> None:
        nonlocal executed
        executed = True

    # Mixed-case + whitespace tags at registration
    _register('network', _cb, tags={' REST ', 'DaeMon'})

    # Run only for 'rest' (with whitespace too); check should run due to tag intersection
    startup_checks.run_startup_checks(tags={' REST '})
    assert executed is True


@pytest.mark.usefixtures("config_values")
def test_unscoped_check_runs_everywhere() -> None:
    executed = {'global': False, 'daemon': False}

    def _cb_global() -> None:
        executed['global'] = True

    def _cb_daemon() -> None:
        executed['daemon'] = True

    _register('global-check', _cb_global, tags=None)        # unscoped
    _register('daemon-only', _cb_daemon, tags={'daemon'})   # scoped

    startup_checks.run_startup_checks(tags={'daemon'})
    assert executed['global'] is True
    assert executed['daemon'] is True


@pytest.mark.usefixtures("config_values")
def test_empty_registry_logs_no_startup_checks(caplog) -> None:
    with caplog.at_level(logging.INFO, logger=LOGGER_NAME):
        startup_checks.run_startup_checks(tags={'daemon'})

    info_messages = _messages(caplog, min_level=logging.INFO)
    assert any('No startup checks to run for tags daemon' in m for m in info_messages)


@pytest.mark.usefixtures("config_values")
def test_startup_checks_snapshot_semantics_for_late_registration() -> None:
    executed: list[str] = []

    def _late() -> None:
        executed.append('late')

    def _first() -> None:
        executed.append('first')
        # Late registration must not affect the already-built snapshot
        startup_checks.register_startup_check(name='late', callback=_late, tags={'daemon'})

    _register('first', _first, tags={'daemon'})

    startup_checks.run_startup_checks(tags={'daemon'})
    assert executed == ['first']

    startup_checks.run_startup_checks(tags={'daemon'})
    assert executed.count('first') == 2
    assert executed.count('late') == 1


@pytest.mark.usefixtures("config_values")
def test_empty_set_of_tags_behaves_like_unscoped() -> None:
    executed = False

    def _cb() -> None:
        nonlocal executed
        executed = True

    # Empty tags normalize to "unscoped" (runs everywhere)
    _register('global-check', _cb, tags=set())

    startup_checks.run_startup_checks(tags={'daemon'})
    assert executed is True


@pytest.mark.usefixtures("config_values")
def test_only_checks_for_selected_tags_run() -> None:
    executed: list[str] = []

    _register('daemon-c', lambda: executed.append('daemon'), tags={'daemon'})
    _register('rest-c', lambda: executed.append('rest'), tags={'rest'})
    _register('global-c', lambda: executed.append('global'), tags=None)

    startup_checks.run_startup_checks(tags={'daemon'})

    assert 'daemon' in executed
    assert 'global' in executed
    assert 'rest' not in executed


@pytest.mark.usefixtures("config_values")
def test_multi_tag_runtime_runs_any_intersecting_check() -> None:
    executed: list[str] = []

    _register('daemon-only', lambda: executed.append('daemon'), tags={'daemon'})
    _register('rest-only', lambda: executed.append('rest'), tags={'rest'})
    _register('daemon-rest', lambda: executed.append('both'), tags={'daemon', 'rest'})
    _register('global', lambda: executed.append('global'), tags=None)

    startup_checks.run_startup_checks(tags={'daemon', 'rest'})

    assert set(executed) == {'daemon', 'rest', 'both', 'global'}
