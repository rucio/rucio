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
Comprehensive tests for rucio.common.startup_checks

What this suite covers
----------------------
1) Registration API
   - Rejects async functions and async-callable objects
   - Rejects non-callables, empty/whitespace names
   - Case-insensitive duplicate protection + replace=True semantics
   - Tag normalization (whitespace trimming + lower-casing)

2) Selection by tags
   - Unscoped checks run everywhere
   - Only checks whose tags intersect the current service tags are executed

3) Configuration overrides
   - 'enabled' restricts the set of checks to run
   - 'disabled' excludes checks (global)
   - Per-tag variants like 'enabled_REST' / 'disabled_daemon' are honored
   - Option name matching is case-insensitive (e.g., 'EnAbLeD')
   - Unknown names in config are ignored without crashing

4) Error handling
   - Exceptions from callbacks are wrapped as StartupCheckError
   - Callbacks returning an awaitable are rejected at runtime
   - Callbacks requiring positional arguments cause a wrapped error

Notes
-----
- We patch 'startup_checks.config_get_list' to emulate configuration without touching
  the real config system.
- We clear the private _registry around each test to ensure isolation.
- We focus on observable behavior but assert on logging when configuration issues
  should surface warnings for operators.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Optional

import pytest

from rucio.common import startup_checks
from rucio.common.exception import StartupCheckError

if TYPE_CHECKING:
    from collections.abc import Callable


# ---------------------------
# Fixtures
# ---------------------------

@pytest.fixture(autouse=True)
def clear_registry() -> None:
    """Ensure the in-memory registry is clean before/after every test."""
    startup_checks._registry.clear()  # type: ignore[attr-defined]
    yield
    startup_checks._registry.clear()  # type: ignore[attr-defined]


@pytest.fixture
def config_lists(monkeypatch) -> dict[str, list[str]]:
    """Patch config_get_list used by startup_checks to read from a local dict.

    Usage inside a test:
        config_lists['enabled'] = ['check_a']
        config_lists['disabled_REST'] = ['check_b']
    """
    class _CaseInsensitiveDict(dict):  # type: ignore[type-arg]
        def __setitem__(self, key, value):  # type: ignore[override]
            super().__setitem__(str(key).lower(), value)

    class _ConfigValues(_CaseInsensitiveDict):
        def __init__(self) -> None:
            super().__init__()
            self.bools = _CaseInsensitiveDict()
            self.ints = _CaseInsensitiveDict()

    values = _ConfigValues()

    def fake_config_get_list(
            section: str,
            option: str,
            *,
            raise_exception: bool = True,
            default=None,
            **kwargs,
    ) -> list[str]:
        assert section == 'startup_checks'
        key = option.lower()
        if key in values:
            return list(values[key])
        return [] if default is None else default

    monkeypatch.setattr(startup_checks, 'config_get_list', fake_config_get_list)

    def fake_config_get_bool(
            section: str,
            option: str,
            raise_exception: bool = True,
            default=None,
            **kwargs,
    ):
        assert section == 'startup_checks'
        key = option.lower()
        if key in values.bools:
            return values.bools[key]
        if raise_exception:
            raise RuntimeError(f'No boolean config for {option}')
        return default

    def fake_config_get_int(
            section: str,
            option: str,
            raise_exception: bool = True,
            default=None,
            **kwargs,
    ):
        assert section == 'startup_checks'
        key = option.lower()
        if key in values.ints:
            return values.ints[key]
        if raise_exception:
            raise RuntimeError(f'No integer config for {option}')
        return default

    monkeypatch.setattr(startup_checks, 'config_get_bool', fake_config_get_bool)
    monkeypatch.setattr(startup_checks, 'config_get_int', fake_config_get_int)
    return values


# ---------------------------
# Helper
# ---------------------------

def _register(name: str, callback: Callable[[], None], *, tags: Optional[set[str]] = None) -> None:
    startup_checks.register_startup_check(name=name, callback=callback, tags=tags, replace=False)


# ---------------------------
# Registration tests
# ---------------------------

def test_register_rejects_non_callable() -> None:
    with pytest.raises(TypeError):
        startup_checks.register_startup_check(name='bad', callback=42)  # type: ignore[arg-type]


def test_register_rejects_whitespace_name() -> None:
    with pytest.raises(ValueError):
        startup_checks.register_startup_check(name='   ', callback=lambda: None)


def test_register_async_function_rejected() -> None:
    async def _async_check() -> None:
        return None

    with pytest.raises(TypeError):
        startup_checks.register_startup_check(name='async-check', callback=_async_check)


def test_register_async_callable_object_rejected() -> None:
    class _AsyncCallable:
        async def __call__(self) -> None:
            return None

    with pytest.raises(TypeError):
        startup_checks.register_startup_check(name='async-callable', callback=_AsyncCallable())


def test_case_insensitive_duplicates_are_rejected() -> None:
    _register('Example', lambda: None)
    with pytest.raises(ValueError):
        _register('example', lambda: None)


def test_replace_allows_case_insensitive_overwrite() -> None:
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


# ---------------------------
# Tag behavior tests
# ---------------------------

def test_tags_normalized_and_matched_case_insensitively() -> None:
    executed = False

    def _cb() -> None:
        nonlocal executed
        executed = True

    # Mixed-case + whitespace tags at registration
    _register('network', _cb, tags={' REST ', 'DaeMon'})

    # Run only for 'rest'; the check should run due to tag intersection
    startup_checks.run_startup_checks(tags={'rest'})
    assert executed is True


def test_unscoped_check_runs_everywhere() -> None:
    executed = {'global': False, 'daemon': False}

    def _cb_global() -> None:
        executed['global'] = True

    def _cb_daemon() -> None:
        executed['daemon'] = True

    _register('global-check', _cb_global, tags=None)  # unscoped
    _register('daemon-only', _cb_daemon, tags={'daemon'})  # scoped

    startup_checks.run_startup_checks(tags={'daemon'})
    assert executed['global'] is True
    assert executed['daemon'] is True


def test_empty_set_of_tags_behaves_like_unscoped() -> None:
    executed = False

    def _cb() -> None:
        nonlocal executed
        executed = True

    _register('global-check', _cb, tags=set())

    startup_checks.run_startup_checks(tags={'daemon'})
    assert executed is True


def test_only_checks_for_selected_tags_run() -> None:
    executed: list[str] = []

    _register('daemon-c', lambda: executed.append('daemon'), tags={'daemon'})
    _register('rest-c', lambda: executed.append('rest'), tags={'rest'})
    _register('global-c', lambda: executed.append('global'), tags=None)

    startup_checks.run_startup_checks(tags={'daemon'})
    assert 'daemon' in executed
    assert 'global' in executed
    assert 'rest' not in executed


# ---------------------------
# Config override tests
# ---------------------------

def test_enabled_restricts_set(config_lists) -> None:
    executed: list[str] = []

    _register('alpha', lambda: executed.append('alpha'), tags={'daemon'})
    _register('beta', lambda: executed.append('beta'), tags={'daemon'})
    _register('gamma', lambda: executed.append('gamma'), tags={'daemon'})

    config_lists['enabled'] = ['beta']  # only beta should run

    startup_checks.run_startup_checks(tags={'daemon'})
    assert executed == ['beta']


def test_enabled_option_name_is_case_insensitive(config_lists) -> None:
    executed: list[str] = []

    _register('alpha', lambda: executed.append('alpha'), tags={'daemon'})
    _register('beta', lambda: executed.append('beta'), tags={'daemon'})
    config_lists['EnAbLeD'] = ['beta']  # mixed-case key should be honored

    startup_checks.run_startup_checks(tags={'daemon'})
    assert executed == ['beta']


def test_enabled_check_names_are_case_insensitive(config_lists) -> None:
    executed: list[str] = []

    _register('NeTwOrK', lambda: executed.append('NeTwOrK'), tags={'daemon'})
    _register('beta', lambda: executed.append('beta'), tags={'daemon'})

    config_lists['enabled'] = ['network']  # name lookup should be case-insensitive

    startup_checks.run_startup_checks(tags={'daemon'})
    assert executed == ['NeTwOrK']


def test_disabled_global_excludes_when_no_enabled(config_lists) -> None:
    executed: list[str] = []

    _register('alpha', lambda: executed.append('alpha'), tags={'daemon'})
    _register('beta', lambda: executed.append('beta'), tags={'daemon'})

    config_lists['disabled'] = ['beta']

    startup_checks.run_startup_checks(tags={'daemon'})
    assert executed == ['alpha']


def test_disabled_can_remove_all_checks_and_logs_info(config_lists, caplog) -> None:
    executed: list[str] = []

    _register('alpha', lambda: executed.append('alpha'), tags={'daemon'})
    _register('beta', lambda: executed.append('beta'), tags={'daemon'})

    config_lists['disabled'] = ['alpha', 'beta']

    with caplog.at_level(logging.INFO, logger='rucio.startup_checks'):
        startup_checks.run_startup_checks(tags={'daemon'})

    assert executed == []
    info_messages = [record.getMessage() for record in caplog.records if record.levelno >= logging.INFO]
    assert any('No startup checks to run for tags daemon' in message for message in info_messages)


def test_disable_overrides_enable_per_tag(config_lists) -> None:
    executed: list[str] = []

    _register('alpha', lambda: executed.append('alpha'), tags={'rest'})
    _register('beta', lambda: executed.append('beta'), tags={'rest'})

    config_lists['enabled'] = ['alpha', 'beta']
    config_lists['disabled_REST'] = ['beta']  # per-tag disabled wins over enabled

    startup_checks.run_startup_checks(tags={'rest'})
    assert executed == ['alpha']


def test_enabled_per_tag_suffix_is_honoured(config_lists) -> None:
    executed = False

    def _cb() -> None:
        nonlocal executed
        executed = True

    _register('network', _cb, tags={'rest'})
    config_lists['enabled_REST'] = ['network']

    startup_checks.run_startup_checks(tags={'rest'})
    assert executed is True


def test_unknown_names_in_config_are_ignored(config_lists, caplog) -> None:
    executed: list[str] = []
    _register('alpha', lambda: executed.append('alpha'), tags={'daemon'})

    config_lists['enabled'] = ['ghost']  # does not exist

    with caplog.at_level(logging.WARNING, logger='rucio.startup_checks'):
        startup_checks.run_startup_checks(tags={'daemon'})

    assert executed == ['alpha']
    warning_messages = [record.getMessage() for record in caplog.records if record.levelno >= logging.WARNING]
    assert any('Unknown startup check(s) in `startup_checks.enabled`' in message for message in warning_messages)
    assert any('falling back to default checks' in message for message in warning_messages)


def test_unknown_disabled_names_raise_warning(config_lists, caplog) -> None:
    executed: list[str] = []
    _register('alpha', lambda: executed.append('alpha'), tags={'daemon'})

    config_lists['disabled'] = ['ghost']

    with caplog.at_level(logging.WARNING, logger='rucio.startup_checks'):
        startup_checks.run_startup_checks(tags={'daemon'})

    assert executed == ['alpha']
    warning_messages = [record.getMessage() for record in caplog.records if record.levelno >= logging.WARNING]
    assert any('Unknown startup check(s) in `startup_checks.disabled`' in message for message in warning_messages)


def test_enabled_not_applicable_names_fall_back_to_defaults(config_lists, caplog) -> None:
    executed: list[str] = []

    _register('alpha', lambda: executed.append('alpha'), tags={'daemon'})
    _register('beta', lambda: executed.append('beta'), tags={'rest'})

    config_lists['enabled'] = ['beta']  # valid check but not for daemon tag

    with caplog.at_level(logging.INFO, logger='rucio.startup_checks'):
        startup_checks.run_startup_checks(tags={'daemon'})

    assert executed == ['alpha']
    info_messages = [record.getMessage() for record in caplog.records if record.levelno >= logging.INFO]
    assert any('not applicable to tags' in message for message in info_messages)
    assert any('falling back to default checks' in message for message in info_messages)


def test_strict_mode_unknown_names_fail(config_lists) -> None:
    _register('alpha', lambda: None, tags={'daemon'})
    config_lists['enabled'] = ['ghost']
    config_lists.bools['strict'] = True

    with pytest.raises(StartupCheckError):
        startup_checks.run_startup_checks(tags={'daemon'})


def test_strict_mode_missing_names_fail(config_lists) -> None:
    _register('alpha', lambda: None, tags={'rest'})
    config_lists['enabled'] = ['alpha']
    config_lists.bools['strict'] = True

    with pytest.raises(StartupCheckError):
        startup_checks.run_startup_checks(tags={'daemon'})


def test_strict_mode_filters_removing_all_checks_fail(config_lists) -> None:
    _register('alpha', lambda: None, tags={'daemon'})
    config_lists['enabled'] = ['alpha']
    config_lists['disabled'] = ['alpha']
    config_lists.bools['strict'] = True

    with pytest.raises(StartupCheckError):
        startup_checks.run_startup_checks(tags={'daemon'})


def test_enabled_may_list_names_from_other_tags_but_only_current_tags_run(config_lists) -> None:
    executed: list[str] = []

    _register('alpha', lambda: executed.append('alpha'), tags={'rest'})
    _register('beta', lambda: executed.append('beta'), tags={'daemon'})

    # both listed, but we run with 'rest' only; expect only alpha
    config_lists['enabled'] = ['alpha', 'beta']

    startup_checks.run_startup_checks(tags={'rest'})
    assert executed == ['alpha']


# ---------------------------
# Error handling tests
# ---------------------------

def test_callback_exception_is_wrapped() -> None:
    def _boom() -> None:
        raise RuntimeError('boom')

    _register('explodes', _boom, tags={'daemon'})
    with pytest.raises(StartupCheckError):
        startup_checks.run_startup_checks(tags={'daemon'})


def test_callback_requiring_arguments_is_wrapped() -> None:
    def _needs_arg(x: int) -> None:
        return None

    _register('bad-sig', _needs_arg, tags={'daemon'})
    with pytest.raises(StartupCheckError):
        startup_checks.run_startup_checks(tags={'daemon'})


def test_async_return_value_is_rejected() -> None:
    async def _async_inner() -> None:
        await asyncio.sleep(0)

    def _callback():
        return _async_inner()

    _register('async-return', _callback)
    with pytest.raises(StartupCheckError):
        startup_checks.run_startup_checks(tags={'daemon'})


# Keep the user-proposed tests that are still valuable (for completeness)
def test_enable_and_disable_lists_can_coexist(config_lists) -> None:
    executed: list[str] = []

    def _make_callback(name: str) -> Callable[[], None]:
        def _callback() -> None:
            executed.append(name)

        return _callback

    _register('alpha', _make_callback('alpha'), tags={'daemon'})
    _register('beta', _make_callback('beta'), tags={'daemon'})

    config_lists['enabled'] = ['alpha', 'beta']
    config_lists['disabled_DAEMON'] = ['beta']

    startup_checks.run_startup_checks(tags={'daemon'})
    assert executed == ['alpha']


def test_tag_suffix_case_is_honoured(config_lists) -> None:
    executed = False

    def _callback() -> None:
        nonlocal executed
        executed = True

    _register('network', _callback, tags={'rest'})
    config_lists['enabled_REST'] = ['network']

    startup_checks.run_startup_checks(tags={'rest'})
    assert executed is True


def test_duplicate_names_in_config_lists_are_deduplicated(config_lists) -> None:
    executed: list[str] = []

    _register('alpha', lambda: executed.append('alpha'), tags={'daemon'})

    config_lists['enabled'] = ['alpha', 'ALPHA', 'alpha']

    startup_checks.run_startup_checks(tags={'daemon'})

    assert executed == ['alpha']


def test_soft_timeout_logs_warning(config_lists, caplog, monkeypatch) -> None:
    executed: list[str] = []

    _register('alpha', lambda: executed.append('alpha'), tags={'daemon'})

    config_lists.ints['timeout_ms'] = 150

    times = iter([100.0, 100.2, 100.2])
    monkeypatch.setattr(startup_checks.time, 'perf_counter', lambda: next(times))

    with caplog.at_level(logging.WARNING, logger='rucio.startup_checks'):
        startup_checks.run_startup_checks(tags={'daemon'})

    assert executed == ['alpha']
    warning_messages = [record.getMessage() for record in caplog.records if record.levelno >= logging.WARNING]
    assert any('exceeded soft timeout' in message for message in warning_messages)


def test_summary_logs_include_counts(config_lists, caplog) -> None:
    executed: list[str] = []

    def _make_cb(name: str):
        def _cb() -> None:
            executed.append(name)

        return _cb

    _register('alpha', _make_cb('alpha'), tags={'daemon'})
    _register('beta', _make_cb('beta'), tags={'daemon'})

    config_lists['disabled'] = ['beta']

    with caplog.at_level(logging.INFO, logger='rucio.startup_checks'):
        startup_checks.run_startup_checks(tags={'daemon'})

    assert executed == ['alpha']
    info_messages = [record.getMessage() for record in caplog.records if record.levelno == logging.INFO]
    assert any('Startup checks completed successfully: 1 ran, 1 disabled by config' in message for message in info_messages)
