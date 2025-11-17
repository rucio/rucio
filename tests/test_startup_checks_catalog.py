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

import importlib
import logging
import sys
from contextlib import contextmanager
from types import ModuleType, SimpleNamespace

import pytest


def _session_scope(dialect: str):
    @contextmanager
    def _scope():
        yield SimpleNamespace(bind=SimpleNamespace(dialect=SimpleNamespace(name=dialect)))

    return _scope


@pytest.fixture
def catalog(monkeypatch):
    session_state = {'dialect': 'postgresql', 'legacy': []}

    def _get_session():
        return _session_scope(session_state['dialect'])

    def _oracle_legacy_json_columns(session):  # pylint: disable=unused-argument
        return list(session_state['legacy'])

    session_module = ModuleType('rucio.db.sqla.session')
    session_module.get_session = _get_session

    util_module = ModuleType('rucio.db.sqla.util')
    util_module.oracle_legacy_json_columns = _oracle_legacy_json_columns

    monkeypatch.setitem(sys.modules, 'rucio.db.sqla.session', session_module)
    monkeypatch.setitem(sys.modules, 'rucio.db.sqla.util', util_module)
    monkeypatch.delitem(sys.modules, 'rucio.common.startup_checks_catalog', raising=False)

    module = importlib.import_module('rucio.common.startup_checks_catalog')

    return module, session_state


def test_legacy_oracle_json_columns_returns_none_for_non_oracle(catalog):
    module, state = catalog
    state['dialect'] = 'postgresql'

    assert module.legacy_oracle_json_columns() is None


def test_legacy_oracle_json_columns_returns_tuple(catalog):
    module, state = catalog
    state['dialect'] = 'oracle'
    state['legacy'] = [('t', 'c')]

    assert module.legacy_oracle_json_columns() == (('t', 'c'),)


def test_ensure_oracle_json_columns_are_native_logs_success(catalog, monkeypatch, caplog):
    module, _ = catalog
    monkeypatch.setattr(module, 'legacy_oracle_json_columns', lambda: ())

    with caplog.at_level(logging.INFO, logger='rucio.common.startup_checks_catalog'):
        module.ensure_oracle_json_columns_are_native()

    assert 'Oracle JSON column check passed' in caplog.text


def test_ensure_oracle_json_columns_are_native_raises(catalog, monkeypatch):
    module, _ = catalog
    monkeypatch.setattr(module, 'legacy_oracle_json_columns', lambda: (('table', 'column'),))

    with pytest.raises(RuntimeError) as error:
        module.ensure_oracle_json_columns_are_native()

    assert 'legacy CLOBs' in str(error.value)


def test_register_all_uses_replace(catalog, monkeypatch):
    module, _ = catalog
    recorded: dict[str, object] = {}

    def _fake_register(*, name, callback, description=None, tags=None, replace):  # type: ignore[no-untyped-def]
        recorded.update(
            name=name,
            callback=callback,
            description=description,
            tags=tags,
            replace=replace,
        )

    monkeypatch.setattr(module, 'register_startup_check', _fake_register)

    module.register_all()

    assert recorded['name'] == 'oracle-json-columns'
    assert recorded['replace'] is True
    assert callable(recorded['callback'])
