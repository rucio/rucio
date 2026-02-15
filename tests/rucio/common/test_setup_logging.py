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
import io
import logging
import sys
import types

import pytest

from rucio.common import logging as rucio_logging


@pytest.fixture(autouse=True)
def _reset_root_handlers_and_streams():
    """Ensure each test has a clean logging configuration and doesn't leak std stream changes."""
    original_stdout, original_stderr = sys.stdout, sys.stderr
    logging.root.handlers = []
    yield
    logging.root.handlers = []
    sys.stdout = original_stdout
    sys.stderr = original_stderr


def _mock_config_get(value_map):
    def _mock(section, option, raise_exception=False, default=None):
        return value_map.get(option, default)

    return _mock


def _install_flask_default_handler(monkeypatch, default_handler):
    """
    Ensure `from flask.logging import default_handler` resolves to `default_handler`
    without requiring Flask to be installed and without replacing the real `flask`
    module when it is available.
    """
    try:
        # If Flask is installed, just patch the attribute on the real module.
        import flask.logging as flask_logging  # type: ignore
    except Exception:
        # Flask is not installed (or cannot be imported). Provide minimal stubs
        # so the import inside setup_logging works.
        flask_mod = types.ModuleType("flask")
        # Mark as a package (best-effort) so submodule imports behave predictably.
        flask_mod.__path__ = []  # type: ignore[attr-defined]
        # Provide minimal attributes used by _get_request_data().
        flask_mod.has_request_context = lambda: False  # type: ignore[attr-defined]
        flask_mod.request = object()  # type: ignore[attr-defined]

        flask_logging = types.ModuleType("flask.logging")
        monkeypatch.setitem(sys.modules, "flask", flask_mod)
        monkeypatch.setitem(sys.modules, "flask.logging", flask_logging)

    monkeypatch.setattr(flask_logging, "default_handler", default_handler, raising=False)


def test_setup_logging_prefers_env_stream(monkeypatch):
    monkeypatch.setenv("RUCIO_LOG_STREAM", "stderr")
    monkeypatch.setattr(rucio_logging, "config_get", _mock_config_get({"loglevel": "INFO", "logstream": "stdout"}))
    monkeypatch.setattr(rucio_logging, "config_get_bool", _mock_config_get({"redirect_stdout_to_stderr": False}))

    recorded = {}
    monkeypatch.setattr(logging, "basicConfig", lambda **kwargs: recorded.update(kwargs))

    rucio_logging.setup_logging()

    handler = recorded["handlers"][0]
    assert handler.stream is sys.stderr
    assert handler.level == logging.INFO


def test_setup_logging_redirect_env_overrides_config(monkeypatch):
    # env explicitly disables redirect even if config enables it
    fake_stdout = io.StringIO()
    fake_stderr = io.StringIO()
    monkeypatch.setattr(sys, "stdout", fake_stdout)
    monkeypatch.setattr(sys, "stderr", fake_stderr)
    monkeypatch.setenv("RUCIO_LOGGING_REDIRECT_STDOUT_TO_STDERR", "0")

    monkeypatch.setattr(rucio_logging, "config_get", _mock_config_get({"loglevel": "INFO", "logstream": "stderr"}))
    monkeypatch.setattr(rucio_logging, "config_get_bool", _mock_config_get({"redirect_stdout_to_stderr": True}))

    recorded = {}
    monkeypatch.setattr(logging, "basicConfig", lambda **kwargs: recorded.update(kwargs))

    rucio_logging.setup_logging()

    assert sys.stdout is fake_stdout


def test_setup_logging_redirects_stdout(monkeypatch):
    # Ensure global CI env doesn't influence this testcase
    monkeypatch.delenv("RUCIO_LOG_STREAM", raising=False)

    fake_stdout = io.StringIO()
    fake_stderr = io.StringIO()
    monkeypatch.setattr(sys, "stdout", fake_stdout)
    monkeypatch.setattr(sys, "stderr", fake_stderr)
    monkeypatch.setenv("RUCIO_LOGGING_REDIRECT_STDOUT_TO_STDERR", "1")
    monkeypatch.setattr(
        rucio_logging,
        "config_get",
        _mock_config_get({"loglevel": "WARNING", "logstream": "stdout"}),
    )
    monkeypatch.setattr(
        rucio_logging,
        "config_get_bool",
        _mock_config_get({"redirect_stdout_to_stderr": False}),
    )

    recorded = {}
    monkeypatch.setattr(logging, "basicConfig", lambda **kwargs: recorded.update(kwargs))

    rucio_logging.setup_logging()

    assert sys.stdout is fake_stderr
    handler = recorded["handlers"][0]
    assert handler.stream is fake_stdout
    assert handler.level == logging.WARNING


def test_setup_logging_configures_application_logger(monkeypatch):
    # Provide a fake flask.logging.default_handler so the test doesn't depend on Flask.
    default_handler = object()
    _install_flask_default_handler(monkeypatch, default_handler)

    class DummyLogger:
        def __init__(self):
            # Mimic Flask defaults: one default handler + propagate=False
            self.handlers = [default_handler]
            self.level = None
            self.propagate = False

        def addHandler(self, handler):  # noqa: N802
            self.handlers.append(handler)

        def removeHandler(self, handler):  # noqa: N802
            self.handlers.remove(handler)

        def setLevel(self, level):  # noqa: N802
            self.level = level

    class DummyApp:
        def __init__(self):
            self.logger = DummyLogger()

    monkeypatch.setattr(rucio_logging, "config_get", _mock_config_get({"loglevel": "ERROR", "logstream": "stderr"}))
    monkeypatch.setattr(rucio_logging, "config_get_bool", _mock_config_get({"redirect_stdout_to_stderr": False}))

    recorded = {}
    monkeypatch.setattr(logging, "basicConfig", lambda **kwargs: recorded.update(kwargs))

    app = DummyApp()
    rucio_logging.setup_logging(application=app, process_name="worker")

    handler = recorded["handlers"][0]
    assert app.logger.handlers == [handler]
    assert app.logger.level == logging.ERROR
    assert app.logger.propagate is False


def test_setup_logging_does_not_clear_custom_app_handlers(monkeypatch):
    # Provide a fake flask.logging.default_handler so the test doesn't depend on Flask.
    default_handler = object()
    custom_handler = object()
    _install_flask_default_handler(monkeypatch, default_handler)

    class DummyLogger:
        def __init__(self):
            self.handlers = [default_handler, custom_handler]
            self.level = None
            self.propagate = False

        def addHandler(self, handler):  # noqa: N802
            self.handlers.append(handler)

        def removeHandler(self, handler):  # noqa: N802
            self.handlers.remove(handler)

        def setLevel(self, level):  # noqa: N802
            self.level = level

    class DummyApp:
        def __init__(self):
            self.logger = DummyLogger()

    monkeypatch.setattr(rucio_logging, "config_get", _mock_config_get({"loglevel": "ERROR", "logstream": "stderr"}))
    monkeypatch.setattr(rucio_logging, "config_get_bool", _mock_config_get({"redirect_stdout_to_stderr": False}))

    recorded = {}
    monkeypatch.setattr(logging, "basicConfig", lambda **kwargs: recorded.update(kwargs))

    app = DummyApp()
    rucio_logging.setup_logging(application=app, process_name="worker")

    handler = recorded["handlers"][0]
    assert default_handler not in app.logger.handlers
    assert custom_handler in app.logger.handlers
    assert handler not in app.logger.handlers
    assert app.logger.level == logging.ERROR
