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

import pytest

from rucio.common import logging as rucio_logging


@pytest.fixture(autouse=True)
def _reset_root_handlers():
    """Ensure each test has a clean logging root configuration."""
    logging.root.handlers = []
    yield
    logging.root.handlers = []


def _mock_config_get(value_map):
    def _mock(section, option, raise_exception=False, default=None):
        return value_map.get(option, default)

    return _mock


def _mock_config_get_bool(value_map):
    def _mock(section, option, raise_exception=False, default=None):
        return value_map.get(option, default)

    return _mock


def test_setup_logging_prefers_env_stream(monkeypatch):
    monkeypatch.setenv("RUCIO_LOG_STREAM", "stderr")
    monkeypatch.setattr(rucio_logging, "config_get", _mock_config_get({"loglevel": "INFO", "logstream": "stdout"}))
    monkeypatch.setattr(rucio_logging, "config_get_bool", _mock_config_get_bool({"redirect_stdout_to_stderr": False}))

    recorded = {}
    monkeypatch.setattr(logging, "basicConfig", lambda **kwargs: recorded.update(kwargs))

    rucio_logging.setup_logging()

    handler = recorded["handlers"][0]
    assert handler.stream is sys.stderr
    assert handler.level == logging.INFO


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
        _mock_config_get_bool({"redirect_stdout_to_stderr": False}),
    )

    recorded = {}
    monkeypatch.setattr(logging, "basicConfig", lambda **kwargs: recorded.update(kwargs))

    rucio_logging.setup_logging()

    assert sys.stdout is fake_stderr
    handler = recorded["handlers"][0]
    assert handler.stream is fake_stdout
    assert handler.level == logging.WARNING


def test_setup_logging_configures_application_logger(monkeypatch):
    class DummyLogger:
        def __init__(self):
            self.handlers = ["original"]
            self.level = None
            self.propagate = True

        def addHandler(self, handler):  # noqa: N802
            self.handlers.append(handler)

        def setLevel(self, level):  # noqa: N802
            self.level = level

    class DummyApp:
        def __init__(self):
            self.logger = DummyLogger()

    monkeypatch.setattr(rucio_logging, "config_get", _mock_config_get({"loglevel": "ERROR", "logstream": "stderr"}))
    monkeypatch.setattr(rucio_logging, "config_get_bool", _mock_config_get_bool({"redirect_stdout_to_stderr": False}))

    recorded = {}
    monkeypatch.setattr(logging, "basicConfig", lambda **kwargs: recorded.update(kwargs))

    app = DummyApp()
    rucio_logging.setup_logging(application=app, process_name="worker")

    handler = recorded["handlers"][0]
    assert app.logger.handlers == [handler]
    assert app.logger.level == logging.ERROR
    assert app.logger.propagate is False
