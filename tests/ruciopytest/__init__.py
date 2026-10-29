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

import enum
import logging
import sys

import pytest

from .profiles import SUITE_PROFILES, SuiteProfile  # noqa: F401


class _StdoutHandler(logging.StreamHandler):
    """Write to the current sys.stdout, which pytest swaps while capturing.

    This keeps the plugin's progress messages exactly where print() would put
    them: on the terminal on the host, and in the forwarded output inside the
    container.
    """

    def emit(self, record: logging.LogRecord) -> None:
        self.stream = sys.stdout
        super().emit(record)


class _Formatter(logging.Formatter):
    """'[module] message', with the level name added for warnings and errors."""

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        if record.levelno >= logging.WARNING:
            return f'[{record.module}] {record.levelname}: {message}'
        return f'[{record.module}] {message}'


# Plugin modules log through logging.getLogger(__name__); their records end up here.
_logger = logging.getLogger(__name__)
if not _logger.handlers:
    _handler = _StdoutHandler(sys.stdout)
    _handler.setFormatter(_Formatter('%(message)s'))
    _logger.addHandler(_handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False

# Type-safe stash keys (shared across plugin.py and collection.py)

suite_profile_key = pytest.StashKey[SuiteProfile]()
container_manager_key = pytest.StashKey["ContainerManager"]()
delegate_to_container_key = pytest.StashKey[bool]()
# Set on the in-container multi_vo outer session: the aggregate exit code of the
# per-VO xdist children (run_multi_vo). When present, the outer session does NOT
# collect/run the suite itself -- it mirrors this code so CI gates on the
# faithful per-VO xdist execution, not a redundant serial pass.
multi_vo_forward_rc_key = pytest.StashKey[int]()


class NoParallelGroups(enum.Enum):
    # Special group. Tests with this marker will never run in parallel with any other test
    EXCLUSIVE = 'exclusive'
    # Per-daemon-groups. Running the same daemon multiple times in parallel will fail due to job assignment by hash
    PREPARER = 'preparer'
    THROTTLER = 'throttler'
    STAGER = 'stager'
    SUBMITTER = 'submitter'
    POLLER = 'poller'
    RECEIVER = 'receiver'
    FINISHER = 'finisher'
    # Accessing predefined RSEs
    XRD = 'xrd'
    WEB = 'web'
