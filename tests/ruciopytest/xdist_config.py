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

import os
import warnings
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    import pytest

    from .profiles import SuiteProfile


def configure_xdist(config: "pytest.Config", profile: "SuiteProfile") -> int:
    """Configure xdist worker count based on suite profile and environment.

    The function applies the following precedence:

    1. If xdist is not installed, return 0 (no parallel execution).
    2. If the suite's RDBMS is not xdist-compatible, disable xdist and
       warn if the user explicitly requested workers via ``--xdist-workers``.
    3. If the user passed ``--xdist-workers=N``, honour that value.
    4. In CI (detected via ``GITHUB_ACTIONS`` or ``CI`` env vars), use
       the profile's ``default_workers_ci``.
    5. Locally, leave ``numprocesses`` as-is so that any ``-n`` the user
       passed on the command line is respected.

    :returns: The effective worker count.
    """
    # Guard: xdist not installed
    if not config.pluginmanager.hasplugin("xdist"):
        return 0

    # RDBMS not compatible with parallel execution
    if not profile.xdist_enabled:
        explicit = config.getoption("xdist_workers", default=None)
        if explicit is not None and explicit > 0:
            warnings.warn(
                f"Suite '{profile.name}' with RDBMS '{profile.rdbms}' does not "
                f"support parallel execution. Ignoring --xdist-workers={explicit}.",
                stacklevel=2,
            )
        config.option.numprocesses = 0
        config.option.dist = "no"
        return 0

    # Explicit --xdist-workers override
    explicit = config.getoption("xdist_workers", default=None)
    if explicit is not None:
        config.option.numprocesses = explicit
        return explicit

    # Auto-detect CI environment
    is_ci = (
        os.environ.get("GITHUB_ACTIONS") == "true"
        or os.environ.get("CI") == "true"
    )
    if is_ci:
        config.option.numprocesses = profile.default_workers_ci
        return profile.default_workers_ci

    # Local: respect whatever the user passed via -n (or xdist default)
    return getattr(config.option, "numprocesses", 0)
