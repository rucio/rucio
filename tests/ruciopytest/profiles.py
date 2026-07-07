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

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional

# RDBMS backends that support xdist parallel execution.
# Only postgres14 is known to handle concurrent test writes reliably.
# sqlite is single-writer, oracle and mysql8 have connection pooling
# constraints in CI that prevent reliable parallel execution.
_XDIST_COMPATIBLE_RDBMS = frozenset({"postgres14"})


@dataclass(frozen=True)
class SuiteProfile:
    """Declarative test suite profile.

    Each profile captures all the configuration needed to run a specific
    test suite: which RDBMS backend, which docker-compose profiles to
    activate, whether xdist parallel execution is supported, default
    worker counts, test paths, markers, and extra environment variables.
    """

    name: str
    rdbms: str
    compose_profiles: tuple[str, ...] = ()
    xdist_enabled: bool = True
    run_in_container: bool = True
    default_workers_ci: int = 3
    default_workers_local: str = "auto"
    test_paths: tuple[str, ...] = ("tests/",)
    markers: tuple[str, ...] = ()
    exclude_paths: tuple[str, ...] = ()
    env_vars: dict[str, str] = field(default_factory=dict)
    policy: "Optional[str]" = None


# Suite profile registry

SUITE_PROFILES: dict[str, SuiteProfile] = {
    "remote_dbs": SuiteProfile(
        name="remote_dbs",
        rdbms="postgres14",
        compose_profiles=("postgres14",),
        xdist_enabled=True,
        run_in_container=True,
        default_workers_ci=3,
        default_workers_local="auto",
        test_paths=("tests/",),
        exclude_paths=("tests/ruciopytest/*",),
    ),
    "multi_vo": SuiteProfile(
        name="multi_vo",
        rdbms="postgres14",
        compose_profiles=("postgres14",),
        xdist_enabled=True,
        run_in_container=True,
        default_workers_ci=3,
        default_workers_local="auto",
        test_paths=("tests/",),
        exclude_paths=("tests/ruciopytest/*",),
        env_vars={"RUCIO_HOME": "/opt/rucio/etc/multi_vo/tst"},
    ),
    "client": SuiteProfile(
        name="client",
        rdbms="postgres14",
        compose_profiles=(),
        xdist_enabled=True,
        run_in_container=False,
        default_workers_ci=3,
        default_workers_local="auto",
        test_paths=(
            "tests/test_clients.py",
            "tests/test_bin_rucio.py",
            "tests/test_module_import.py",
        ),
    ),
    "votest": SuiteProfile(
        name="votest",
        rdbms="postgres14",
        compose_profiles=("postgres14",),
        xdist_enabled=True,
        run_in_container=True,
        default_workers_ci=3,
        default_workers_local="auto",
        test_paths=("tests/",),
        exclude_paths=("tests/ruciopytest/*",),
    ),
}


def resolve_profile(
    suite_name: str,
    rdbms_override: "Optional[str]" = None,
) -> SuiteProfile:
    """Resolve a suite profile, optionally overriding the RDBMS.

    :param suite_name: One of the registered suite names (remote_dbs,
        multi_vo, client, votest).
    :param rdbms_override: If provided, replaces the profile's default RDBMS
        and recalculates xdist compatibility. Used by CI matrix builds
        that run the same suite against different backends.
    :returns: A ``SuiteProfile`` instance (possibly with overridden RDBMS).
    :raises ValueError: If *suite_name* is not in the registry.
    """
    if suite_name not in SUITE_PROFILES:
        raise ValueError(
            f"Unknown suite: {suite_name!r}. "
            f"Available: {sorted(SUITE_PROFILES.keys())}"
        )

    profile = SUITE_PROFILES[suite_name]

    if rdbms_override is not None:
        xdist_enabled = rdbms_override in _XDIST_COMPATIBLE_RDBMS
        profile = SuiteProfile(
            name=profile.name,
            rdbms=rdbms_override,
            compose_profiles=(rdbms_override,) if rdbms_override != "sqlite" else (),
            xdist_enabled=xdist_enabled,
            run_in_container=profile.run_in_container,
            default_workers_ci=profile.default_workers_ci if xdist_enabled else 0,
            default_workers_local=profile.default_workers_local if xdist_enabled else "0",
            test_paths=profile.test_paths,
            markers=profile.markers,
            exclude_paths=profile.exclude_paths,
            env_vars=profile.env_vars,
            policy=profile.policy,
        )

    return profile
