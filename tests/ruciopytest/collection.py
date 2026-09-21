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

"""Suite-aware test collection filtering for the Rucio pytest plugin.

This module implements:
- Path and marker-based test filtering via ``pytest_collection_modifyitems``
- ``--infra`` service-to-profile resolution
- Suite inference from infrastructure profiles
- ``--dry-run`` report generation
- Overlap warnings when tests match multiple suites
"""

import fnmatch
import json
from collections import defaultdict

import pytest

from . import delegate_to_container_key, suite_profile_key
from .profiles import SUITE_PROFILES, SuiteProfile

# Service-to-profile resolution map (derived from docker-compose.yml)

_SERVICE_TO_PROFILE: dict[str, str] = {
    # RDBMS profiles (service name = profile name)
    "postgres14": "postgres14",
    "mysql8": "mysql8",
    "oracle": "oracle",
    # Storage profile services
    "fts": "storage",
    "ftsdb": "storage",
    "xrd1": "storage",
    "xrd2": "storage",
    "xrd3": "storage",
    "xrd4": "storage",
    "xrd5": "storage",
    "minio": "storage",
    "ssh1": "storage",
    # External metadata profile services
    "mongo": "externalmetadata",
    "mongo-noauth": "externalmetadata",
    "postgres": "externalmetadata",  # Note: different from postgres14
    "elasticsearch_meta": "externalmetadata",
    # Monitoring profile services
    "logstash": "monitoring",
    "kibana": "monitoring",
    "grafana": "monitoring",
    # IAM profile services
    "iam-db": "iam",
    "indigoiam": "iam",
    "indigoiam-login-service": "iam",
    "keycloak": "iam",
    # Client profile service
    "rucioclient": "client",
}

_KNOWN_PROFILES: frozenset[str] = frozenset({
    "postgres14", "mysql8", "oracle", "storage", "externalmetadata",
    "monitoring", "iam", "client",
})


# Infrastructure resolution


def _resolve_infra(infra_arg: str) -> tuple[set[str], set[str]]:
    """Resolve ``--infra`` argument to (profile_names, raw_service_names).

    Each comma-separated token is resolved:
    - If it is a known profile name, added directly to profiles.
    - If it is a known service name, its profile is looked up.
    - Otherwise, ``ValueError`` is raised.

    :returns: Tuple of (resolved_profile_names, raw_service_names).
    """
    profiles: set[str] = set()
    services: set[str] = set()

    for name in infra_arg.split(","):
        name = name.strip()
        if not name:
            continue
        if name in _KNOWN_PROFILES:
            profiles.add(name)
        elif name in _SERVICE_TO_PROFILE:
            profiles.add(_SERVICE_TO_PROFILE[name])
            services.add(name)
        else:
            raise ValueError(f"Unknown infrastructure: {name!r}")

    return profiles, services


def _infer_suites_from_infra(profiles: set[str]) -> list[SuiteProfile]:
    """Find suites whose compose_profiles overlap with the given profiles.

    :param profiles: Set of resolved compose profile names.
    :returns: List of matching ``SuiteProfile`` instances.
    """
    matching = []
    for suite in SUITE_PROFILES.values():
        if set(suite.compose_profiles) & profiles:
            matching.append(suite)
    return matching


# Item matching


def _item_matches_profile(item: pytest.Item, profile: SuiteProfile) -> bool:
    """Check if a test item matches the suite's collection criteria.

    Matching logic:
    1. If the item's path matches any ``exclude_paths`` pattern, return False.
    2. If the item's path matches any ``test_paths`` pattern (via fnmatch or
       startswith for directory prefixes), it is a path match.
    3. If any of the profile's ``markers`` are present on the item, it is a
       marker match.
    4. Return ``path_match or marker_match``.
    """
    rel_path = str(item.path.relative_to(item.config.rootpath))

    # Check exclude paths first
    for pattern in profile.exclude_paths:
        if fnmatch.fnmatch(rel_path, pattern):
            return False

    # Check include by path
    path_match = any(
        fnmatch.fnmatch(rel_path, pattern) or rel_path.startswith(pattern.rstrip("*"))
        for pattern in profile.test_paths
    )

    # Check include by marker
    marker_match = any(
        item.get_closest_marker(m) is not None
        for m in profile.markers
    ) if profile.markers else False

    return path_match or marker_match


# Overlap detection


def _detect_overlaps(
    items: list[pytest.Item],
    active_profile: SuiteProfile,
) -> dict[str, list[str]]:
    """Detect tests that match multiple suite profiles.

    :returns: Dict mapping "suite1,suite2" overlap keys to lists of test node IDs.
    """
    overlaps: dict[str, list[str]] = defaultdict(list)
    other_profiles = [
        p for p in SUITE_PROFILES.values() if p.name != active_profile.name
    ]

    for item in items:
        matching_others = [
            p.name for p in other_profiles
            if _item_matches_profile(item, p)
        ]
        if matching_others:
            key = f"{active_profile.name},{','.join(sorted(matching_others))}"
            overlaps[key].append(item.nodeid)

    return overlaps


# Collection hook


def pytest_collection_modifyitems(
    session: pytest.Session,
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    """Filter collected tests based on the active suite profile.

    When ``--suite`` or ``--infra`` is active, only tests matching the
    suite's path/marker criteria are kept. Deselected tests are reported
    via the ``pytest_deselected`` hook.
    """
    profile = config.stash.get(suite_profile_key, None)
    if profile is None:
        return  # Plugin dormant

    # Host-side delegation skips filtering (tests collected inside container)
    if config.stash.get(delegate_to_container_key, False):
        return

    selected: list[pytest.Item] = []
    deselected: list[pytest.Item] = []

    for item in items:
        if _item_matches_profile(item, profile):
            selected.append(item)
        else:
            deselected.append(item)

    if deselected:
        config.hook.pytest_deselected(items=deselected)
        items[:] = selected  # MUST modify in-place

    # Overlap warnings
    if selected:
        overlaps = _detect_overlaps(selected, profile)
        if overlaps:
            total_overlap = sum(len(v) for v in overlaps.values())
            suites_involved = set()
            for key in overlaps:
                suites_involved.update(key.split(","))

            msg = (
                f"WARNING: {total_overlap} tests match multiple suites: "
                f"{', '.join(sorted(suites_involved))}"
            )
            tw = _get_terminal_writer(config)
            if tw is not None:
                tw.line()
                tw.line(msg, yellow=True)
                # Show first 5 overlapping test names
                shown = 0
                for test_ids in overlaps.values():
                    for tid in test_ids:
                        if shown >= 5:
                            break
                        tw.line(f"  - {tid}", yellow=True)
                        shown += 1
                    if shown >= 5:
                        break
                remaining = total_overlap - shown
                if remaining > 0:
                    tw.line(f"  ... and {remaining} more", yellow=True)
                tw.line()
            else:
                print(msg)

    # Collect-only or dry-run grouping breakdown
    is_collect_only = config.getoption("collectonly", default=False)
    is_dry_run = config.getoption("dry_run", default=False)
    verbosity = config.getoption("verbose", default=0)

    if (is_collect_only or is_dry_run) and verbosity >= 0:
        _print_collection_breakdown(config, profile, selected)

    # Dry-run report
    _print_dry_run_report(config, profile, selected, deselected)


# Dry-run report


def _print_dry_run_report(
    config: pytest.Config,
    profile: SuiteProfile,
    selected: list[pytest.Item],
    deselected: list[pytest.Item],
) -> None:
    """Print infrastructure plan and test collection summary, then exit.

    Only runs when ``--dry-run`` is active.

    When forwarding is active, ``--dry-run``/``--co`` are forwarded into the
    container; the host does not produce its own dry-run report (Phase 6 /
    FWD-11). The in-container forwarded run has no delegate flag set, so it still
    prints + exits authoritatively inside the container, and that output is
    streamed/replayed to the host.
    """
    if not config.getoption("dry_run", default=False):
        return

    # Defensive: when delegating to the container the host does not own the real
    # collection, so it must never print a host-side dry-run report or raise the
    # early pytest.exit. (pytest_collection_modifyitems already early-returns when
    # delegating, so this is normally unreachable on the host — guard explicitly
    # against future call-path changes.)
    if config.stash.get(delegate_to_container_key, False):
        return  # forwarded dry-run: the in-container pytest produces the authoritative report

    report: dict = {
        "infrastructure": {
            "compose_profiles": list(profile.compose_profiles),
            "rdbms": profile.rdbms,
            "xdist_enabled": profile.xdist_enabled,
        },
        "collection": {
            "selected": len(selected),
            "deselected": len(deselected),
            "test_paths": list(profile.test_paths),
            "exclude_paths": list(profile.exclude_paths),
            "markers": list(profile.markers),
        },
    }

    # Group selected tests by directory
    path_groups: dict[str, int] = defaultdict(int)
    for item in selected:
        rel = str(item.path.relative_to(item.config.rootpath))
        directory = "/".join(rel.split("/")[:2])  # e.g. "tests/test_foo"
        path_groups[directory] += 1

    report["collection"]["by_directory"] = dict(
        sorted(path_groups.items(), key=lambda x: -x[1])
    )

    is_json = config.getoption("dry_run_json", default=False)

    if is_json:
        print(json.dumps(report, indent=2))
    else:
        tw = _get_terminal_writer(config)
        _print = tw.line if tw is not None else print

        _print("")
        _print("=" * 60)
        _print("  Dry Run Report")
        _print("=" * 60)
        _print("")
        _print("  Infrastructure Plan:")
        _print(f"    Compose profiles: {', '.join(profile.compose_profiles) or '(none)'}")
        _print(f"    RDBMS:            {profile.rdbms}")
        _print(f"    xdist enabled:    {profile.xdist_enabled}")
        _print("")
        _print("  Test Collection Summary:")
        _print(f"    Selected:   {len(selected)}")
        _print(f"    Deselected: {len(deselected)}")
        _print(f"    Paths:      {', '.join(profile.test_paths)}")
        if profile.exclude_paths:
            _print(f"    Excluded:   {', '.join(profile.exclude_paths)}")
        if profile.markers:
            _print(f"    Markers:    {', '.join(profile.markers)}")
        _print("")
        _print("  Tests by directory:")
        for directory, count in sorted(path_groups.items(), key=lambda x: -x[1]):
            _print(f"    {directory}: {count}")
        _print("")
        _print("=" * 60)

    raise pytest.exit("Dry run complete", returncode=0)


# Collection breakdown (for --co and --dry-run)


def _print_collection_breakdown(
    config: pytest.Config,
    profile: SuiteProfile,
    selected: list[pytest.Item],
) -> None:
    """Print tests grouped by inclusion reason (path match, marker match)."""
    path_matched: list[str] = []
    marker_matched: list[str] = []

    for item in selected:
        rel_path = str(item.path.relative_to(item.config.rootpath))

        has_path = any(
            fnmatch.fnmatch(rel_path, pattern) or rel_path.startswith(pattern.rstrip("*"))
            for pattern in profile.test_paths
        )
        has_marker = any(
            item.get_closest_marker(m) is not None
            for m in profile.markers
        ) if profile.markers else False

        if has_path:
            path_matched.append(item.nodeid)
        if has_marker and not has_path:
            marker_matched.append(item.nodeid)

    tw = _get_terminal_writer(config)
    _print = tw.line if tw is not None else print

    _print("")
    _print(f"  Collection breakdown for suite '{profile.name}':")
    _print(f"    By path:   {len(path_matched)} tests")
    _print(f"    By marker: {len(marker_matched)} tests")
    _print(f"    Total:     {len(selected)} tests")
    _print("")


# Helpers


def _get_terminal_writer(config: pytest.Config):
    """Get the terminal writer from terminalreporter, or None."""
    reporter = config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        return reporter._tw
    return None
