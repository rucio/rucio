# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Sanity checks for the MANIFEST.*.in files used by tools/build_sdist_wheel.sh
to build the rucio/clients/webui sdists and wheels.

These are plain path-existence checks against the repository working tree,
so they don't require a database or any running services, unlike most of
the rest of the test suite.
"""

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

MANIFEST_FILES = [
    "MANIFEST.client.in",
    "MANIFEST.server.in",
    "MANIFEST.webui.in",
]

# Only "include <path>" and "recursive-include <dir> <patterns>" directives name
# a concrete file or directory that must exist; "prune", "global-exclude" and
# bare "include MANIFEST.in" (which is a distutils convention, not a repo path)
# are intentionally not checked here.
INCLUDE_RE = re.compile(r"^include\s+(?P<path>\S+)\s*$")
RECURSIVE_INCLUDE_RE = re.compile(r"^recursive-include\s+(?P<path>\S+)\s+")


def _referenced_paths(manifest_text):
    """Yield every concrete file/directory path referenced by an
    `include` or `recursive-include` directive in a MANIFEST.*.in file."""
    for line in manifest_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "include MANIFEST.in":
            # Distutils boilerplate, not a path in this repo.
            continue
        m = INCLUDE_RE.match(line)
        if m:
            yield m.group("path")
            continue
        m = RECURSIVE_INCLUDE_RE.match(line)
        if m:
            yield m.group("path")


@pytest.mark.parametrize("manifest_name", MANIFEST_FILES)
def test_manifest_referenced_paths_exist(manifest_name):
    """Every file/directory referenced by `include`/`recursive-include` in a
    MANIFEST.*.in file must actually exist in the repository working tree.

    Regression test for the `script.py.mako` migration template being silently
    dropped from the server sdist/wheel because MANIFEST.server.in referenced
    the old pre-reorganization path `lib/rucio/db/migrate_repo/script.py.mako`
    instead of the current `lib/rucio/db/sqla/migrate_repo/script.py.mako`.
    """
    manifest_path = REPO_ROOT / manifest_name
    manifest_text = manifest_path.read_text()

    missing = []
    for rel_path in _referenced_paths(manifest_text):
        if "*" in rel_path or "?" in rel_path:
            # Glob pattern, e.g. "include bin/*": must match at least one file.
            if not list(REPO_ROOT.glob(rel_path)):
                missing.append(rel_path)
            continue
        # Strip trailing slash used for directories, e.g. "include tests/".
        candidate = REPO_ROOT / rel_path.rstrip("/")
        if not candidate.exists():
            missing.append(rel_path)

    assert not missing, (
        f"{manifest_name} references path(s) that do not exist in the repo: "
        f"{missing}"
    )
