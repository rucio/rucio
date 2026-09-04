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

"""Unit tests for votest_support (import-free of rucio, no live server)."""

import configparser
from pathlib import Path

from tests.ruciopytest.votest_support import (
    collect_votest_paths,
    load_matrix,
    resolve_policy,
    rewrite_policy_section,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = REPO_ROOT / "etc/docker/test/matrix_policy_package_tests.yml"


def _matrix_entries(matrix, policy, key):
    """Repo-relative paths listed under ``matrix[policy]["tests"][key]``."""
    return {e.replace("rucio_tests", "tests", 1) for e in matrix[policy]["tests"].get(key, [])}


def _real_test_files():
    """Every ``tests/test_*.py`` currently on disk, repo-relative."""
    return {str(p.relative_to(REPO_ROOT)) for p in (REPO_ROOT / "tests").glob("test_*.py")}


def test_collect_votest_paths_atlas():
    """atlas allows the whole ``tests/`` dir minus its deny list.

    Asserts invariants, not a frozen count: the selection must be real files on
    disk, and every deny entry that exists must be excluded.
    """
    matrix = load_matrix(MATRIX_PATH)
    paths = collect_votest_paths(matrix, "atlas", REPO_ROOT)

    assert paths, "atlas selected nothing"
    assert all(p.startswith("tests/") for p in paths)
    assert all(p.endswith(".py") for p in paths)
    assert all((REPO_ROOT / p).is_file() for p in paths), "selected a path that is not on disk"

    denied = _matrix_entries(matrix, "atlas", "deny")
    assert not (set(paths) & denied), "atlas selected a denied file"
    # allow is the whole tests/ dir: everything selected is a real test module.
    assert set(paths) <= _real_test_files()


def test_collect_votest_paths_belleii():
    """belleii allows an explicit file list; dead entries are dropped."""
    matrix = load_matrix(MATRIX_PATH)
    paths = collect_votest_paths(matrix, "belleii", REPO_ROOT)

    assert paths, "belleii selected nothing"
    assert all(p.startswith("tests/") for p in paths)
    assert all(p.endswith(".py") for p in paths)
    assert all((REPO_ROOT / p).is_file() for p in paths), "selected a path that is not on disk"

    allowed = _matrix_entries(matrix, "belleii", "allow")
    denied = _matrix_entries(matrix, "belleii", "deny")
    # Selection is exactly the allow entries that exist on disk, minus deny.
    expected = {p for p in allowed - denied if (REPO_ROOT / p).is_file()}
    assert set(paths) == expected
    assert "tests/test_belleii.py" in paths


def test_collect_votest_paths_policies_differ():
    """The two policies genuinely select different, non-empty suites."""
    matrix = load_matrix(MATRIX_PATH)
    atlas = collect_votest_paths(matrix, "atlas", REPO_ROOT)
    belleii = collect_votest_paths(matrix, "belleii", REPO_ROOT)
    assert atlas and belleii
    assert set(atlas) != set(belleii)
    # Every file atlas denies is absent from atlas but may well be in belleii's
    # allow list -- that asymmetry is the whole point of the per-policy matrix.
    atlas_denied = _matrix_entries(matrix, "atlas", "deny")
    assert not (set(atlas) & atlas_denied)
    assert set(belleii) & atlas_denied, "belleii should allow files atlas denies"


def test_collect_drops_nonexistent(tmp_path):
    # Build a tiny fake repo: tests/ with exactly one real test file.
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_real.py").write_text("# real\n")

    matrix = {
        "fake": {
            "tests": {
                "allow": [
                    "rucio_tests/test_real.py",
                    "rucio_tests/test_missing.py",  # does not exist -> dropped
                ],
                "deny": [],
            }
        }
    }
    paths = collect_votest_paths(matrix, "fake", tmp_path)
    assert paths == ["tests/test_real.py"]


def test_rewrite_policy_section(tmp_path):
    cfg_path = tmp_path / "rucio.cfg"
    cp = configparser.ConfigParser()
    cp["policy"] = {"stale_key": "old_value"}
    cp["client"] = {"vo": "tst"}
    with open(cfg_path, "w") as f:
        cp.write(f)

    rewrite_policy_section(str(cfg_path), {"permission": "atlas", "schema": "atlas"})

    out = configparser.ConfigParser()
    out.read(cfg_path)
    assert dict(out["policy"]) == {"permission": "atlas", "schema": "atlas"}
    assert "stale_key" not in out["policy"]
    # Unrelated section untouched.
    assert dict(out["client"]) == {"vo": "tst"}


def test_rewrite_policy_section_creates_missing(tmp_path):
    cfg_path = tmp_path / "rucio.cfg"
    cp = configparser.ConfigParser()
    cp["client"] = {"vo": "tst"}
    with open(cfg_path, "w") as f:
        cp.write(f)

    rewrite_policy_section(str(cfg_path), {"permission": "belleii"})

    out = configparser.ConfigParser()
    out.read(cfg_path)
    assert dict(out["policy"]) == {"permission": "belleii"}


class _FakeConfig:
    def __init__(self, policy):
        self._policy = policy

    def getoption(self, name, default=None):
        if name == "policy":
            return self._policy
        return default


def test_resolve_policy_flag_wins():
    cfg = _FakeConfig("atlas")
    assert resolve_policy(cfg, {"POLICY": "belleii"}) == "atlas"


def test_resolve_policy_env_fallback():
    cfg = _FakeConfig(None)
    assert resolve_policy(cfg, {"POLICY": "belleii"}) == "belleii"


def test_resolve_policy_none():
    cfg = _FakeConfig(None)
    assert resolve_policy(cfg, {}) is None
