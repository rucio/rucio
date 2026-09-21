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

"""Suite-selection logic tests for the votest branch.

Two things are covered here, both against synthetic inputs so that adding or
removing a file under ``tests/`` never affects these tests:

- :func:`votest_support.collect_votest_paths` correctly applies a policy's
  allow/deny lists (directory expansion, file entries, deny subtraction, and
  silent dropping of entries that don't exist on disk).
- :func:`votest_support.resolve_policy` resolves ``--policy`` over the
  ``POLICY`` env var, and yields ``None`` when neither is set.

Both are **import-free of rucio** and run in plain CI: no live server, no
container. votest selection is pure path math.
"""

from pathlib import Path

from tests.ruciopytest import votest_support

REPO_ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = REPO_ROOT / "etc/docker/test/matrix_policy_package_tests.yml"


def _matrix() -> dict:
    return votest_support.load_matrix(MATRIX_PATH)


def _fake_repo(tmp_path: Path) -> Path:
    """Build a synthetic repo tree with three test files under ``tests/``."""
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    for name in ("test_alpha.py", "test_beta.py", "test_gamma.py"):
        (tests_dir / name).write_text("# synthetic\n")
    # A non-``test_*.py`` file: must never be picked up by directory expansion.
    (tests_dir / "helper.py").write_text("# not a test module\n")
    return tmp_path


def test_votest_selection_allow_list(tmp_path) -> None:
    """Explicit file entries in ``allow`` select exactly those files."""
    repo = _fake_repo(tmp_path)
    matrix = {
        "fake": {
            "tests": {
                "allow": ["rucio_tests/test_alpha.py", "rucio_tests/test_gamma.py"],
                "deny": [],
            }
        }
    }
    assert votest_support.collect_votest_paths(matrix, "fake", repo) == [
        "tests/test_alpha.py",
        "tests/test_gamma.py",
    ]


def test_votest_selection_directory_expansion_minus_deny(tmp_path) -> None:
    """``rucio_tests`` expands to the dir's ``test_*.py``; ``deny`` subtracts."""
    repo = _fake_repo(tmp_path)
    matrix = {
        "fake": {
            "tests": {
                "allow": ["rucio_tests"],
                "deny": ["rucio_tests/test_beta.py"],
            }
        }
    }
    # helper.py is not test_*.py, so expansion skips it; test_beta.py is denied.
    assert votest_support.collect_votest_paths(matrix, "fake", repo) == [
        "tests/test_alpha.py",
        "tests/test_gamma.py",
    ]


def test_votest_selection_drops_nonexistent_entries(tmp_path) -> None:
    """Allow/deny entries with no file on disk are silently dropped.

    Mirrors the real matrix, whose lists carry dead entries (and, for atlas, a
    non-``test_*.py`` entry) that must not break selection.
    """
    repo = _fake_repo(tmp_path)
    matrix = {
        "fake": {
            "tests": {
                "allow": [
                    "rucio_tests/test_alpha.py",
                    "rucio_tests/test_does_not_exist.py",
                    "rucio_tests/helper.py",  # exists, but explicitly named -> kept
                ],
                "deny": ["rucio_tests/test_also_gone.py"],  # dead deny entry
            }
        }
    }
    assert votest_support.collect_votest_paths(matrix, "fake", repo) == [
        "tests/helper.py",
        "tests/test_alpha.py",
    ]


def test_votest_selection_missing_deny_key(tmp_path) -> None:
    """A policy with no ``deny`` key selects its whole allow list."""
    repo = _fake_repo(tmp_path)
    matrix = {"fake": {"tests": {"allow": ["rucio_tests/test_beta.py"]}}}
    assert votest_support.collect_votest_paths(matrix, "fake", repo) == ["tests/test_beta.py"]


def test_policy_resolution() -> None:
    """SUIT-07: --policy flag wins over POLICY env; both-missing -> None.

    Uses a tiny fake config object exposing ``getoption("policy")`` and a dict
    env. Documents the plugin's UsageError contract: votest with a None policy is
    rejected; an unknown policy (not a matrix key) is detectable.
    """

    class FakeConfig:
        def __init__(self, policy):
            self._policy = policy

        def getoption(self, name, default=None):
            assert name == "policy"
            return self._policy if self._policy is not None else default

    # flag wins over env
    assert votest_support.resolve_policy(FakeConfig("atlas"), {"POLICY": "belleii"}) == "atlas"
    # env fallback when no flag
    assert votest_support.resolve_policy(FakeConfig(None), {"POLICY": "belleii"}) == "belleii"
    # both missing -> None (plugin raises UsageError on None for votest)
    assert votest_support.resolve_policy(FakeConfig(None), {}) is None

    # unknown policy is detectable against the data-driven matrix keys
    matrix = _matrix()
    resolved = votest_support.resolve_policy(FakeConfig("nope"), {})
    assert resolved not in matrix
