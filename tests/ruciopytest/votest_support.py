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

"""votest support: POLICY-driven test selection and rucio.cfg policy rewrite.

This module absorbs the logic that legacy ``tools/test/votest_helper.py``
performed for the votest branch of ``tools/test/test.sh``:

- :func:`load_matrix` reads ``etc/docker/test/matrix_policy_package_tests.yml``.
- :func:`collect_votest_paths` reimplements ``collect_tests`` exactly, emitting
  **repo-relative** ``tests/test_X.py`` paths, silently dropping allow/deny
  entries that don't exist on disk (parity-critical).
- :func:`rewrite_policy_section` reimplements ``persist_config_overrides``: it
  wipes and rewrites the ``[policy]`` section of the active ``rucio.cfg``.
- :func:`resolve_policy` resolves the policy from ``--policy`` (flag wins) with
  a ``POLICY`` env-var fallback.

All functions are pure / import-free of rucio so they can be unit tested without
a live server or container.
"""

import configparser
import glob
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Optional


def load_matrix(matrix_path: "Path") -> dict:
    """Parse ``matrix_policy_package_tests.yml`` into a dict.

    :param matrix_path: Path to the matrix YAML file.
    :returns: The parsed mapping of policy name -> policy config.
    """
    with open(matrix_path) as f:
        return yaml.safe_load(f)


def collect_votest_paths(matrix: dict, policy: str, repo_root: "Path") -> "list[str]":
    """Compute the repo-relative test set for a votest policy.

    Faithfully reimplements ``tools/test/votest_helper.py::collect_tests``:

    - The keyword ``rucio_tests`` maps to the ``tests/`` directory.
    - A directory entry expands via glob to its ``test_*.py`` files.
    - A file entry that exists on disk is kept.
    - An entry that resolves to neither an existing dir nor file is **silently
      dropped** (parity-critical: belleii's allow list has dead entries and
      atlas's allow includes ``rucioxdist.py`` which is not a ``test_*.py``).

    The selected set is ``allow_paths - deny_paths``. Paths are emitted
    repo-relative (``tests/test_X.py``), never absolute, so the collection
    matcher (which compares against rootdir-relative paths) matches.

    :param matrix: The parsed matrix mapping (see :func:`load_matrix`).
    :param policy: The policy name (e.g. ``"atlas"``, ``"belleii"``).
    :param repo_root: The rucio repository root.
    :returns: A sorted list of repo-relative test paths (deterministic baseline).
    """
    cfg = matrix[policy]["tests"]

    def resolve(entries: "list[str]") -> "set[str]":
        out: set[str] = set()
        for e in entries:
            rel = e.replace("rucio_tests", "tests") if e.startswith("rucio_tests") else e
            p = repo_root / rel
            if p.is_dir():
                from pathlib import Path

                for g in glob.glob(f"{p}/test_*.py"):
                    out.add(str(Path(g).relative_to(repo_root)))
            elif p.is_file():
                out.add(rel)
            # else: silently drop (entry doesn't exist on disk)
        return out

    allow = resolve(cfg.get("allow", []))
    deny = resolve(cfg.get("deny", []))
    return sorted(allow - deny)


def rewrite_policy_section(rucio_cfg: str, config_overrides: dict) -> None:
    """Wipe and rewrite the ``[policy]`` section of ``rucio.cfg``.

    Reimplements ``persist_config_overrides``: read the existing cfg, clear the
    ``[policy]`` section entirely, set only the override keys, write back. Other
    sections are preserved untouched.

    :param rucio_cfg: Path to the live ``rucio.cfg``.
    :param config_overrides: Mapping of policy keys to set under ``[policy]``.
    """
    cp = configparser.ConfigParser()
    cp.read(rucio_cfg)
    if "policy" not in cp:
        cp.add_section("policy")
    cp["policy"].clear()
    for k, v in config_overrides.items():
        cp["policy"][k] = str(v)
    with open(rucio_cfg, "w") as f:
        cp.write(f)


def resolve_policy(config, env) -> "Optional[str]":
    """Resolve the votest policy: ``--policy`` flag wins over ``POLICY`` env.

    :param config: A pytest config exposing ``getoption("policy", default=None)``.
    :param env: A mapping (typically ``os.environ``) consulted for ``POLICY``.
    :returns: The resolved policy name, or ``None`` if neither is set.
    """
    return config.getoption("policy", default=None) or env.get("POLICY")
