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

"""Absorbed multi_vo setup helpers for the rucio pytest plugin.

This module reproduces the legacy ``tools/test/test.sh`` multi_vo branch
without depending on the legacy shell scripts or importing
``tools/merge_rucio_configs.py`` (that script runs ``argparse`` at import
time and is therefore not import-safe).

Two pieces are absorbed here:

* :func:`merge_configs` -- a verbatim copy of
  ``tools/merge_rucio_configs.py::merge_configs`` (last-source-wins
  ConfigParser merge + ``RUCIO_CFG_*`` env overrides).
* :func:`generate_multi_vo_configs` -- reproduces the two ``test.sh``
  merges, writing per-VO ``rucio.cfg`` files into the live in-container
  per-VO etc dirs (``/opt/rucio/etc/multi_vo/{tst,ts2}/etc``).
"""

import configparser
import json
import logging
import os
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None


# Absorbed merge_configs (copied verbatim from tools/merge_rucio_configs.py
# lines ~28-134; do NOT import that module -- its top-level argparse runs on
# import). Kept byte-for-byte compatible so multi_vo config generation matches
# legacy test.sh behavior exactly (last-source-wins + RUCIO_CFG_* env override).

# Multi-word sections used in kubernetes are slightly different from what rucio
# expects. Usually it's just a .replace('-', '_'), but not for hermes2.
multi_word_sections = {
    'messaging_fts3': 'messaging-fts3',
    'messaging_cache': 'messaging-cache',
    'messaging_hermes': 'messaging-hermes',
    'messaging_hermes2': 'hermes',
    'nongrid_trace': 'nongrid-trace',
    'tracer_kronos': 'tracer-kronos',
}


def load_flat_config(flat_config):
    """Convert {"section_option": "value"} -> {"section": {"option": "value"}}."""
    config_dict = {}
    for flat_key, config_value in flat_config.items():
        section = option = None
        # Try parsing a multi-word section
        for mw_key in multi_word_sections:
            if flat_key.startswith(mw_key + '_'):
                section = mw_key
                option = flat_key[len(mw_key) + 1:]

        # It didn't match any known multi-word section, assume it's a single word
        if not section:
            section, option = flat_key.split('_', maxsplit=1)

        config_dict.setdefault(section, {})[option] = config_value
    return config_dict


def fix_multi_word_sections(config_dict):
    return {multi_word_sections.get(section, section): config_for_section for section, config_for_section in config_dict.items()}


def config_len(config_dict):
    return sum(len(option) for _, option in config_dict.items())


def merge_configs(source_file_paths, dest_file_path, use_env=True, logger=logging.log):
    """
    Merge multiple configuration sources into one rucio.cfg.
    On conflicting values, relies on the default python's ConfigParser behavior: the value from last source wins.
    Sources can be .ini, .yaml, or .json files. Json is supported as a compromise solution for easier integration
    with kubernetes (because both python and helm natively support it).
    If use_env=True, env variables starting with RUCIO_CFG_ are also merged as the last (highest priority) source.
    """

    parser = configparser.ConfigParser()
    for path in source_file_paths:
        path = Path(path)

        if not path.exists():
            logger(logging.WARNING, "Skipping {}: path doesn't exist".format(path))
            continue

        if path.is_dir():
            file_paths = sorted(p for p in path.iterdir() if not p.name.startswith(".") and p.is_file())
        else:
            file_paths = [path]

        for file_path in file_paths:
            try:
                if file_path.suffix == '.json':
                    with open(file_path, 'r') as f:
                        file_config = fix_multi_word_sections(json.load(f))
                        parser.read_dict(file_config)
                elif yaml and file_path.suffix in ['.yaml', '.yml']:
                    with open(file_path, 'r') as f:
                        file_config = fix_multi_word_sections(yaml.safe_load(f))
                        parser.read_dict(file_config)
                elif path.is_file() or file_path.suffix in ['.ini', '.cfg', '.config']:
                    local_parser = configparser.ConfigParser()
                    local_parser.read(file_path)
                    file_config = {section: {option: value for option, value in section_proxy.items()} for section, section_proxy in local_parser.items()}
                else:
                    logger(logging.WARNING, "Skipping file {} due to wrong extension".format(file_path))
                    continue

                parser.read_dict(file_config)
                logger(logging.INFO, "Merged {} configuration values from {}".format(config_len(file_config), file_path))
            except Exception as error:
                logger(logging.WARNING, "Skipping file {} due to error: {}".format(file_path, error))

    if use_env:
        # env variables use the following format: "RUCIO_CFG_{section.substitute('-','_').upper}_{option.substitute('-', '_').upper}"
        env_config = {}
        for env_key, env_value in os.environ.items():
            rucio_cfg_prefix = 'RUCIO_CFG_'
            if not env_key.startswith(rucio_cfg_prefix):
                continue
            env_key = env_key[len(rucio_cfg_prefix):].lower()  # convert "RUCIO_CFG_WHATEVER" to "whatever"
            env_config[env_key] = env_value

        env_config = fix_multi_word_sections(load_flat_config(env_config))
        parser.read_dict(env_config)
        logger(logging.INFO, "Merged {} configuration values from ENV".format(config_len(env_config)))

    if dest_file_path:
        logger(logging.INFO, "Writing {}".format(dest_file_path))
        with open(dest_file_path, 'w') as dest_file:
            parser.write(dest_file)
    else:
        parser.write(sys.stdout)


# Per-VO config generation (reproduces the two test.sh merges)

# Live in-container per-VO etc dirs. The tst cfg's
# [alembic] cfg=/opt/rucio/etc/multi_vo/tst/etc/alembic.ini line confirms
# these per-VO etc dirs are the ones consumed at runtime (verified destination,
# see RESEARCH Pitfall 4 / Open Q#2).
DEFAULT_TST_ETC = "/opt/rucio/etc/multi_vo/tst/etc"
DEFAULT_TS2_ETC = "/opt/rucio/etc/multi_vo/ts2/etc"

_COMMON_CFG = "etc/docker/test/extra/rucio_autotests_common.cfg"
_TST_SOURCE_CFG = "etc/docker/test/extra/rucio_multi_vo_tst_postgres14.cfg"
_TS2_SOURCE_CFG = "etc/docker/test/extra/rucio_multi_vo_ts2_postgres14.cfg"


def generate_multi_vo_configs(
    repo_root: Path,
    tst_etc_dir: str = DEFAULT_TST_ETC,
    ts2_etc_dir: str = DEFAULT_TS2_ETC,
    use_env: bool = True,
) -> dict[str, str]:
    """Generate the two per-VO ``rucio.cfg`` files (tst, ts2).

    Reproduces the legacy ``test.sh`` multi_vo merges:

    * tst: merge ``rucio_autotests_common.cfg`` + ``rucio_multi_vo_tst_postgres14.cfg``
      into ``<tst_etc_dir>/rucio.cfg`` (vo=testvo1, multi_vo=True).
    * ts2: merge ``rucio_autotests_common.cfg`` + ``rucio_multi_vo_ts2_postgres14.cfg``
      into ``<ts2_etc_dir>/rucio.cfg`` (vo=testvo2, multi_vo=True).

    Parameters
    ----------
    repo_root:
        Repository root holding the ``etc/docker/test/extra/`` source cfgs.
    tst_etc_dir / ts2_etc_dir:
        Destination per-VO etc dirs. Default to the live in-container layout;
        unit tests override with ``tmp_path`` subdirs.
    use_env:
        Apply ``RUCIO_CFG_*`` env overrides (legacy uses ``--use-env``).

    Returns
    -------
    dict
        ``{"tst": <tst rucio.cfg path>, "ts2": <ts2 rucio.cfg path>}``.
    """
    repo_root = Path(repo_root)
    base = repo_root / _COMMON_CFG
    tst_source = repo_root / _TST_SOURCE_CFG
    ts2_source = repo_root / _TS2_SOURCE_CFG

    for src in (base, tst_source, ts2_source):
        if not src.exists():
            raise RuntimeError(f"multi_vo source cfg missing: {src}")

    os.makedirs(tst_etc_dir, exist_ok=True)
    os.makedirs(ts2_etc_dir, exist_ok=True)

    tst_cfg = os.path.join(tst_etc_dir, "rucio.cfg")
    ts2_cfg = os.path.join(ts2_etc_dir, "rucio.cfg")

    try:
        merge_configs([str(base), str(tst_source)], tst_cfg, use_env=use_env)
        merge_configs([str(base), str(ts2_source)], ts2_cfg, use_env=use_env)
    except OSError as e:
        raise RuntimeError(f"failed to write multi_vo configs: {e}") from e

    # Carry over the base cfg's [alembic] section into both generated cfgs.
    #
    # The per-VO source cfgs (rucio_multi_vo_{tst,ts2}_postgres14.cfg) override
    # [alembic] cfg to a per-VO path (e.g. /opt/rucio/etc/multi_vo/tst/etc/
    # alembic.ini). Under the legacy multi_vo docker image those per-VO
    # alembic.ini files exist; the simple-autotest runtime image does NOT create
    # them. Because InfraManager._build_database() runs
    # ``Config(config_get('alembic','cfg')); command.stamp(cfg,'head')``, a cfg
    # pointing at a non-existent alembic.ini yields an alembic Config with no
    # ``script_location`` -> ``CommandError: No 'script_location' key`` -> the
    # whole multi_vo bring-up aborts before any test runs. The base cfg
    # (rucio_autotests_common.cfg) points [alembic] cfg at /opt/rucio/etc/
    # alembic.ini, which DOES exist in the container (remote_dbs builds fine via
    # it). Forcing the base [alembic] back over the per-VO override keeps a valid
    # script_location while the per-VO DB/VO settings (last-source-wins) stay.
    _carry_over_section(base, tst_cfg, "alembic")
    _carry_over_section(base, ts2_cfg, "alembic")

    return {"tst": tst_cfg, "ts2": ts2_cfg}


def _carry_over_section(base_cfg_path, dest_cfg_path, section):
    """Force *section* from *base_cfg_path* into the already-written
    *dest_cfg_path*, overriding whatever the per-VO merge produced.

    No-op when the base cfg lacks the section. Used to restore the base
    ``[alembic]`` (valid ``cfg`` -> existing alembic.ini) after the per-VO
    source overrode it with a path the runtime image never creates.
    """
    base = configparser.ConfigParser()
    base.read(str(base_cfg_path))
    if not base.has_section(section):
        return

    dest = configparser.ConfigParser()
    dest.read(dest_cfg_path)
    if not dest.has_section(section):
        dest.add_section(section)
    # Replace the section wholesale with the base values.
    for option in dest.options(section):
        dest.remove_option(section, option)
    for option, value in base.items(section):
        dest.set(section, option, value)

    with open(dest_cfg_path, "w") as f:
        dest.write(f)
