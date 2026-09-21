# ruciopytest — the Rucio test-suite pytest plugin

`ruciopytest` is a pytest plugin that runs Rucio's test suites with a single
`pytest` command. It replaces the legacy `tools/test/test.sh` driver: no shell
scripts, no CI matrix parsing, and no manual `docker compose` container
management. You pick a suite with `--suite=...`, and the plugin resolves the
right database backend, brings up (or reuses) the containers it needs, forwards
execution into the Rucio container when required, and mirrors the results back
to your terminal.

**Assumptions.** This guide assumes you already have Docker (with the Compose
plugin) installed and a working Rucio development checkout. If you don't, set up
the [dockerized dev environment](../../etc/docker/dev) first and read the
project [CONTRIBUTING](https://rucio.cern.ch/documentation/contributing)
guidelines. This README does not re-explain installing Docker or bootstrapping
the repo — it explains the plugin.

Everything below is grounded in the actual plugin source:
[`plugin.py`](plugin.py) (CLI options), [`profiles.py`](profiles.py) (suite
table), [`forwarding.py`](forwarding.py) (host-vs-container),
[`multi_vo_support.py`](multi_vo_support.py) (multi-VO), and
[`.github/workflows/simple-autotest.yml`](../../.github/workflows/simple-autotest.yml)
(the CI matrix).

## Contents

- [Quickstart](#quickstart)
- [How it works](#how-it-works)
- [Suite table](#suite-table)
- [CLI reference](#cli-reference)
- [Examples](#examples)
- [CI mapping](#ci-mapping)
- [Migrating from test.sh](#migrating-from-testsh)
- [Troubleshooting](#troubleshooting)

## Quickstart

Run your first suite in ~30 seconds. The `client` suite runs entirely on the
host (no container to wait for), so it's the fastest way to see the plugin work
end to end:

```bash
python -m pytest --suite=client tests/
```

That command runs the client-library tests (`tests/test_clients.py`,
`tests/test_bin_rucio.py`, `tests/test_module_import.py`) against a running
Rucio server. When you're ready for a full server-side run against PostgreSQL,
switch to a forwarded suite — the plugin will start the container for you:

```bash
python -m pytest --suite=remote_dbs tests/
```

> The plugin is **dormant** until you pass `--suite` (or `--infra`). A plain
> `python -m pytest tests/` with neither flag behaves like stock pytest and does
> not touch containers or the database.

## How it works

Read this before the reference — the flags make a lot more sense once you have
the mental model.

### Host execution vs container forwarding

Every suite has a **default execution mode** driven by its `run_in_container`
profile flag ([`profiles.py`](profiles.py)):

- **Host suites** (`client`) run pytest directly on your machine, against an
  externally managed Rucio server. No containers are started.
- **Forwarded suites** (`remote_dbs`, `multi_vo`, `votest`) re-run pytest
  *inside* the Rucio container. On the host, the plugin starts the container
  stack, suppresses host-side collection, and delegates the whole run into the
  container via `docker compose exec`. Each in-container test report is streamed
  back and replayed natively, so N container tests surface as N results in your
  terminal and the container's exit code becomes your exit code
  ([`forwarding.py`](forwarding.py)).

You can override the default with `--run-in-container` (force forwarding) or
`--no-run-in-container` (force host execution). Forcing a normally-forwarded
suite onto the host prints a loud warning — results may be unreliable because
the host environment lacks the container's services.

**Env crossing the boundary.** Only environment variables prefixed with
`RUCIO_` (plus `SUITE`, `POLICY`, `RDBMS`, `GITHUB_ACTIONS`, and anything you
add with `--container-env KEY=VALUE`) are forwarded into the container
(`_ENV_ALLOWLIST_PREFIXES = ("RUCIO_",)` in [`forwarding.py`](forwarding.py)).
Arbitrary host env does **not** leak in.

### Database lifecycle

Each run purges the database, rebuilds the schema, and re-seeds the base VO /
root account before tests execute (`InfraManager.setup()` in
[`infra_manager.py`](infra_manager.py)). Pass `--keep-db` to skip that entire
purge/rebuild/seed cycle and reuse the database from the previous run — much
faster for iterating, at the cost of potentially stale state.

### Multi-VO

The `multi_vo` suite exercises two virtual organisations: `tst` (`testvo1`) and
`ts2` (`testvo2`). It generates a per-VO `rucio.cfg` under
`/opt/rucio/etc/multi_vo/{tst,ts2}/etc` ([`multi_vo_support.py`](multi_vo_support.py))
and, by default, runs both VOs. The `RUCIO_MULTI_VO_LEG` environment variable is a
local/dev override that selects a single VO leg (`tst` or `ts2`). CI leaves it
**unset**, so both VOs run sequentially on one shared DB: `tst` first, then `ts2`
only if `tst` passed (see [`infra_manager.py`](infra_manager.py) `run_multi_vo`).
When unset or set to an unrecognized value, both VOs run sequentially.

### Forwarded xdist (parallel workers)

Forwarded suites that declare `xdist_enabled` on a parallel-capable backend get
pytest-xdist workers injected automatically inside the container
(`build_forward_xdist_args` in [`forwarding.py`](forwarding.py)). Only
`postgres14` is xdist-compatible — SQLite is single-writer, and Oracle/MySQL hit
connection limits under load. The worker count defaults to 3 on CI
(`GITHUB_ACTIONS=true`) and `auto` locally; `--xdist-workers=N` overrides it.
(`multi_vo` is the exception: its per-VO child processes own their own xdist, so
the outer forwarded run is not parallelized.)

## Suite table

Four suites are registered in the plugin (`SUITE_PROFILES` in
[`profiles.py`](profiles.py)):

| Suite        | RDBMS backend | Compose/container profiles | Default execution mode | What it covers |
| ------------ | ------------- | -------------------------- | ---------------------- | -------------- |
| `client`     | postgres14    | none (`()`)                | **host-side**          | Client-library tests only: `tests/test_clients.py`, `tests/test_bin_rucio.py`, `tests/test_module_import.py`. Runs on the host against a running server. |
| `remote_dbs` | postgres14    | `postgres14`               | **forwarded**          | Full server-side test suite (`tests/`, excluding `tests/ruciopytest/*`) against the RDBMS. The main correctness suite. |
| `multi_vo`   | postgres14    | `postgres14`               | **forwarded**          | Full suite run under multi-VO configuration for two VOs (`tst`=testvo1, `ts2`=testvo2). Verifies VO isolation. |
| `votest`     | postgres14    | `postgres14`               | **forwarded**          | Policy-package tests selected from `matrix_policy_package_tests.yml`; requires a policy (`--policy=atlas` / `belleii`, or the `POLICY` env). |

> **Note:** SQLite is **not** a plugin suite — it was descoped in Phase 8. Only
> `postgres14` remains, and it is the only xdist-compatible backend. SQLite
> still exists in the legacy `tools/test/test.sh` driver, but not here.

## CLI reference

All options below live in the `rucio` option group registered by
`pytest_addoption` in [`plugin.py`](plugin.py). They combine with any standard
pytest flag — notably `--co` (collect-only), `-k`, `-m`, `-x`, `-v`.

| Flag | Argument | Default | Effect |
| ---- | -------- | ------- | ------ |
| `--suite` | `{client,remote_dbs,multi_vo,votest}` | `None` | Test suite to run. The plugin is **dormant** if neither `--suite` nor `--infra` is given. |
| `--keep-db` | *(flag)* | `False` | Keep the database from the previous run (skip purge/rebuild/seed). |
| `--policy` | `PKG` | `None` | votest policy package (e.g. `atlas`, `belleii`); falls back to the `POLICY` env var. Required for `--suite=votest`. |
| `--xdist-workers` | `N` (int) | `None` | Number of xdist workers, overriding auto-detection (3 on CI, `auto` locally). |
| `--infra` | `STR` | `None` | Override infrastructure: comma-separated compose profiles or service names. Can run without `--suite` (suites are inferred) or with it (suite's tests, overridden infra). |
| `--dry-run` | *(flag)* | `False` | Show the infrastructure plan and test collection **without executing** tests. |
| `--dry-run-json` | *(flag)* | `False` | Emit the dry-run report as JSON (implies `--dry-run`). |
| `--run-in-container` | *(flag)* | `None` | Force forwarding execution **into** the Rucio container, even for a host suite. |
| `--no-run-in-container` | *(flag)* | `None` | Force running on the **host** even for a container suite (prints a warning; results may be unreliable). |
| `--container-env` | `KEY=VALUE` | `[]` | Set an arbitrary env var inside the container for the forwarded run. Repeatable. |

`--run-in-container` / `--no-run-in-container` share one destination — the last
one wins, and neither is forwarded into the container (they only decide *where*
the run happens).

A few non-obvious flags, at a glance (full worked examples are in
[Examples](#examples)):

```bash
# --infra: run the standard suite but point it at an explicit compose profile.
python -m pytest --infra=postgres14 tests/

# --container-env: inject an env var into the forwarded in-container run.
python -m pytest --suite=remote_dbs --container-env=RUCIO_LOG_LEVEL=DEBUG tests/

# --policy: required to select the votest policy package.
python -m pytest --suite=votest --policy=atlas tests/
```

## Examples

One standalone example per mode — jump to the one you need. Output is shown only
for `--co` and `--dry-run` (where it clarifies behavior); ordinary run commands
omit output to avoid staleness.

### Host-side run

Runs on your machine against an already-running server. Fastest feedback, no
container startup:

```bash
python -m pytest --suite=client tests/
```

### Forwarded run

Executes inside the Rucio container (the plugin starts it for you). Use this for
the full server-side suite:

```bash
python -m pytest --suite=remote_dbs tests/
```

Force a forwarded suite onto the host instead (debugging only — the host lacks
the container's services, so results may be unreliable and you'll see a
warning):

```bash
python -m pytest --suite=remote_dbs --no-run-in-container tests/
```

### Reuse the database with `--keep-db`

Skip the purge/rebuild/seed cycle and reuse the previous run's database — great
for fast iteration. Tradeoff: leftover state from the prior run can make tests
pass or fail spuriously, so drop `--keep-db` when in doubt:

```bash
python -m pytest --suite=remote_dbs --keep-db tests/
```

### Override infrastructure with `--infra`

`--infra` takes comma-separated compose profiles or service names. Use it alone
(the plugin infers the suites that match the infra) or with `--suite` (the
suite's tests, but the infrastructure you name):

```bash
# Bring up the postgres14 profile and run whatever suites match it.
python -m pytest --infra=postgres14 tests/

# Keep the remote_dbs test set, override the infrastructure.
python -m pytest --suite=remote_dbs --infra=postgres14 tests/
```

### Inject env into the container with `--container-env`

Only `RUCIO_`-prefixed host env crosses into the forwarded container; use
`--container-env` (repeatable) to push any other variable in for the run:

```bash
python -m pytest --suite=remote_dbs \
  --container-env=RUCIO_LOG_LEVEL=DEBUG \
  --container-env=MY_FLAG=1 tests/
```

### Select a policy with `--policy`

`votest` requires a policy package; `--policy` wins over the `POLICY` env var:

```bash
python -m pytest --suite=votest --policy=atlas tests/
```

### Preview collection with `--co`

Standard pytest collect-only — list what *would* run without executing. For a
forwarded suite the listing comes from inside the container (the authoritative
source). Illustrative output:

```bash
$ python -m pytest --suite=votest --policy=atlas --co tests/
# ...
<Module tests/test_policy_atlas.py>
  <Function test_atlas_permission_add_rule>
  <Function test_atlas_scope_naming>
# ... (illustrative — actual list depends on the selected policy)
```

### Preview the full plan with `--dry-run`

`--dry-run` prints the infrastructure plan *and* the test collection without
running anything. Add `--dry-run-json` for a machine-readable report.
Illustrative output:

```bash
$ python -m pytest --suite=multi_vo --dry-run tests/
============ Rucio Test Suite Configuration ============
  Suite:          multi_vo
  RDBMS:          postgres14
  xdist enabled:  True
  ...
# infra plan + collected tests listed, nothing executed
# (illustrative — exact fields depend on the resolved profile)
```

## CI mapping

The `.github/workflows/simple-autotest.yml` `test` job runs one leg per matrix
entry. Each leg is just a `python -m pytest --suite=<suite> ... tests/`
invocation with a handful of env vars — so any failing leg reproduces locally
with the equivalent command below.

| CI leg | Env the workflow sets | Equivalent local command |
| ------ | --------------------- | ------------------------ |
| `remote_dbs` (py3.9) | `RDBMS=postgres14 PYTHON=3.9` | `python -m pytest --suite=remote_dbs tests/` |
| `remote_dbs` (py3.10) | `RDBMS=postgres14 PYTHON=3.10` | `python -m pytest --suite=remote_dbs tests/` (py3.10 image) |
| `multi_vo` | `RDBMS=postgres14 PYTHON=3.9` | `python -m pytest --suite=multi_vo tests/` (runs tst then ts2 sequentially, shared DB) |
| `client` | `RDBMS=postgres14 PYTHON=3.9` | `python -m pytest --suite=client tests/` |

Notes for reproducing a leg:

- **`multi_vo` is a single sequential leg** (legacy parity): one runner job with
  one compose stack running both VOs against **one shared instance/DB** — `tst`
  first, then `ts2` only if `tst` passed. CI leaves `RUCIO_MULTI_VO_LEG` **unset**
  (no `vo:` field in the matrix), so `run_multi_vo()` takes the sequential
  shared-DB path, matching legacy `run_multi_vo_tests_docker.sh`. Accepted
  trade-off: no cross-VO parallelism, so multi_vo is the ~35 min long-pole — the
  8.1 wall-time win is deliberately traded for legacy-faithful shared-DB
  correctness. `RUCIO_MULTI_VO_LEG=tst|ts2` remains a local/dev single-VO
  override. See `simple-autotest.yml` around the `matrix.include` block.
- **Forwarded suites get xdist workers injected** inside the container (3 on CI
  via `GITHUB_ACTIONS=true`), so `remote_dbs` runs its tests in parallel inside
  the container. (The `votest` legs, which also get xdist, run in the separate
  `simplify_votests.yml` workflow — see below.)
- **`votest` is NOT in `simple-autotest.yml`** — the policy-package (votest) legs
  run in the dedicated `.github/workflows/simplify_votests.yml` workflow (a
  per-policy matrix of `atlas` and `belleii`, on pull_request + push +
  workflow_dispatch + nightly schedule). To reproduce a votest leg locally:
  `python -m pytest --suite=votest --policy=<atlas|belleii> tests/`.
- The full CI invocation adds reporting flags —
  `--junitxml=test-results/<leg>-py<py>.xml -r fExX --log-level=DEBUG -v
  --tb=short` — which you can append locally but aren't needed to reproduce a
  failure.
- The `client` leg runs **host-side** on the runner, with an automatic
  in-container fallback if the provisioned server is unreachable.

## Migrating from test.sh

The plugin is a drop-in for `tools/test/test.sh`. If you know the legacy
`SUITE=...` invocations, here's the mapping (grounded in `tools/test/test.sh`):

- `SUITE=client` → `python -m pytest --suite=client tests/`
- `SUITE=votest` → `python -m pytest --suite=votest --policy=<pkg> tests/`
- `SUITE=multi_vo` → `python -m pytest --suite=multi_vo tests/` (runs both VOs; a
  single leg via `RUCIO_MULTI_VO_LEG=tst|ts2`)
- `SUITE=remote_dbs` → `python -m pytest --suite=remote_dbs tests/`

The legacy `SUITE=sqlite` has **no** plugin equivalent — SQLite was descoped from
the plugin (only `postgres14` remains). It still exists in `test.sh` if you need
it.

## Troubleshooting

### Stale results after `--keep-db`

- **Symptom:** tests pass/fail inconsistently, or data from a previous run
  lingers.
- **Cause:** `--keep-db` skipped the purge/rebuild/seed cycle, so leftover DB
  state carried over.
- **Fix:** re-run **without** `--keep-db` to get a clean database.

### Container env var not taking effect

- **Symptom:** an env var you set on the host isn't visible inside the forwarded
  run.
- **Cause:** only `RUCIO_`-prefixed vars (plus `SUITE`/`POLICY`/`RDBMS`/
  `GITHUB_ACTIONS`) cross into the container.
- **Fix:** prefix it with `RUCIO_`, or pass it explicitly with
  `--container-env=KEY=VALUE`.

### Wrong VO / multi-VO config issues

- **Symptom:** a `multi_vo` run exercises the wrong VO, or you want just one.
- **Cause:** `RUCIO_MULTI_VO_LEG` is set to a specific leg (`tst`/`ts2`) when you
  wanted both, or is unset / set to an unrecognized value (which runs both VOs
  sequentially) when you wanted just one.
- **Fix:** set `RUCIO_MULTI_VO_LEG=tst` or `=ts2` to select the leg; leave it
  unset to run both.

### Container won't start

- **Symptom:** the run aborts before tests, or a bind-mount / compose error
  appears.
- **Cause:** Docker isn't running, the dev runtime image isn't built, or the
  needed compose profile isn't available. Forwarding also requires the repo
  bind-mounted at `/rucio_source`.
- **Fix:** ensure Docker is up, build/pull the dev runtime image, and use the
  [dockerized dev environment](../../etc/docker/dev) so the `/rucio_source`
  mount and compose profiles exist. A stale-image warning during forwarding
  hints you should rebuild.
