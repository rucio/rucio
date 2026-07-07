# ruciopytest

`ruciopytest` is a pytest plugin that runs the Rucio test suites with a single
`pytest` command. You select a suite with `--suite`, and the plugin starts the
containers the suite needs, prepares the database and runs the tests. It is
available alongside the existing `tools/test/test.sh` scripts.

To use it you need Docker with the Compose plugin and a Rucio checkout with the
[development environment](../../etc/docker/dev) set up.

## Quickstart

Run the server-side test suite against PostgreSQL:

```bash
python -m pytest --suite=remote_dbs tests/
```

Run a single test file:

```bash
python -m pytest --suite=remote_dbs tests/test_did.py
```

Without `--suite` the plugin does nothing, and `python -m pytest tests/`
behaves like plain pytest.

## How it works

The `client` suite runs on the host, against a Rucio server that is already
running. No containers are started.

The other suites (`remote_dbs`, `multi_vo`, `votest`) run inside the rucio
container. On the host, the plugin starts the container stack and runs pytest
inside the container with `docker compose exec`. The test results are reported
back to your terminal, and the exit code of the run inside the container becomes
the exit code of your command. Only environment variables starting with
`RUCIO_`, plus `SUITE`, `POLICY`, `RDBMS` and `GITHUB_ACTIONS`, are passed into
the container. Use `--container-env KEY=VALUE` to pass any other variable.

Before the tests run, the database is purged, the schema is rebuilt and the base
VO and root account are created. With `--keep-db` this step is skipped and the
database from the previous run is used.

When you run pytest on the host, the plugin creates a new container stack for
each run and removes it, including the database volume, when the run ends. The
next run therefore starts with an empty database, and there is nothing to keep.
To reuse a database, the stack has to stay up between runs, which is what
`--keep-containers` does. The plugin rejects `--keep-db` on the host without
`--keep-containers`. On the first run with both options the database is built
once; later runs reuse it. You can also run the plugin inside the rucio container of a stack you started
yourself. The plugin then does not start or stop any containers, and the
database keeps running between runs, so `--keep-db` is enough:

```bash
export RDBMS=postgres16   # must match --profile below
C="docker compose -p rucio-dev-tests -f etc/docker/dev/docker-compose.yml -f etc/docker/dev/docker-compose.test.override.yml --profile postgres16"
$C up -d --build --wait rucio
$C exec rucio pip install -e /rucio_source
$C exec rucio bash -c 'for f in /rucio_source/etc/*; do n=$(basename "$f"); [ -e "/opt/rucio/etc/$n" ] || ln -sf "$f" "/opt/rucio/etc/$n"; done; httpd -k graceful'

# The first run builds the database, later runs reuse it.
$C exec -w /rucio_source rucio python -m pytest --suite=remote_dbs tests/test_did.py
$C exec -w /rucio_source rucio python -m pytest --suite=remote_dbs --keep-db tests/test_did.py

# Remove the stack when you are done.
$C down -v
```

`RUCIO_TEST_IMAGE` (default `rucio-test:local`) and `PYTHON` (default `3.9`) are
optional. Tests run without pytest-xdist in this mode, so it suits running a few
test files at a time.

The `multi_vo` suite runs the tests for two VOs, `tst` (testvo1) and `ts2`
(testvo2), one after the other against one shared database. `ts2` only runs if
`tst` passed. To run a single VO locally, set `RUCIO_MULTI_VO_LEG=tst` or
`RUCIO_MULTI_VO_LEG=ts2`.

Suites running in the container use pytest-xdist workers when the database is
`postgres16`. The default is 3 workers on GitHub Actions and `auto` otherwise;
`--xdist-workers` overrides it. Other databases run without xdist. For
`multi_vo`, xdist is used inside each VO run.

`rucio.cfg` is not mounted into the container. The container entrypoint
(`etc/docker/dev/rucio/entrypoint.sh`) generates `/opt/rucio/etc/rucio.cfg` when
the container starts, by merging `etc/docker/test/extra/rucio_autotests_common.cfg`
with the file for the selected database (for example `rucio_postgres16.cfg`).
Environment variables of the form `RUCIO_CFG_<SECTION>_<OPTION>` on the rucio
service are applied last. The matching `alembic.ini` is copied next to it. The
plugin then links any other files from the source `etc/` directory that are
missing in `/opt/rucio/etc`, without replacing existing ones. Two suites change
the generated configuration before restarting httpd: `multi_vo` writes one
configuration per VO to `/opt/rucio/etc/multi_vo/{tst,ts2}/etc/` and enables
multi-VO in `rucio.cfg`, and `votest` rewrites the `[policy]` section for the
selected policy package.

## Suites

| Suite        | Database   | Compose profiles | Runs on   | Tests |
| ------------ | ---------- | ---------------- | --------- | ----- |
| `client`     | postgres16 | none             | host      | `tests/test_clients.py`, `tests/test_bin_rucio.py`, `tests/test_module_import.py` |
| `remote_dbs` | postgres16 | `postgres16`     | container | `tests/`, except `tests/ruciopytest/` |
| `multi_vo`   | postgres16 | `postgres16`     | container | `tests/`, except `tests/ruciopytest/`, for the VOs `tst` and `ts2` |
| `votest`     | postgres16 | `postgres16`     | container | Policy package tests from `matrix_policy_package_tests.yml`. Requires a policy. |

The suite names match the `SUITE` values of `tools/test/test.sh`. `SUITE=sqlite` has no plugin
equivalent; use `tools/test/test.sh` for it.

Set `RDBMS=oracle` or `RDBMS=mysql8` to run a suite against another database.
SQLite is not supported by the plugin.

## Command-line options

The options can be combined with the usual pytest options such as `-k`, `-x`,
`-v` and `--co`.

| Option | Description |
| ------ | ----------- |
| `--suite={client,remote_dbs,multi_vo,votest}` | Test suite to run. |
| `--keep-db` | Keep the database from the previous run (skip purge, rebuild and seed). On the host it requires `--keep-containers`. |
| `--keep-containers` | Reuse a running test stack and leave it running afterwards. |
| `--cleanup` | Remove all `rucio-test-*` container stacks and exit. Does not need `--suite`. |
| `--policy=PKG` | Policy package for `votest`, for example `atlas` or `belleii`. Falls back to the `POLICY` environment variable. |
| `--xdist-workers=N` | Number of xdist workers. Overrides the default. |
| `--infra=PROFILES` | Override the infrastructure of `--suite` with comma-separated compose profiles or service names. Requires `--suite`. |
| `--dry-run` | Show the infrastructure plan and the collected tests without running them. |
| `--dry-run-json` | Print the dry-run report as JSON. Implies `--dry-run`. |
| `--run-in-container` | Run the tests inside the rucio container, also for the `client` suite. |
| `--no-run-in-container` | Run the tests on the host, also for container suites. Results may be unreliable. |
| `--container-env=KEY=VALUE` | Set an environment variable inside the container for the run. Can be repeated. |

If both `--run-in-container` and `--no-run-in-container` are given, the last one
is used.

## Re-running tests quickly

By default, every run starts a new stack, installs the source, builds the
database and removes the stack at the end. This takes over a minute, even for
one test file. To run the same tests repeatedly, keep the stack and the database
between runs, so a re-run only takes as long as the tests themselves:

```bash
# The first run starts the stack and builds the database
python -m pytest --suite=remote_dbs --keep-containers --keep-db tests/test_did.py

# Later runs reuse the stack and the database
python -m pytest --suite=remote_dbs --keep-containers --keep-db tests/test_did.py

# Remove all test stacks when you are done
python -m pytest --cleanup
```

Code changes are picked up between runs: the source is mounted into the
container and installed in editable mode, and httpd is reloaded on every run.
After changing dependencies, the Dockerfile or the configuration files in
`etc/docker/test/extra/`, start a new stack by running `--cleanup` first, since
`rucio.cfg` is only generated when the container starts. If tests behave unexpectedly because of data left from
earlier runs, drop `--keep-db` to rebuild the database in the running stack.

Each suite uses its own stack name, so different suites can run in parallel.

## CI mapping

The CI jobs are defined in
[`simple-autotest.yml`](../../.github/workflows/simple-autotest.yml) and
[`simplify_votests.yml`](../../.github/workflows/simplify_votests.yml). Each leg
runs one `pytest` command, so it can be run locally with the command below. If
`RUCIO_TEST_IMAGE` is not set, the plugin builds the test image locally for
`PYTHON` (default 3.9).

| CI leg | Workflow | Local command |
| ------ | -------- | ------------- |
| `remote_dbs` (py3.9) | `simple-autotest.yml` | `python -m pytest --suite=remote_dbs tests/` |
| `remote_dbs` (py3.10) | `simple-autotest.yml` | `PYTHON=3.10 RUCIO_TEST_IMAGE=rucio-test:py310 python -m pytest --suite=remote_dbs tests/` |
| `remote_dbs-oracle` (py3.9) | `simple-autotest.yml` | `RDBMS=oracle python -m pytest --suite=remote_dbs tests/` (no xdist) |
| `multi_vo` | `simple-autotest.yml` | `python -m pytest --suite=multi_vo tests/` |
| `client` | `simple-autotest.yml` | `python -m pytest --suite=client tests/`, against a running server (see below) |
| `votest-atlas` | `simplify_votests.yml` | `python -m pytest --suite=votest --policy=atlas tests/` |
| `votest-belleii` | `simplify_votests.yml` | `python -m pytest --suite=votest --policy=belleii tests/` |

The py3.10 command uses a separate image tag, so the 3.9 image is kept.

The `client` leg runs on the CI host. The easiest way to run it locally is
inside the rucio container of a running dev stack, after preparing the database
with `tools/run_tests.sh -i`:

```bash
docker exec -it -w /rucio_source dev-rucio-1 python -m pytest --suite=client tests/
```

To reproduce the CI leg exactly, run the commands of the
"Provision rucio server (client)" step in `simple-autotest.yml` and then the
command from the table. That step changes the host with `sudo` (`/etc/hosts`,
`/opt/rucio`, `/etc/grid-security`) and needs port 443, so it is safer to run it
in a VM.

## Troubleshooting

### Tests pass or fail inconsistently with `--keep-db`

Data from a previous run is still in the database. Run again without
`--keep-db`. With `--keep-containers`, the database is rebuilt in the running
stack.

### An environment variable is not set inside the container

Only variables starting with `RUCIO_`, plus `SUITE`, `POLICY`, `RDBMS` and
`GITHUB_ACTIONS`, are passed into the container. Pass other variables with
`--container-env=KEY=VALUE`.

### The containers do not start

Check that Docker is running and that the
[development environment](../../etc/docker/dev) is set up, since the plugin
expects the repository to be mounted at `/rucio_source` in the rucio container.
