# `bootstrap_dev.sh` usage

The `tools/bootstrap_dev.sh` helper prepares a local Rucio development or test
environment. It can reset a dedicated branch to a requested release or to the
upstream `master`, start Docker Compose profiles, and run the predefined test
suites that ship with the repository.

## Requirements

Run the script from a local Rucio clone with the following tools available:

- `git`
- `docker` with either Docker Compose v1 or v2
- `curl` and `jq` when `--latest` is used

## Invocation

```bash
./tools/bootstrap_dev.sh [options]
```

Short flags (`-r`, `-l`, `-m`, `-p`, `-t`, `-f`, `-c`, `-x`, `-y`, `-h`) mirror
their long variants.

## Options

### Checkout (choose at most one)

- `-r, --release <TAG>` – force the demo branch (default `demo-env`) to the
  upstream release tag `<TAG>`.
- `-l, --latest` – reset the demo branch to the release that matches the Docker
  Hub `latest` digest.
- `-m, --master` – reset the demo branch to the upstream `master` branch.

If no checkout option is set, the existing working tree remains untouched.

### Docker

- `-p, --profile [NAME]` – start the Docker Compose stack. Without `NAME` only
  unprofiled/base services run. Repeat the option to add multiple named
  profiles.
- `-x, --expose-ports` – include `docker-compose.ports.yml` so that services
  publish ports on `127.0.0.1`.

### Other

- `-t, --test <N>` – run test number `N` after bootstrapping. Tests manage the
  Compose lifecycle themselves and cannot be combined with `--profile/-p`.
- `-f, --filter <PYTEST>` – limit the selected test to the provided pytest
  expression.
- `-c, --cache-use` – reuse cached container images. With tests this enables
  autotest image reuse; with profiles it skips `docker compose pull`.
- `-y, --yes` – answer destructive prompts automatically. When an `upstream`
  remote must be created or adjusted, HTTPS is chosen without interaction.
- `-h, --help` – show the synopsis together with the list of discovered tests.

### Notes

1. Checkout flags operate on the demo branch and discard any local changes on
   that branch.
2. Docker Compose runs only when at least one `--profile/-p` argument is given.
3. `--filter/-f` requires `--test/-t`.
4. `--cache-use/-c` must accompany either `--test/-t` or `--profile/-p`.
5. `--expose-ports` merges `docker-compose.ports.yml` and binds services on
   `127.0.0.1`.
6. Tests remove the `dev_vol-ruciodb-data` volume before execution.
7. The script keeps an `upstream` remote pointing at `rucio/rucio`; missing or
   diverging remotes are fixed before checkout.

## Built-in safeguards

Before performing any git or Docker action the script verifies that required
commands are available, that the Docker daemon is reachable, and that the
configured upstream remote targets `rucio/rucio`. Force resets on the demo
branch and the destructive steps executed by the tests are gated by prompts
unless `--yes` is set. When profiles start, previous Compose projects with the
same name are stopped and cleaned up, optional cache reuse is applied, and
Compose v2 users automatically receive the `--pull never` flag. Enabling dry-run
mode via `BOOTSTRAP_DEV_DRY_RUN=1` (or `BOOTSTRAP_DEV_TEST_MODE=1`) logs all
planned git and Docker commands without running them.

## Environment overrides

- `UPSTREAM_REMOTE` – name of the upstream remote (default `upstream`).
- `DEMO_BRANCH` – demo branch name to reset (default `demo-env`).
- `RUCIO_DEV_SKIP_PULL=1` – skip `docker compose pull` while running profiles;
  with Compose v2 this also adds `--pull never` to `docker compose up`.
- `RUCIO_AUTOTEST_REUSE_IMAGES=1` – reuse cached autotest images when running
  tests (same effect as `--cache-use`).
- `BOOTSTRAP_DEV_DRY_RUN=1` or `BOOTSTRAP_DEV_TEST_MODE=1` – parse options and
  report actions without issuing git or Docker commands.

## Examples

### Checkout and profiles

1. Check out a release and start the storage profile:
   ```bash
   ./tools/bootstrap_dev.sh --release 37.4.0 --profile storage
   ./tools/bootstrap_dev.sh -r 37.4.0 -p storage
   ```
2. Check out a release and run only the base services:
   ```bash
   ./tools/bootstrap_dev.sh --release 37.4.0 --profile
   ./tools/bootstrap_dev.sh -r 37.4.0 -p
   ```
3. Start multiple profiles with published ports:
   ```bash
   ./tools/bootstrap_dev.sh --release 37.4.0 --profile storage --profile monitoring --expose-ports
   ./tools/bootstrap_dev.sh -r 37.4.0 -p storage -p monitoring -x
   ```
4. Track `master` while running profiles:
   ```bash
   ./tools/bootstrap_dev.sh --master --profile storage --profile monitoring
   ./tools/bootstrap_dev.sh -m -p storage -p monitoring
   ```
5. Skip image pulls when starting profiles:
   ```bash
   ./tools/bootstrap_dev.sh --master --profile storage --cache-use
   RUCIO_DEV_SKIP_PULL=1 ./tools/bootstrap_dev.sh -m -p storage
   ```
6. Perform only the checkout step:
   ```bash
   ./tools/bootstrap_dev.sh --master
   ./tools/bootstrap_dev.sh -m
   ```
7. Use the release that matches Docker Hub `latest`:
   ```bash
   ./tools/bootstrap_dev.sh --latest --profile storage
   ./tools/bootstrap_dev.sh -l -p storage
   ```
8. Start base services with port exposure while tracking `latest`:
   ```bash
   ./tools/bootstrap_dev.sh --latest --profile --expose-ports
   ./tools/bootstrap_dev.sh -l -p -x
   ```
9. Run base services without checking out a release:
   ```bash
   ./tools/bootstrap_dev.sh --profile
   ./tools/bootstrap_dev.sh -p
   ```
10. Launch base services together with multiple profiles:
    ```bash
    ./tools/bootstrap_dev.sh --profile storage --profile monitoring
    ./tools/bootstrap_dev.sh -p storage -p monitoring
    ```
11. Start a specific profile, for example Postgres 14:
    ```bash
    ./tools/bootstrap_dev.sh --profile postgres14
    ./tools/bootstrap_dev.sh -p postgres14
    ```
12. Start client-focused services:
    ```bash
    ./tools/bootstrap_dev.sh -p client -p externalmetadata -p iam
    ```
13. Work offline with cached images:
    ```bash
    ./tools/bootstrap_dev.sh -p storage -p monitoring --cache-use
    RUCIO_DEV_SKIP_PULL=1 ./tools/bootstrap_dev.sh -p storage -p monitoring
    ```

### Tests (incompatible with profiles)

14. Run the default test suite (drops the dev database volume):
    ```bash
    ./tools/bootstrap_dev.sh --test 1
    ./tools/bootstrap_dev.sh -t 1
    ```
15. Apply a pytest filter to the default suite:
    ```bash
    ./tools/bootstrap_dev.sh --test 1 --filter tests/test_replica.py::test_add_replicas
    ./tools/bootstrap_dev.sh -t 1 -f tests/test_replica.py::test_add_replicas
    ```
16. Run a matrix entry:
    ```bash
    ./tools/bootstrap_dev.sh --test 9
    ./tools/bootstrap_dev.sh -t 9
    ```
17. Combine a matrix entry with a pytest filter:
    ```bash
    ./tools/bootstrap_dev.sh -t 9 -f "tests/test_scope.py::test_scope_duplicate"
    ```
18. Reuse cached autotest images:
    ```bash
    ./tools/bootstrap_dev.sh -t 9 --cache-use
    RUCIO_AUTOTEST_REUSE_IMAGES=1 ./tools/bootstrap_dev.sh -t 9
    ```
19. Check out a release before running tests:
    ```bash
    ./tools/bootstrap_dev.sh -r 37.4.0 -t 1
    ```

### Discovery and help

20. Display the usage summary and the discovered tests:
    ```bash
    ./tools/bootstrap_dev.sh -h
    ```

### Environment override samples

21. Use a different upstream remote name:
    ```bash
    UPSTREAM_REMOTE=origin ./tools/bootstrap_dev.sh -m -p
    ```
22. Override the demo branch name:
    ```bash
    DEMO_BRANCH=my-demo ./tools/bootstrap_dev.sh -r 37.4.0 -p storage
    ```
23. Start profiles offline with port exposure:
    ```bash
    RUCIO_DEV_SKIP_PULL=1 ./tools/bootstrap_dev.sh -p storage -p monitoring -x
    ```

## After starting profiles

When profiles launch the script prints follow-up commands for inspecting
containers, viewing logs, and stopping the stack. Repeat the same profile
options after changing Git branches to ensure the running services match the
checked-out code.

## Dry-run mode

Set `BOOTSTRAP_DEV_DRY_RUN=1` or `BOOTSTRAP_DEV_TEST_MODE=1` to parse options,
log selections, and show the planned git and Docker steps without executing
them.
