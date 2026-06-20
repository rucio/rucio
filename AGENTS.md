# AGENTS.md

Guidance for AI coding agents — and the humans driving them — contributing to
Rucio. The authoritative references are the
[contribution guide](https://rucio.cern.ch/documentation/contributing) and the
[Rucio AI Policy](https://rucio.cern.ch/documentation/developer/dev_ai_policy);
this file summarises them and adds the practical commands you need. **If anything
here conflicts with the online documentation, the documentation wins.**

## ⚠️ AI Policy — read this first

Rucio has an explicit
[AI Policy](https://rucio.cern.ch/documentation/developer/dev_ai_policy) that
**every contributor must follow** when using AI tools to produce code,
documentation, or any other contribution. If you are an AI agent (or using one),
these rules are binding:

1. **AI use is permitted** — *you MAY use AI tools for contributing to Rucio, as
   long as you follow the principles below.*
2. **Disclosure is mandatory** — *you MUST disclose the usage of AI tools.* This
   applies to any pull request **and** any other communication in the project
   (issues, comments, mailing lists, etc.). State clearly in the PR description
   that AI tools were used and how.
3. **You are fully responsible** — *you MUST take full responsibility for your
   contributions* and *MUST understand and be able to explain the details of all
   changes.* The goal *MUST be to create better-quality code, not to create code
   faster.* Do not open a PR you cannot explain line by line.
4. **Human review is required** — *code review MUST be done by a human.* You MAY
   use AI tools **in addition to** a full human review cycle, never as a
   replacement for it.

The intent: avoid shifting review burden and "comprehension debt" onto
maintainers. Low-quality, unexplained, AI-generated PRs are unwelcome regardless
of whether they pass CI. When in doubt, do less, understand more, and disclose.

## Contribution workflow

Rucio uses a fork-and-pull-request model. Read the full
[contribution guide](https://rucio.cern.ch/documentation/contributing) before
your first PR — the essentials:

### 1. Set up your fork

```bash
git clone https://github.com/<your-user>/rucio.git && cd rucio
git remote add upstream https://github.com/rucio/rucio.git
tools/configure_git.sh    # adds upstream + installs the prepare-commit-msg hook
pre-commit install        # installs the lint hooks (see below)
```

Add your name and organisation to the contributors list ([AUTHORS.rst](AUTHORS.rst)).

### 2. Open an issue first

**No pull request is merged without an associated GitHub issue** — release notes
are generated from issues. The issue should describe the motivation, the proposed
modification, and the expected result.

### 3. Create a branch

Branch from an up-to-date `upstream/master`. Helper scripts encode the naming
convention and set the upstream tracking for you:

```bash
tools/create-feature-branch <issue-number> <name>   # new functionality
tools/create-patch-branch   <issue-number> <name>   # bug fix / hotfix
```

### 4. Commit using Conventional Commits

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

<optional body>

Closes: #<issue-number>
```

- **Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `ci`, `revert`
  (`chore` is also used for tooling/dependency bumps).
- **Scopes** (pick the most specific): `Auth`, `Clients`, `Consistency`, `Core`,
  `Database`, `DatasetDeletion`, `Deletion`, `DIRAC`, `Containerization`,
  `Documentation`, `LifetimeModel`, `Messaging`, `Metadata`, `Monitoring`,
  `MultiVO`, `OpenData`, `Policies`, `Probes`, `Protocols`, `Rebalancing`,
  `Recovery`, `Replicas`, `API`, `Rules`, `Subscriptions`, `Testing`,
  `Transfers`, `WebUI`.
- **Issue trailer:** include `Closes: #<issue>` (closes the issue) or
  `Issue: #<issue>` (references it without closing).
- **Breaking changes:** append `!` after the scope and add a `BREAKING CHANGE:`
  footer, e.g. `feat(API)!: remove auto OIDC flow from gateway and REST`.

Real examples from history: `fix(Core): handle sign-gcs account attribute`,
`test(Deletion): Add test for reaper generating DID detachment messages`,
`feat(Clients)!: Remove lifetime-exception from default endpoints`.

> Note: the local `tools/prepare-commit-msg` hook may template an older message
> format — the Conventional Commits format above (matching current `master`
> history) is the one to use.

### 5. Open the pull request

- **Target branch:** always `master` (the next release). Maintainers cherry-pick
  fixes to maintained release branches; do **not** target release branches
  yourself.
- **PR title:** `<component>: <short change message> #<issue-number>`.
- Fill out the [PR template](.github/PULL_REQUEST_TEMPLATE.md) completely.
- Keep each PR focused on a **single objective**; split unrelated changes into
  separate PRs. Squash/amend to avoid noisy intermediate commits.
- **Disclose AI usage** in the description (see the [AI Policy](#️-ai-policy--read-this-first)).

### 6. Review and merge

- All CI (tests, lint, type checks) must pass.
- A human from the Rucio development team reviews the PR; the merge team merges it
  after a second review. Stale PRs are closed automatically.

## Project overview

Rucio is a Python framework for organising, managing, and accessing large volumes
of scientific data across globally distributed, heterogeneous storage (used by
ATLAS and many other scientific communities).

- **Language / versions:** Python **3.9 – 3.13** (CI runs the full matrix); keep
  new code 3.9-compatible.
- **License:** Apache 2.0 — every source file carries the CERN license header.

### Repository layout

```
lib/rucio/        Main package
  client/         Python client library (talks to the REST API)
  cli/            Command-line interface
  gateway/        Permission / abstraction layer between clients and core
  core/           Server-side business logic
  db/sqla/        SQLAlchemy models and Alembic migrations
  daemons/        Long-running server daemons (conveyor, judge, reaper, …)
  rse/            RSE (Rucio Storage Element) protocols and manager
  transfertool/   Integrations with transfer services (e.g. FTS3)
  web/rest/       Flask REST API
  common/         Shared utilities, exceptions, constants
bin/              Daemon and CLI entry points (rucio, rucio-admin, rucio-*)
tests/            Test suite (pytest)
tools/            Dev/CI helper scripts (tests, linting, headers, migrations)
etc/docker/dev/   Containerised development environment (recommended)
requirements/     Pinned dependency sets (client / server / dev)
```

Server-side layering: **client → web/rest → gateway → core → db/sqla**. Respect
these boundaries — `core` holds business logic, `gateway` enforces permissions,
and clients must not reach into `core` directly.

## Development environment

The **recommended** workflow uses the containerised dev environment; the test
suite is database-backed and expects the services the containers provide.

```bash
docker compose --file etc/docker/dev/docker-compose.yml up -d   # standard env
docker exec -it dev-rucio-1 /bin/bash                           # enter container
```

See [etc/docker/dev/README.rst](etc/docker/dev/README.rst) for the
storage-enabled and full-monitoring variants and upload/transfer walkthroughs.

## Build, test, and lint commands

Run these **inside the dev container**.

```bash
# Full unit-test suite (bootstraps the DB, ~10 min)
tools/run_tests.sh

# Bootstrap once, then run tests selectively
tools/run_tests.sh -i
tools/pytest.sh tests/test_replica.py
tools/pytest.sh -vvv tests/test_replica.py::TestReplicaCore::test_delete_replicas

# Also run lint as part of the suite
tools/run_tests.sh -l
```

`tools/run_tests.sh` flags: `-i` init only, `-k` keep DB, `-r` activate default
RSEs, `-x` stop on first failure, `-c` coverage, `-t` verbose.

### Linting, formatting, and types

Linting is driven by **pre-commit** ([.pre-commit-config.yaml](.pre-commit-config.yaml)):

```bash
pre-commit run --all-files
tools/run_pyright.sh            # pyright, basic mode (pyrightconfig.json)
```

- **ruff** (`--fix`) — primary linter; config in [pyproject.toml](pyproject.toml).
  Rule families: isort (`I`), pep8-naming (`N`), bandit (`S`), pyupgrade (`UP`),
  flake8-type-checking (`TCH`), flake8-tidy-imports (`TID`), pylint errors
  (`PLE`). **Line length 256.**
- **flake8** — additional style checks.
- **add_header** ([tools/add_header](tools/add_header)) — verifies the CERN
  license header; run `tools/add_header <files>` for new files.
- **Type hints:** add them to new/modified code. Prefer built-in and
  `collections.abc` generics over banned `typing` aliases (use `dict`/`list`,
  `collections.abc.Mapping`/`Iterable`/`Callable`, not `typing.Dict`/`Mapping`/…);
  ruff `TID` enforces this. Put type-only imports inside `if TYPE_CHECKING:`.

## Code style & conventions

- Every source file starts with the **CERN Apache-2.0 license header** (copy from
  any `lib/rucio/` file or use `tools/add_header`).
- Line length **256**; isort-ordered imports with `rucio` as first-party.
- pep8-naming is enforced; targeted exemptions live in
  `[tool.ruff.lint.per-file-ignores]` — check there before fighting the linter.
- **Match the surrounding code** — mirror the existing patterns and naming of the
  module you edit rather than introducing new idioms.

## Tests

- Tests live in [tests/](tests/) and use **pytest**; shared fixtures are in
  [tests/conftest.py](tests/conftest.py) — use them instead of bare instances.
- The suite is **database-backed** and must be deterministic and self-contained.
  Parallel execution (xdist) is auto-disabled for `sqlite`/`mysql`/`oracle`
  backends (locking/deadlocks); PostgreSQL runs in parallel. Mark tests that
  interfere with others as `noparallel`.
- Add or update tests for every behavioural change.

## Quick reference for agents

- **Follow the [AI Policy](#️-ai-policy--read-this-first): disclose AI use, take
  full responsibility, understand every line, and never replace human review.**
- Open an **issue first**; one focused PR per objective, targeting `master`.
- Commit with **Conventional Commits** (`type(scope): …`) and a `Closes: #<issue>`
  trailer.
- Preserve the **license header**; keep code **Python 3.9-compatible**.
- Run **pre-commit**, **pyright**, and the **relevant tests** before proposing
  changes (`tools/pytest.sh <path>` for fast targeted runs in the dev container).
- Don't bypass the **client → rest → gateway → core → db** layering;
