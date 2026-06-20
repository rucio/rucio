# AGENTS.md

Repository-wide instructions for AI coding agents and for humans directing them.
A more specific `AGENTS.md` may add or override instructions within its subtree.
Before editing a file, locate and follow every applicable `AGENTS.md` from the repository root to the target; the most specific instruction wins.

## Sources of truth

- Follow the [Rucio AI Policy](https://rucio.cern/documentation/developer/dev_ai_policy/), [Rucio contribution guide](https://rucio.cern/documentation/contributing/), and [Rucio sprint-planning policy](https://rucio.cern/documentation/developer/sprint_planning/).
- For Python and SQLAlchemy style or type-annotation work, also follow the [Rucio style guide](https://rucio.cern/documentation/developer/dev_style_guide/) and [Rucio type-annotation guide](https://rucio.cern/documentation/developer/type_annotation_guide/).
- For handling security vulnerabilities, follow the [Rucio security policy](.github/SECURITY.md).
- For technical details such as supported Python versions, command options, lint rules, commit-message rules, and CI checks, use the relevant repository configuration, scripts, and workflows rather than this summary.
- If this file conflicts with an authoritative source, follow that source and report the mismatch.

## Mandatory AI policy

- AI assistance is permitted only under the Rucio AI Policy.
- Disclose AI assistance in every contribution and project communication for which it was used.
- The human contributor remains fully responsible for the result and must understand and be able to explain every proposed change.
- Keep proposed changes small enough for the human contributor to review, understand, and explain.

The intent of the policy is to avoid shifting review burden and comprehension debt onto maintainers: the goal must be better-quality code, not faster code.
Low-quality, unexplained AI-generated contributions are unwelcome regardless of whether they pass CI.

## Safety and authorisation

- Treat GitHub as read-only unless the human explicitly requests a specific write action. Do not create or modify issues, pull requests, comments, reviews, labels, branches, or releases; push commits; approve; merge; close; or reopen anything without that authorisation.
- Treat a suspected security vulnerability as confidential: do not describe it in public issues, pull requests, comments, or commits. Follow the [Rucio security policy](.github/SECURITY.md) for private reporting, and disclose any AI involvement in finding it.

## Issue and pull-request size

Rucio defines issue size by estimated human (not AI agent) engineering effort.

- Before any implementation, verify that an associated issue exists; the current contribution and commit-message rules require its issue number in the commits.
- For an L issue, recommend decomposition into independently reviewable sub-issues before implementation.
- For an XL issue, do not implement it as one change or one pull request. Stop and give the human a concrete decomposition plan containing independently reviewable sub-issues, their acceptance criteria, dependencies, and suggested order.
- For L and XL issues, before implementation verify that the issue names a reviewer or co-author and that the planned approach has been discussed. If either prerequisite is missing, stop and report it instead of starting the implementation.
- Each pull request must address one issue or sub-issue and one objective.
- If implementation reveals additional objectives or substantial unrelated work, stop expanding the change and propose follow-up issues instead.

## Implementation discipline

- Start from the problem and acceptance criteria described in the associated issue. If the request and issue disagree, report the mismatch before making a conflicting change.
- Implement only what the issue requires. Prefer the smallest reviewable change that fully solves the current problem.
- When different implementations are equally correct and clear, prefer the simpler one.
- Do not generalise for hypothetical future use cases.
- Respect the existing architecture, coding style, helper patterns, naming, and test conventions. Inspect adjacent implementation and tests before introducing a new pattern.
- Reuse or adapt existing helpers before adding new helpers or abstractions.
- Do not introduce new options, flags, abstractions, dependencies, or compatibility layers unless required by the issue, existing supported behaviour, or an established repository pattern.
- Add type annotations to new production code according to the Rucio type-annotation guide and adjacent code. Do not expand a focused change into unrelated type-annotation migration.
- Preserve the minimum Python version and formatting rules declared in [`pyproject.toml`](pyproject.toml).
- Preserve required source-file license headers; use [`tools/add_header`](tools/add_header) rather than inventing a new header.
- Do not mix unrelated cleanup, refactoring, renaming, or formatting into the change.

## Architecture

Preserve the server-side layering:

```text
client -> web/rest -> gateway -> core -> db/sqla
```

- Client code calls the public API and must not reach directly into server-side core logic.
- REST code handles HTTP concerns; gateway code handles permissions and external-facing abstraction; core code contains business logic; `db/sqla` contains persistence models and migrations.
- Do not bypass layers for convenience. Follow the established dependency direction in the surrounding code.

## Environment and validation

- Use the development environment documented in [`etc/docker/dev/README.md`](etc/docker/dev/README.md) for database-backed and integration work.
- For host-side Python commands, use an existing `.venv` rather than the global Python environment.
- Start with the smallest relevant validation and expand it according to the scope and risk of the change.
- Inspect script help and repository configuration instead of copying or guessing volatile flags.

Typical targeted and broader commands include:

```bash
tools/pytest.sh <test-path-or-node>
pre-commit run --files <changed-files>
tools/run_pyright.sh
tools/run_tests.sh
pre-commit run --all-files
```

Use [`commitlint.config.js`](commitlint.config.js), [`pyproject.toml`](pyproject.toml), [`.pre-commit-config.yaml`](.pre-commit-config.yaml), [`tools/run_pyright.sh`](tools/run_pyright.sh), and [`.github/workflows/`](.github/workflows/) as the sources of truth for current commit, lint, type-check, and CI requirements.
Follow the current CI workflow for the complete Pyright invocation.

Always report the exact checks run, their result, and any relevant checks not run.
Distinguish failures caused by the change from pre-existing failures or environment limitations (in such cases a new issue must be opened).
Do not claim that a check passed unless it was run and its result was observed.

## Tests

- Add or update tests for every behavioural change.
- Before adding setup or cleanup code, inspect nearby tests, [`tests/conftest.py`](tests/conftest.py), and [`tests/temp_factories.py`](tests/temp_factories.py) for reusable facilities.
- Prefer existing fixtures and temporary factories over bare persistent objects.
- Match the style and level of the surrounding tests.
- Tests must be deterministic, self-contained, and non-flaky.
- Clean up persistent state created by a test. Unique names alone are not a substitute for cleanup.
- Mark tests as `noparallel` when they can interfere with other tests.

## Commits and reviewability

- Every commit **MUST** represent one coherent logical change and contain no unrelated files or hunks.
- The commit subject must accurately describe the complete change. If one short subject cannot describe it accurately, split the commit at logical, independently reviewable boundaries.
- When suggesting or creating commit messages, keep them short and follow [`commitlint.config.js`](commitlint.config.js) and the [Rucio contribution guide](https://rucio.cern/documentation/contributing/). Read the current configuration instead of relying on copied lists of allowed types or scopes.
