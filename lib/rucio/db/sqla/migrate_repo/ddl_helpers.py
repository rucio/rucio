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

"""
Utility helpers for the Alembic DDL migrations.

The functions collected here smooth over backend differences so that schema changes
can be expressed once and executed safely across Rucio's supported databases.
"""

import logging
from typing import TYPE_CHECKING

from alembic import context, op
from sqlalchemy.dialects import mysql, postgresql, sqlite
from sqlalchemy.dialects import oracle as ora
from sqlalchemy.engine.default import DefaultDialect
from sqlalchemy.exc import DatabaseError

if TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import Any, Optional

    from alembic.runtime.migration import MigrationContext
    from sqlalchemy.sql.compiler import IdentifierPreparer
    from sqlalchemy.sql.schema import Table


LOGGER = logging.getLogger(__name__)
_WARNED_UNKNOWN_DIALECT = False

MYSQL_GENERAL_MISSING_TOKENS: tuple[str, ...] = (
    "doesn't exist",
    "does not exist",
    "unknown constraint",
    "unknown index",
    "unknown key",
    "check that column/key exists",
    "check that it exists",
)

MYSQL_CONSTRAINT_MISSING_TOKENS: tuple[str, ...] = (
    *MYSQL_GENERAL_MISSING_TOKENS,
    "can't drop foreign key",
    "can't drop constraint",
    "not found in the table",
)


def _warn_unknown_dialect_once() -> None:
    """Log a single warning when the SQL dialect cannot be determined.

    This preserves historic behavior for offline runs but makes it explicit that
    Oracle would otherwise receive double-quoted, case-sensitive identifiers.
    """

    global _WARNED_UNKNOWN_DIALECT
    if not _WARNED_UNKNOWN_DIALECT:
        LOGGER.warning(
            "Unable to determine SQL dialect for Alembic helpers; falling back to "
            "generic behavior. For offline runs, set 'sqlalchemy.url' or use "
            "'alembic -x dialect=<name>' (e.g. oracle). On Oracle, quoted identifiers "
            "would be case-sensitive."
        )
        _WARNED_UNKNOWN_DIALECT = True


def _matches_any(
        message: 'Optional[str]',
        tokens: 'Iterable[str]'
) -> bool:
    """
    Return ``True`` when any token is present in *message*.

    Parameters
    ----------
    message : Optional[str]
        The string to search. ``None`` is treated as the empty string so that
        unexpected exceptions do not bubble further up the stack.
    tokens : Iterable[str]
        Search terms to look for. The comparison is case-insensitive so callers
        can provide tokens in any casing. Falsy tokens are normalised to the
        empty string, which matches any message; callers should pre-filter such
        values if that behaviour is undesirable.

    Returns
    -------
    bool
        ``True`` if at least one token is present in ``message``; otherwise ``False``.
    """

    msg = (message or "").lower()
    return any((token or "").lower() in msg for token in tokens)


def _dialect_name() -> 'Optional[str]':
    """
    Internal shorthand for `_get_current_dialect`, normalising "mariadb" to "mysql".
    """

    name = _get_current_dialect()
    if name == "mariadb":
        return "mysql"
    return name


def _preparer() -> 'IdentifierPreparer':
    """
    Return the current dialect's identifier preparer.

    When a migration context is active we defer to its dialect preparer.
    Otherwise, look up the configured backend and return the preparer for that
    engine so that offline migrations still receive backend-specific quoting
    (e.g. backticks for MySQL/MariaDB, double quotes for PostgreSQL). If no
    dialect hint can be derived we keep operating by falling back to
    ``DefaultDialect`` and emit a one-time warning so callers understand that
    ANSI-style quoting (double quotes) will be used irrespective of the actual
    backend. This particularly impacts Oracle because identifiers will then be
    quoted and therefore case-sensitive, contrary to the typical Rucio
    expectation of uppercase folding.
    """

    ctx = _get_migration_context()
    dialect = getattr(ctx, "dialect", None)
    if dialect is not None:
        return dialect.identifier_preparer

    name = (_get_current_dialect() or "").lower()
    if name in {"mysql", "mariadb"}:
        return mysql.dialect().identifier_preparer
    if name == "postgresql":
        return postgresql.dialect().identifier_preparer
    if name == "oracle":
        return ora.dialect().identifier_preparer
    if name == "sqlite":
        return sqlite.dialect().identifier_preparer

    # DefaultDialect produces ANSI-style double quotes; this is our final
    # fallback when no dialect hints are available, even though Oracle will
    # therefore receive quoted identifiers in this edge case.
    _warn_unknown_dialect_once()
    return DefaultDialect().identifier_preparer


def quote_identifier(
        name: 'Optional[str]'
) -> str:
    """
    Quote *name* using the active dialect's identifier rules.

    Parameters
    ----------
    name : Optional[str]
        The identifier to quote. Falsy values (``None`` or the empty string)
        result in ``""`` so the helper can be used directly with optional values.

    Returns
    -------
    str
        The quoted identifier or the empty string when ``name`` is falsy.
    """

    if not name:
        return ""
    return _preparer().quote_identifier(name)


def _quoted_table(
        table_name: str,
        schema: 'Optional[str]'
) -> str:
    """
    Quote *table_name* and *schema* for SQL emission.

    Oracle deliberately avoids quoting so that identifiers retain their
    server‑side uppercase folding. This matches the behaviour of existing
    migrations that concatenate ``f"{schema}.{table_name}"`` strings.

    Fail-safe: when the dialect cannot be determined, do **not** quote. This
    preserves legacy concatenation semantics and keeps Oracle safe. A one-time
    warning is emitted to help users fix their offline configuration.
    """

    name = (_get_current_dialect() or "").lower()

    if not name:
        _warn_unknown_dialect_once()
        if schema:
            return f"{schema}.{table_name}"
        return table_name

    if name == 'oracle':
        if schema:
            return f"{schema}.{table_name}"
        return table_name

    if schema:
        return f"{quote_identifier(schema)}.{quote_identifier(table_name)}"
    return quote_identifier(table_name)


def _get_current_dialect() -> 'Optional[str]':
    """
    Return the name of the database dialect used for the current run.

    The lookup prefers an active `MigrationContext` but gracefully
    falls back to Alembic configuration when no context is present (e.g.
    offline migrations): it checks ``context.config`` for ``dialect`` and
    finally derives the name from ``sqlalchemy.url`` if needed.

    Returns
    -------
    Optional[str]
        The dialect name recognised by SQLAlchemy (for example ``"mysql"`` or
        ``"postgresql"``) or ``None`` when no hint can be derived.
    """

    ctx = _get_migration_context()
    dialect = getattr(ctx, "dialect", None)
    name = getattr(dialect, "name", None)
    if name:
        return name

    cfg = getattr(context, "config", None)
    if cfg is not None:
        name = cfg.get_main_option("dialect")
        if name:
            return name

        url = cfg.get_main_option("sqlalchemy.url")
        if url:
            parsed = url.split(":", 1)[0]
            name = parsed.split("+", 1)[0]
            if name:
                return name
    return None


def _get_migration_context() -> 'Optional[MigrationContext]':
    """
    Return the active Alembic `alembic.runtime.migration.MigrationContext`, if any.

    Tries ``alembic.op.get_context()`` first (typical for online migrations),
    then falls back to ``alembic.context.get_context()`` (useful in some offline
    or test setups). If neither is available, returns ``None``.

    Returns
    -------
    Optional[MigrationContext]
        The context currently bound to Alembic operations, or ``None`` when no
        migration is running.

    Notes
    -----
    * This helper never creates or configures a context; it only *retrieves* an
      already-active one if present.
    * Safe to call outside of Alembic migrations (it simply returns ``None``).
    """

    try:
        return op.get_context()
    except Exception:
        pass

    try:
        return context.get_context()
    except Exception:
        return None


def is_current_dialect(
        *dialect_names: str
) -> bool:
    """
    Return ``True`` if the *active* database dialect matches any provided names.

    Parameters
    ----------
    *dialect_names : str
        One or more dialect names to test (e.g. ``"postgresql"``, ``"mysql"``, ``"oracle"``).
        Matching is case‑insensitive but otherwise literal; backends that report ``"mariadb"``
        do not match ``"mysql"`` unless you include ``"mariadb"`` explicitly.

    Returns
    -------
    bool
        ``True`` when the active dialect name is one of ``dialect_names``, else ``False``.

    How the dialect is resolved
    ---------------------------
    1. If an `alembic.runtime.migration.MigrationContext` is active, use ``ctx.dialect.name``.
    2. Otherwise, consult ``alembic.context.config``:
       * the ``dialect`` main option, if set
       * otherwise the scheme from ``sqlalchemy.url`` (e.g. ``postgresql+psycopg`` -> ``postgresql``)
    3. If no hint can be found, the function returns ``False``.

    Examples
    --------
    In an Alembic migration:

    >>> from alembic import op
    >>> from rucio.db.sqla.migrate_repo import is_current_dialect
    >>> if is_current_dialect("oracle"):
    ...     # Example: perform an Oracle-specific change used in Rucio migrations
    ...     op.execute("ALTER SESSION SET NLS_LENGTH_SEMANTICS=CHAR")
    """

    name = _get_current_dialect()
    if not name:
        return False
    wanted = {d.lower() for d in dialect_names}
    return name.lower() in wanted


def get_effective_schema() -> 'Optional[str]':
    """
    Return the schema Alembic treats as the default for migrations, if any.

    When helpers in this module are called without a ``schema=`` argument,
    they fall back to this value so that objects live alongside the Alembic
    version table by default.

    Resolution order (first non‑empty wins)
    --------------------------------------
    1. ``alembic.runtime.migration.MigrationContext.version_table_schema``
    2. ``MigrationContext.opts['version_table_schema']``
    3. ``alembic.context.config.get_main_option('version_table_schema')``

    Returns
    -------
    Optional[str]
        The configured version‑table schema, or ``None`` when no default is set.

    Notes
    -----
    This function inspects only the active Alembic context/configuration; it
    does not query the server.
    """

    ctx = _get_migration_context()
    if ctx is not None:
        schema = getattr(ctx, "version_table_schema", None)
        if schema:
            return schema
        opts = getattr(ctx, "opts", {}) or {}
        schema = opts.get("version_table_schema")
        if schema:
            return schema
    cfg = getattr(context, "config", None)
    if cfg is not None:
        schema = cfg.get_main_option("version_table_schema")
        if schema:
            return schema
    return None


def qualify_table(
        table_name: str,
        schema: 'Optional[str]' = None
) -> str:
    """
    Render an appropriately quoted (or unquoted) table identifier, schema‑qualified when configured.

    Parameters
    ----------
    table_name : str
        Unqualified table name to quote. Must be non-empty and contain no dots.
    schema : Optional[str] = None
        Schema to qualify with. When omitted, uses `get_effective_schema`.
        If that also yields ``None``, the result is unqualified. Passing
        ``""`` is treated the same as ``None``. Multi-part schema names
        (containing ``"."``) are rejected.

    Returns
    -------
    str
        The table name qualified with its schema when provided. For detected
        non-Oracle dialects, quoting is performed via SQLAlchemy's
        `sqlalchemy.sql.compiler.IdentifierPreparer` so the output matches the
        active engine (e.g. backticks for MySQL/MariaDB). Oracle intentionally
        returns unquoted identifiers so that implicit uppercasing continues to
        work, and when the dialect cannot be determined the helper emits a
        warning and likewise returns unquoted identifiers.

    Notes
    -----
    * This helper performs no server round‑trips.
    * Useful when emitting raw SQL via ``op.execute`` that must be portable
      across PostgreSQL, MySQL/MariaDB, Oracle, and SQLite.

    Examples
    --------
    Dialect (mode)             Input                 Expected output
    -------------------------  --------------------  ------------------------------
    PostgreSQL (detected)      ("users", "dev")      '"dev"."users"'
    MySQL/MariaDB (detected)   ("users", "dev")      '`dev`.`users`'
    Oracle (detected)          ("requests", "ATLAS") 'ATLAS.requests'
    SQLite (detected)          ("users", None)       '"users"'
    Unknown dialect            ("users", "dev")      'dev.users'
    Unknown dialect            ("users", None)       'users'
    Any                        ("", "dev")           ValueError
    Any                        ("dev.users", None)   ValueError
    Any                        ("users", "dev.app")  ValueError
    """

    if not table_name:
        raise ValueError("table_name must be a non-empty unqualified identifier")
    if "." in table_name:
        raise ValueError("Pass an unqualified table_name; use schema=... for qualification")
    if schema is None:
        schema = get_effective_schema()
    if schema == "":
        schema = None
    if schema is not None and "." in schema:
        raise ValueError("schema must be a single identifier; multi-part names are unsupported")
    return _quoted_table(table_name, schema)


def try_drop_constraint(
        constraint_name: str,
        table_name: str,
        *,
        type_: 'Optional[str]' = None,
) -> None:
    """
    Drop a named constraint if it exists, without failing on "missing" cases.

    Behavior by dialect:
    * PostgreSQL: emits two safe statements:
        first an unquoted ALTER TABLE IF EXISTS <tbl> DROP CONSTRAINT IF EXISTS <name>
        (to match historically unquoted / any‑casing names), then the quoted form.
        When type_ == "primary", it also tries the backend’s default PK name <table>_pkey
        (both unquoted and quoted).
    * MySQL / MariaDB: – uses the appropriate ``ALTER TABLE ... DROP ...`` form;
      probes the kind when ``type_`` is not supplied and treats standard "missing"
      errors as a no‑op.
    * SQLite, Oracle, others : – delegates to Alembic (``drop_constraint``)
      with ``type_`` as given.

    Parameters
    ----------
    constraint_name : str
        Name of the constraint to remove.
    table_name : str
        Table hosting the constraint.
    type_ : Optional[str]
        Explicit constraint type (primarily for MySQL/MariaDB). Providing this lets
        Alembic emit the appropriate ``DROP`` statement without additional probing.
        Canonical Alembic values include ``"foreignkey"``, ``"check"``, ``"unique"``
        and ``"primary"``. On MySQL/MariaDB, when ``type_`` is provided, the call is
        delegated to :func:`drop_constraint` with the type passed through unchanged so
        that schema defaulting remains consistent.
        When ``type_`` is omitted on those backends, the helper probes by trying
        (in order): ``DROP FOREIGN KEY``, then ``DROP INDEX``, then ``DROP CHECK``.
        Legacy "syntax"/"unsupported" errors for ``DROP CHECK`` (older
        MySQL/MariaDB) are tolerated both during probing and when ``type_ ==
        "check"`` so callers need not special-case legacy engines. On
        PostgreSQL the helper emits raw SQL and ignores ``type_``. Other backends
        fall back to Alembic with ``type_`` passed through.

    Returns
    -------
    None

    Raises
    ------
    RuntimeError
        If an unexpected database error occurs (i.e., not a recognised "missing"
        constraint condition).

    Notes
    -----
    * Idempotent by construction : repeated calls leave the schema unchanged.
    * Error strings that indicate a harmless "missing" case are normalised across
      backends and tolerated.
    * Callers should drop dependent objects (e.g., FKs referencing a PK) first,
      mirroring common migration ordering.

    Examples
    --------
    >>> # Works whether or not the FK exists (MySQL/MariaDB will probe)
    >>> try_drop_constraint("fk_orders_user_id", "orders")
    >>> # If you know the type, supply it to avoid probing on MySQL/MariaDB
    >>> try_drop_constraint("fk_orders_user_id", "orders", type_="foreignkey")
    """

    dialect = _dialect_name()
    schema = get_effective_schema()
    quoted_table = _quoted_table(table_name, schema)
    plain_table = f"{schema}.{table_name}" if schema else table_name
    quoted_constraint = _qident(constraint_name)
    if dialect == "postgresql":
        # Prefer an unquoted drop first so it matches constraints created without quotes
        # (PostgreSQL folds unquoted identifiers to lower-case). Then try the quoted
        # form to catch explicitly quoted, case-sensitive names. When dropping a PK,
        # also attempt the backend's default primary key name (<table>_pkey).
        stmts = [
            f"ALTER TABLE IF EXISTS {quoted_table} DROP CONSTRAINT IF EXISTS {constraint_name}",
            f"ALTER TABLE IF EXISTS {quoted_table} DROP CONSTRAINT IF EXISTS {quoted_constraint}",
        ]
        if (type_ or "").lower() == "primary":
            default_pk = f"{table_name}_pkey"
            stmts.append(
                f"ALTER TABLE IF EXISTS {quoted_table} DROP CONSTRAINT IF EXISTS {default_pk}"
            )
            stmts.append(
                f"ALTER TABLE IF EXISTS {quoted_table} DROP CONSTRAINT IF EXISTS {_qident(default_pk)}"
            )
        for stmt in stmts:
            op.execute(stmt)
        return

    if dialect == "mysql":
        if type_:
            try:
                drop_constraint(constraint_name, table_name, type_=type_)
            except (DatabaseError, ValueError) as exc:
                message = str(exc).lower()
                tolerated = _matches_any(message, MYSQL_CONSTRAINT_MISSING_TOKENS)

                # Older MySQL/MariaDB variants (pre 8.x / 10.2) do not support
                # ``DROP CHECK`` syntax; treat those as benign when explicitly
                # dropping a check constraint so callers do not need to special
                # case legacy engines.
                if (type_ or "").lower() == "check":
                    if any(word in message for word in ["syntax", "not supported", "unsupported"]):
                        tolerated = True

                if not tolerated:
                    raise RuntimeError(exc) from exc
                LOGGER.debug(
                    "Constraint %s on %s already missing or unsupported to drop "
                    "directly (dialect=mysql, type=%s): %s",
                    constraint_name,
                    plain_table,
                    type_,
                    message,
                )
            return

        statements = (
            (
                f"ALTER TABLE {quoted_table} DROP FOREIGN KEY {quoted_constraint}",
                False,
            ),
            (
                f"ALTER TABLE {quoted_table} DROP INDEX {quoted_constraint}",
                False,
            ),
            (
                f"ALTER TABLE {quoted_table} DROP CHECK {quoted_constraint}",
                True,
            ),
        )
        executed = False
        for stmt, allow_syntax in statements:
            try:
                op.execute(stmt)
                executed = True
                return
            except DatabaseError as exc:
                message = str(exc).lower()
                tolerated = _matches_any(message, MYSQL_CONSTRAINT_MISSING_TOKENS)
                if allow_syntax:
                    tolerated = tolerated or "syntax" in message
                if not tolerated:
                    raise RuntimeError(exc) from exc
        if not executed:
            LOGGER.debug(
                "Constraint %s on %s not dropped; treated as already missing",
                constraint_name,
                plain_table,
            )
        return

    try:
        drop_constraint(constraint_name, table_name, type_=type_)
    except (DatabaseError, ValueError) as exc:
        message = str(exc).lower()
        tolerated = (
                "nonexistent constraint" in message
                or "undefined object" in message
                or "undefinedobject" in message
                or "no such constraint" in message
                or _matches_any(message, MYSQL_CONSTRAINT_MISSING_TOKENS)
        )
        if not tolerated:
            raise RuntimeError(exc) from exc
        LOGGER.debug(
            "Constraint %s on %s already missing; treated as no-op",
            constraint_name,
            plain_table,
        )


# ---------------------------------------------------------------------------
# Schema-defaulting wrappers for alembic.op
# ---------------------------------------------------------------------------

def _with_default_schema(kwargs: 'dict[str, Any]') -> 'dict[str, Any]':
    """
    Ensure a default schema is present in ``kwargs['schema']``.

    Parameters
    ----------
    kwargs : dict[str, Any]
        Keyword-argument mapping destined for an Alembic operation. If ``schema`` is
        absent or falsy (``None``/``""``), this helper injects the value from
        :func:`get_effective_schema`, when available.

    Returns
    -------
    dict[str, Any]
        The (potentially) augmented mapping. The input is mutated and returned for convenience.

    Notes
    -----
    Schema is keyword-only in the wrapper functions, so it cannot appear in ``*args``.
    """
    if "schema" not in kwargs or kwargs.get("schema") in (None, ""):
        eff = get_effective_schema()
        if eff:
            kwargs["schema"] = eff
    return kwargs


def add_column(*args: 'Any', **kwargs: 'Any') -> None:
    """
    Replacement for :func:`alembic.op.add_column` with schema defaulting.

    Parameters
    ----------
    *args : Any
        Positional arguments forwarded to Alembic.
    **kwargs : Any
        Keyword arguments forwarded to Alembic. If ``schema`` is not provided or is
        falsy, :func:`get_effective_schema` is injected.

    Returns
    -------
    None

    Examples
    --------
    Add a column to the Rucio ``replicas`` table while respecting the configured
    version-table schema:

    >>> add_column("replicas", sa.Column("tape_state", sa.String(1)))
    """
    kwargs = _with_default_schema(dict(kwargs))
    return op.add_column(*args, **kwargs)


def alter_column(*args: 'Any', **kwargs: 'Any') -> None:
    """
    Replacement for :func:`alembic.op.alter_column` with schema defaulting.

    Parameters
    ----------
    *args : Any
        Positional arguments forwarded to Alembic.
    **kwargs : Any
        Keyword arguments forwarded to Alembic. If ``schema`` is not provided or is
        falsy, :func:`get_effective_schema` is injected.

    Returns
    -------
    None

    Examples
    --------
    Make ``guid`` nullable in the Rucio ``dids`` table:

    >>> alter_column("dids", "guid", existing_type=sa.String(36), nullable=True)
    """
    kwargs = _with_default_schema(dict(kwargs))
    return op.alter_column(*args, **kwargs)


def create_check_constraint(*args: 'Any', **kwargs: 'Any') -> None:
    """
    Replacement for :func:`alembic.op.create_check_constraint` with schema defaulting.

    Parameters
    ----------
    *args : Any
        Positional arguments forwarded to Alembic.
    **kwargs : Any
        Keyword arguments forwarded to Alembic. If ``schema`` is not provided or is
        falsy, :func:`get_effective_schema` is injected.

    Returns
    -------
    None

    Examples
    --------
    Ensure that the ``state`` column on ``replicas`` stays within a small set:

    >>> create_check_constraint("CHK_REPLICAS_STATE", "replicas", "state IN ('A','B')")
    """
    kwargs = _with_default_schema(dict(kwargs))
    return op.create_check_constraint(*args, **kwargs)


def create_index(*args: 'Any', **kwargs: 'Any') -> None:
    """
    Replacement for :func:`alembic.op.create_index` with schema defaulting.

    Parameters
    ----------
    *args : Any
        Positional arguments forwarded to Alembic.
    **kwargs : Any
        Keyword arguments forwarded to Alembic. If ``schema`` is not provided or is
        falsy, :func:`get_effective_schema` is injected.

    Returns
    -------
    None

    Examples
    --------
    Create a common Rucio index over ``(scope, name)`` on ``replicas``:

    >>> create_index("IX_REPLICAS_SCOPE_NAME", "replicas", ["scope", "name"], unique=False)
    """
    kwargs = _with_default_schema(dict(kwargs))
    return op.create_index(*args, **kwargs)


def create_primary_key(*args: 'Any', **kwargs: 'Any') -> None:
    """
    Replacement for :func:`alembic.op.create_primary_key` with schema defaulting.

    Parameters
    ----------
    *args : Any
        Positional arguments forwarded to Alembic.
    **kwargs : Any
        Keyword arguments forwarded to Alembic. If ``schema`` is not provided or is
        falsy, :func:`get_effective_schema` is injected.

    Returns
    -------
    None

    Examples
    --------
    Set the canonical Rucio DID composite key:

    >>> create_primary_key("DIDS_PK", "dids", ["scope", "name"])
    """
    kwargs = _with_default_schema(dict(kwargs))
    return op.create_primary_key(*args, **kwargs)


def create_table(*args: 'Any', **kwargs: 'Any') -> 'Table':
    """
    Replacement for :func:`alembic.op.create_table` with schema defaulting.

    Parameters
    ----------
    *args : Any
        Positional arguments forwarded to Alembic.
    **kwargs : Any
        Keyword arguments forwarded to Alembic. If ``schema`` is not provided or is
        falsy, :func:`get_effective_schema` is injected.

    Returns
    -------
    Table
        The SQLAlchemy ``Table`` object produced by Alembic.

    Examples
    --------
    Create a temporary audit table under the configured migration schema:

    >>> tbl = create_table(
    ...     "tmp_account_audit",
    ...     sa.Column("id", sa.Integer(), primary_key=True),
    ...     sa.Column("account", sa.String(25), nullable=False),
    ... )
    """
    kwargs = _with_default_schema(dict(kwargs))
    return op.create_table(*args, **kwargs)


def create_unique_constraint(*args: 'Any', **kwargs: 'Any') -> None:
    """
    Replacement for :func:`alembic.op.create_unique_constraint` with schema defaulting.

    Parameters
    ----------
    *args : Any
        Positional arguments forwarded to Alembic.
    **kwargs : Any
        Keyword arguments forwarded to Alembic. If ``schema`` is not provided or is
        falsy, :func:`get_effective_schema` is injected.

    Returns
    -------
    None

    Examples
    --------
    Enforce unique emails for Rucio accounts:

    >>> create_unique_constraint("UQ_ACCOUNTS_EMAIL", "accounts", ["email"])
    """
    kwargs = _with_default_schema(dict(kwargs))
    return op.create_unique_constraint(*args, **kwargs)


def drop_column(*args: 'Any', **kwargs: 'Any') -> None:
    """
    Replacement for :func:`alembic.op.drop_column` with schema defaulting.

    Parameters
    ----------
    *args : Any
        Positional arguments forwarded to Alembic.
    **kwargs : Any
        Keyword arguments forwarded to Alembic. If ``schema`` is not provided or is
        falsy, :func:`get_effective_schema` is injected.

    Returns
    -------
    None

    Examples
    --------
    Remove a deprecated column from ``requests``:

    >>> drop_column("requests", "old_col")
    """
    kwargs = _with_default_schema(dict(kwargs))
    return op.drop_column(*args, **kwargs)


def drop_constraint(*args: 'Any', **kwargs: 'Any') -> None:
    """
    Replacement for :func:`alembic.op.drop_constraint` with schema defaulting.

    Parameters
    ----------
    *args : Any
        Positional arguments forwarded to Alembic.
    **kwargs : Any
        Keyword arguments forwarded to Alembic. If ``schema`` is not provided or is
        falsy, :func:`get_effective_schema` is injected.

    Returns
    -------
    None

    Notes
    -----
    This is a thin schema-defaulting wrapper. For tolerant "drop if exists" semantics,
    use :func:`try_drop_constraint`.
    """
    kwargs = _with_default_schema(dict(kwargs))
    return op.drop_constraint(*args, **kwargs)


def drop_index(*args: 'Any', **kwargs: 'Any') -> None:
    """
    Replacement for :func:`alembic.op.drop_index` with schema defaulting.

    Parameters
    ----------
    *args : Any
        Positional arguments forwarded to Alembic.
    **kwargs : Any
        Keyword arguments forwarded to Alembic. If ``schema`` is not provided or is
        falsy, :func:`get_effective_schema` is injected.

    Returns
    -------
    None

    Notes
    -----
    This wrapper does not swallow "missing index" errors. For idempotent semantics across
    backends, prefer :func:`try_drop_index`.

    Examples
    --------
    >>> drop_index("IX_ACCOUNTS_EMAIL", table_name="accounts")
    """
    kwargs = _with_default_schema(dict(kwargs))
    return op.drop_index(*args, **kwargs)


def drop_table(*args: 'Any', **kwargs: 'Any') -> None:
    """
    Replacement for :func:`alembic.op.drop_table` with schema defaulting.

    Parameters
    ----------
    *args : Any
        Positional arguments forwarded to Alembic.
    **kwargs : Any
        Keyword arguments forwarded to Alembic. If ``schema`` is not provided or is
        falsy, :func:`get_effective_schema` is injected.

    Returns
    -------
    None

    Examples
    --------
    >>> drop_table("tmp_account_audit")
    """
    kwargs = _with_default_schema(dict(kwargs))
    return op.drop_table(*args, **kwargs)


def rename_table(*args: 'Any', **kwargs: 'Any') -> None:
    """
    Replacement for :func:`alembic.op.rename_table` with schema defaulting.

    Parameters
    ----------
    *args : Any
        Positional arguments forwarded to Alembic.
    **kwargs : Any
        Keyword arguments forwarded to Alembic. If ``schema`` is not provided or is
        falsy, :func:`get_effective_schema` is injected.

    Returns
    -------
    None

    Examples
    --------
    >>> rename_table("collections", "collections_legacy")
    """
    kwargs = _with_default_schema(dict(kwargs))
    return op.rename_table(*args, **kwargs)


__all__ = [
    "add_column",
    "alter_column",
    "create_check_constraint",
    "create_index",
    "create_primary_key",
    "create_table",
    "create_unique_constraint",
    "drop_column",
    "drop_index",
    "drop_table",
    "rename_table",
    "is_current_dialect",
    "get_effective_schema",
    "qualify_table",
    "quote_identifier",
    "drop_constraint",
    "try_drop_constraint",
]
