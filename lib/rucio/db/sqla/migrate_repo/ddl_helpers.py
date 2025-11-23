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

Key features
------------
* Uses SQLAlchemy's dialect preparer to quote identifiers correctly.
* Dialect detection works both online and offline, enabling migrations to run
  deterministically even when no live connection is available.
* ``try_drop_constraint`` and ``try_drop_index`` treat missing objects as a no-op,
  so rerunning migrations is safe.
* Quotes identifiers to keep PL/pgSQL and PL/SQL code robust with unusual names.

Operational notes
--------------------
* Error handling uses known message fragments to spot “already missing” cases.
  Review and extend the ``MYSQL_*_MISSING_TOKENS`` constants and
  ``ORACLE_INDEX_MISSING_TOKENS`` when database versions or locales change,
  otherwise previously ignored errors may surface as `RuntimeError`.
* Unsupported dialects are skipped (logged as no-ops). Backends outside the
  supported set (currently MySQL/MariaDB, PostgreSQL, and Oracle) are logged
  and skipped rather than raising. Validate that your migrations run on an expected
  backend; otherwise schema changes might appear to succeed while having no effect.
* Direct DDL requires privileges. Ensure the DB user has rights for the emitted
  `alembic.op` calls or raw ``ALTER``/``DROP`` statements.
"""

import logging
from typing import TYPE_CHECKING

import sqlalchemy as sa
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

MYSQL_PRIMARY_KEY_MISSING_TOKENS: tuple[str, ...] = (
    *MYSQL_GENERAL_MISSING_TOKENS,
    "can't drop primary key",
)

MYSQL_INDEX_MISSING_TOKENS: tuple[str, ...] = (
    *MYSQL_GENERAL_MISSING_TOKENS,
    "no such index",
    "can't drop index",
)

ORACLE_INDEX_MISSING_TOKENS: tuple[str, ...] = (
    "specified index does not exist",
    "ora-01418",
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


def _qliteral(
        value: 'Optional[str]'
) -> str:
    """
    Wrap *value* in single quotes for SQL/PL blocks.

    Parameters
    ----------
    value : Optional[str]
        The literal value to quote. Embedded single quotes are doubled to
        preserve the original contents.

    Returns
    -------
    str
        The quoted literal. ``None`` is emitted as the SQL ``NULL`` literal.
    """

    if value is None:
        return "NULL"
    return "'" + value.replace("'", "''") + "'"


def _dialect_name() -> 'Optional[str]':
    """
    Internal shorthand for `get_current_dialect`, normalising "mariadb" to "mysql".
    """

    name = get_current_dialect()
    if name == "mariadb":
        return "mysql"
    return name


def get_identifier_preparer() -> 'IdentifierPreparer':
    """
    Return the active SQLAlchemy identifier preparer.

    Returns
    -------
    IdentifierPreparer
        The preparer object SQLAlchemy uses to quote identifiers for the
        currently selected backend.

    Notes
    -----
    * Prefers the dialect attached to an active
      :class:`alembic.runtime.migration.MigrationContext` so that online
      migrations behave exactly like Alembic's built-ins.
    * Falls back to the configured backend (via ``alembic.context.config``)
      during offline runs, keeping migrations reproducible when generating SQL
      for Rucio deployments.
    * Emits a one-time warning and returns ``DefaultDialect``'s preparer when
      no backend hint is available. This means double quotes will be used even
      on Oracle, where identifiers would therefore become case-sensitive.

    Examples
    --------
    >>> preparer = get_identifier_preparer()
    >>> preparer.quote_identifier("request_state")
    '"request_state"'
    """

    ctx = get_migration_context()
    dialect = getattr(ctx, "dialect", None)
    if dialect is not None:
        return dialect.identifier_preparer

    name = (get_current_dialect() or "").lower()
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
    return get_identifier_preparer().quote_identifier(name)


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

    name = (get_current_dialect() or "").lower()

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


def _quoted_index(
        index_name: str,
        schema: 'Optional[str]'
) -> str:
    """
    Quote *index_name* and *schema* for SQL emission.

    Oracle deliberately avoids quoting so that identifiers retain their
    server-side uppercase folding. When the dialect cannot be determined,
    do **not** quote and emit a one-time warning to mirror `_quoted_table`.
    """

    name = (get_current_dialect() or "").lower()

    if not name:
        _warn_unknown_dialect_once()
        if schema:
            return f"{schema}.{index_name}"
        return index_name

    if name == 'oracle':
        if schema:
            return f"{schema}.{index_name}"
        return index_name

    if schema:
        return f"{quote_identifier(schema)}.{quote_identifier(index_name)}"
    return quote_identifier(index_name)


def get_current_dialect() -> 'Optional[str]':
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

    ctx = get_migration_context()
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


def get_migration_context() -> 'Optional[MigrationContext]':
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

    name = get_current_dialect()
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

    ctx = get_migration_context()
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


def qualify_index(
        index_name: str,
        schema: 'Optional[str]' = None
) -> str:
    """
    Render an index identifier suitable for embedding into SQL, with dialect-aware quoting.

    Dialect-specific behavior
    -------------------------
    * **PostgreSQL and similar**: returns a schema-qualified, quoted identifier
      (e.g., ``"schema"."index"``).
    * **Oracle**: intentionally returns an *unquoted* identifier (e.g., ``SCHEMA.INDEX``)
      so that server-side uppercasing semantics are preserved, mirroring :func:`qualify_table`.
    * **MySQL/MariaDB**: returns only the quoted index name (e.g., `` `index` ``), since
      schema-qualified index identifiers are not accepted in statements like ``DROP INDEX``.

    Parameters
    ----------
    index_name : str
        Unqualified index name to quote. Must be a simple identifier (no dots).
    schema : Optional[str]
        Schema to qualify with on dialects that support it. When omitted,
        uses `get_effective_schema`. If an empty string is supplied it is
        treated the same as ``None``. Multi-part schema names (with dots)
        are rejected.

    Returns
    -------
    str
        A properly rendered index identifier appropriate for the current dialect.

    Notes
    -----
    * MySQL/MariaDB require ``DROP INDEX <index> ON <table>``; pass the table
      name separately in those statements.

    Raises
    ------
    ValueError
        If ``index_name`` or ``schema`` is empty or contains dots. This mirrors
        :func:`qualify_table` so callers receive predictable errors when passing
        already-qualified identifiers.

    Examples
    --------
    >>> # Rucio DID primary key under a dedicated migration schema
    >>> qualify_index("DIDS_PK", schema="dev")
    '"dev"."DIDS_PK"'
    >>> # PostgreSQL example for dynamic SQL assembly during Alembic upgrades
    >>> f'DROP INDEX IF EXISTS {qualify_index("IX_REPLICAS_SCOPE_NAME")}'
    'DROP INDEX IF EXISTS "dev"."IX_REPLICAS_SCOPE_NAME"'
    >>> # MySQL/MariaDB: only the index name is returned (no schema)
    >>> qualify_index("IX_REPLICAS_SCOPE_NAME", schema="dev")
    '`IX_REPLICAS_SCOPE_NAME`'
    >>> # Oracle: unquoted identifier to preserve uppercase folding
    >>> qualify_index("IX_REPLICAS_SCOPE_NAME", schema="ATLAS")
    'ATLAS.IX_REPLICAS_SCOPE_NAME'
    """

    # Validate identifiers consistently with qualify_table
    if not index_name or "." in index_name:
        raise ValueError("index_name must be a simple identifier (no dots)")

    if schema is None:
        schema = get_effective_schema()
    if schema == "":
        schema = None
    if schema is not None and "." in schema:
        raise ValueError("schema must be a simple identifier (no dots)")

    if _dialect_name() == "mysql":
        # MySQL/MariaDB do not allow schema-qualified index identifiers.
        return quote_identifier(index_name)

    return _quoted_index(index_name, schema)


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
        When type_ == "primary", it also tries the backend's default PK name <table>_pkey
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
    quoted_constraint = quote_identifier(constraint_name)
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
                f"ALTER TABLE IF EXISTS {quoted_table} DROP CONSTRAINT IF EXISTS {quote_identifier(default_pk)}"
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


def try_drop_index(
        index_name: str,
        table_name: 'Optional[str]' = None
) -> None:
    """
    Drop a named index (tolerating missing objects) across backends.

    Parameters
    ----------
    index_name : str
        Name of the index to remove.
    table_name : Optional[str]
        Table containing the index. MySQL/MariaDB requires this argument
        for ``DROP INDEX`` statements; omitting it raises `ValueError`
        with the message "MySQL/MariaDB requires table_name for DROP INDEX" on
        those dialects (the helper normalizes MariaDB to MySQL).

    Behavior by dialect
    -------------------
    * PostgreSQL: emits ``DROP INDEX IF EXISTS <schema>.<index>``.
    * MySQL / MariaDB: emits ``DROP INDEX <index> ON <table>``.
    * Oracle: delegates to Alembic; known "specified index does not exist" / ``ORA-01418``
      cases are treated as a no-op.
    * Others (including SQLite): delegates to Alembic where possible and
      tolerates recognised "already missing" errors.

    Returns
    -------
    None

    Raises
    ------
    ValueError
        If ``table_name`` is omitted on MySQL/MariaDB.
    RuntimeError
        If an unexpected database error occurs (i.e., not a recognised "missing"
        index condition).

    Notes
    -----
    Missing indexes are treated as a successful no-op so that repeated
    migrations remain idempotent. Errors outside the known "missing"
    cases propagate (wrapped in `RuntimeError` where the helper intercepts them).

    Examples
    --------
    >>> # PostgreSQL: drop the helper index used by the Rucio replicas table
    >>> try_drop_index("IX_REPLICAS_SCOPE_NAME")
    >>> # MySQL/MariaDB: same index but the table name must be supplied
    >>> try_drop_index("IX_REPLICAS_SCOPE_NAME", table_name="replicas")
    """

    dialect = _dialect_name()
    schema = get_effective_schema()
    quoted_index = _quoted_index(index_name, schema)
    quoted_table = _quoted_table(table_name, schema) if table_name else None
    plain_index = f"{schema}.{index_name}" if schema else index_name
    plain_table = f"{schema}.{table_name}" if schema and table_name else table_name

    if dialect == "postgresql":
        op.execute(f"DROP INDEX IF EXISTS {quoted_index}")
        return

    if dialect == "mysql":
        if not table_name:
            raise ValueError("MySQL/MariaDB requires table_name for DROP INDEX")
        try:
            op.execute(f"DROP INDEX {quote_identifier(index_name)} ON {quoted_table}")
        except DatabaseError as exc:
            message = str(exc).lower()
            tolerated = _matches_any(message, MYSQL_INDEX_MISSING_TOKENS)
            if not tolerated:
                raise RuntimeError(exc) from exc
            LOGGER.debug(
                "Index %s on %s already missing (dialect=%s)",
                plain_index,
                plain_table,
                dialect,
            )
        return

    try:
        # Provide schema for backends where Alembic requires it.
        op.drop_index(index_name, table_name=table_name, schema=schema)
    except TypeError:
        # Graceful fallback for older Alembic versions without "schema".
        op.drop_index(index_name, table_name=table_name)
    except (DatabaseError, ValueError) as exc:
        message = str(exc).lower()
        tolerated = (
                "nonexistent" in message
                or "undefined object" in message
                or "undefinedobject" in message
                or _matches_any(message, MYSQL_INDEX_MISSING_TOKENS)
                or _matches_any(message, ORACLE_INDEX_MISSING_TOKENS)
        )
        if not tolerated:
            raise RuntimeError(exc) from exc
        LOGGER.debug(
            "Index %s on %s already missing; treated as no-op",
            plain_index,
            plain_table,
        )


def drop_current_primary_key(
        table_name: str
) -> None:
    """
    Drop the current primary key on ``table_name`` if one exists.

    Parameters
    ----------
    table_name : str
        The table whose primary key should be removed.

    Behavior by dialect
    -------------------
    * PostgreSQL : – looks up the PK name from catalogs and drops it only if present
      (via a small ``DO $$`` block for safety).
    * Oracle : – queries catalogs to discover and drop the PK if present.
    * MySQL / MariaDB: – executes ``ALTER TABLE <table> DROP PRIMARY KEY`` and
      tolerates the standard "already missing" errors.
    * Others : – logged as a no‑op.

    Returns
    -------
    None

    Raises
    ------
    RuntimeError
        On MySQL/MariaDB, if an unexpected database error occurs (i.e., not a recognised
        "missing primary key" condition).

    Notes
    -----
    * Idempotent : repeating the call leaves the database unchanged.
    * Drop dependent foreign keys first to mirror common migration ordering.

    Examples
    --------
    >>> drop_current_primary_key("orders")
    """

    dialect = _dialect_name()
    schema = get_effective_schema()
    plain_table = f"{schema}.{table_name}" if schema else table_name

    if dialect == "mysql":
        quoted_table = _quoted_table(table_name, schema)
        try:
            op.execute(f"ALTER TABLE {quoted_table} DROP PRIMARY KEY")
        except DatabaseError as exc:
            message = str(exc).lower()
            tolerated = _matches_any(message, MYSQL_PRIMARY_KEY_MISSING_TOKENS)
            if not tolerated:
                raise RuntimeError(exc) from exc
            LOGGER.debug(
                "Primary key on %s already missing (dialect=mysql)",
                plain_table,
            )
        return

    if dialect == "postgresql":
        schema_init = _qliteral(schema) if schema else "NULL"
        op.execute(
            f"""
        DO $$
        DECLARE
            schemaname text := {schema_init};
            pkname     text;
            tblname    text := {_qliteral(table_name)};
        BEGIN
            IF schemaname IS NULL THEN
                schemaname := current_schema();
            END IF;

            SELECT c.conname
              INTO pkname
              FROM pg_constraint c
              JOIN pg_class      r ON r.oid = c.conrelid
              JOIN pg_namespace  n ON n.oid = r.relnamespace
             WHERE c.contype = 'p'
               AND n.nspname = schemaname
               AND r.relname = tblname;

            IF pkname IS NOT NULL THEN
                EXECUTE format('ALTER TABLE %I.%I DROP CONSTRAINT %I',
                               schemaname, tblname, pkname);
            END IF;
        END$$;
        """
        )
        return

    if dialect == "oracle":
        owner_expr = (
            f"UPPER({_qliteral(schema)})" if schema else "SYS_CONTEXT('USERENV','CURRENT_SCHEMA')"
        )
        tab_expr = f"UPPER({_qliteral(table_name)})"
        quoted_table = _quoted_table(table_name, schema)

        op.execute(
            f"""
        DECLARE
            v_cnt NUMBER;
        BEGIN
            SELECT COUNT(*)
              INTO v_cnt
              FROM ALL_CONSTRAINTS
             WHERE OWNER = {owner_expr}
               AND TABLE_NAME = {tab_expr}
               AND CONSTRAINT_TYPE = 'P';

            IF v_cnt > 0 THEN
                EXECUTE IMMEDIATE 'ALTER TABLE {quoted_table} DROP PRIMARY KEY';
            END IF;
        END;
        """
        )
        return

    LOGGER.debug(
        "Primary key drop on %s skipped; unsupported dialect treated as no-op",
        plain_table,
    )


def try_drop_primary_key(
        table_name: str,
        *,
        legacy_names: 'Iterable[str]' = (),
) -> None:
    """
    Drop the current primary key on *table_name* in an idempotent, backend-aware way,
    then (optionally) drop a few caller-specified legacy constraint names that could
    collide with the new PK name you intend to create.

    This is a thin wrapper over :func:`drop_current_primary_key`.

    Parameters
    ----------
    table_name : str
        Table whose primary key should be removed.
    legacy_names : Iterable[str], optional
        Additional constraint names to drop *by name* after the current PK is removed.
        Use this only to avoid name collisions when re-creating the PK with a specific
        name (e.g., dropping an old ``TOKENS_PK`` that is not the current PK anymore).

    Notes
    -----
    * This helper does **not** drop dependent foreign keys; do that explicitly in
      the migration when required by the backend (e.g., MySQL/InnoDB).
    * Idempotent: repeating the call leaves the schema unchanged.
    """
    # Drop the actual current PK using the dialect-specific logic.
    drop_current_primary_key(table_name)

    # Optionally clean up a few known legacy names that could collide with the new PK name.
    for name in legacy_names or ():
        try_drop_constraint(name, table_name)


def try_create_table(*args: 'Any', **kwargs: 'Any') -> 'Optional[Table]':
    """
    Create a table only when it is absent, tolerating pre-existing objects.

    Parameters
    ----------
    *args : Any
        Positional arguments forwarded to Alembic. The first positional argument
        must be the table name.
    **kwargs : Any
        Keyword arguments forwarded to Alembic. If ``schema`` is not provided or
        is falsy, :func:`get_effective_schema` is injected.

    Returns
    -------
    Optional[Table]
        The SQLAlchemy ``Table`` object when the table is created; otherwise
        ``None`` when an existing table (regular or temporary) is detected and
        creation is skipped.

    Behavior by dialect
    -------------------
    * Oracle: checks both regular and global temporary tables via
      ``Inspector.get_table_names`` and ``Inspector.get_temp_table_names`` to
      avoid ``ORA-00955`` when temporary tables are pre-seeded.
    * Others: consults ``Inspector.get_table_names`` with the effective schema
      and, where supported, ``Inspector.get_temp_table_names`` as a best effort.

    Notes
    -----
    * Falls back to unconditional creation when no migration context or bind is
      available (e.g. offline SQL generation), mirroring the other helpers'
      best-effort semantics.
    * Keeps the default-schema behavior of :func:`create_table` so callers do
      not need to repeat the schema argument.

    Examples
    --------
    Idempotently create an auxiliary audit table in the migration schema:

    >>> try_create_table(
    ...     "tmp_account_audit",
    ...     sa.Column("id", sa.Integer(), primary_key=True),
    ...     sa.Column("account", sa.String(25), nullable=False),
    ... )
    """

    if not args:
        raise ValueError("create_table_if_missing requires a table name as the first argument")

    table_name = args[0]
    kwargs = _with_default_schema(dict(kwargs))
    schema = kwargs.get("schema")
    dialect = _dialect_name()
    ctx = get_migration_context()
    bind = getattr(ctx, "bind", None) if ctx else None

    if dialect is None:
        _warn_unknown_dialect_once()

    inspector = None
    if bind is not None:
        try:
            inspector = sa.inspect(bind)
        except Exception:
            inspector = None

    if inspector is not None:
        target = table_name.lower()
        existing_tables = {tbl.lower() for tbl in inspector.get_table_names(schema=schema)}
        if target in existing_tables:
            LOGGER.debug(
                "Table %s already exists; create_table_if_missing treated as no-op", _quoted_table(table_name, schema)
            )
            return None

        temp_tables: 'Iterable[str]'
        try:
            temp_tables = inspector.get_temp_table_names()
        except Exception:
            temp_tables = ()

        if target in {tbl.lower() for tbl in temp_tables}:
            LOGGER.debug(
                "Temporary table %s already exists; create_table_if_missing treated as no-op",
                _quoted_table(table_name, schema),
            )
            return None

    elif ctx is not None and bind is None:
        LOGGER.debug(
            "create_table_if_missing falling back to unconditional creation; migration context has no bind",
        )
    else:
        LOGGER.debug(
            "create_table_if_missing falling back to unconditional creation; no migration context available",
        )

    return op.create_table(*args, **kwargs)


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
    "drop_constraint",
    "drop_current_primary_key",
    "drop_index",
    "drop_table",
    "get_current_dialect",
    "get_effective_schema",
    "get_identifier_preparer",
    "get_migration_context",
    "is_current_dialect",
    "qualify_index",
    "qualify_table",
    "quote_identifier",
    "rename_table",
    "try_create_table",
    "try_drop_constraint",
    "try_drop_index",
    "try_drop_primary_key",
]
