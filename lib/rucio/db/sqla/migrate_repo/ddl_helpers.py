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

from typing import TYPE_CHECKING

from alembic import context, op

if TYPE_CHECKING:
    from typing import Optional

    from alembic.runtime.migration import MigrationContext


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


__all__ = [
    "is_current_dialect",
    "get_effective_schema",
]
