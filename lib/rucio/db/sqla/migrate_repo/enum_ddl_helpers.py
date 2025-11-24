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
PostgreSQL enum DDL helpers for Alembic migrations.

The functions in this module build raw SQL strings for enum-related DDL that
Alembic can execute with `alembic.op.execute`.  Each helper focuses on a
single operation so that migrations remain explicit and easy to review. The
offered helpers span the meaningful enum operations PostgreSQL allows.
"""

from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql as pg

from .ddl_helpers import (
    get_current_dialect,
    get_effective_schema,
    get_server_version_info,
    quote_identifier,
    quote_literal,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from typing import Optional, Union


def _validate_identifier(
        name: str,
        *,
        allow_qualified: bool = False
) -> None:
    """
    Validate that *name* satisfies PostgreSQL identifier requirements.

    The following constraints are enforced:

    * identifiers must be strings and non-empty;
    * unqualified identifiers must not contain dots when ``allow_qualified`` is ``False``;
    * qualified identifiers must not contain empty segments or exceed the 63-byte limit per segment;
    * the NUL byte (``"\\x00"``) is rejected in every case.

    Parameters
    ----------
    name : str
        Identifier to validate. May be schema-qualified when *allow_qualified* is ``True``.
    allow_qualified : bool, optional
        Whether to allow a ``schema.name`` qualified identifier. Default is ``False``.

    Raises
    ------
    TypeError
        If *name* (or a qualified segment) is not a string.
    ValueError
        If *name* is empty, contains the NUL byte, is qualified when not allowed,
        or any segment exceeds 63 bytes.

    Examples
    --------
    >>> _validate_identifier("request_state")
    >>> _validate_identifier("rucio.request_state", allow_qualified=True)
    """

    def _check(part: str) -> None:
        """
        Validate a single, unqualified identifier segment.

        Parameters
        ----------
        part : str
            The identifier to validate. Must be a non-empty string with no NUL bytes
            and at most 63 bytes when encoded as UTF-8.

        Raises
        ------
        TypeError
            If ``part`` is not a string.
        ValueError
            If ``part`` is empty, contains NUL bytes, or exceeds the 63‑byte
            PostgreSQL name length limit (63 bytes).
        """
        if not isinstance(part, str):
            raise TypeError("Identifier must be a string.")
        if part == "":
            raise ValueError("Identifier must be a non-empty string.")
        if "\x00" in part:
            raise ValueError("Identifier must not contain NUL (\\x00) bytes.")
        if len(part.encode("utf-8")) > 63:
            raise ValueError("Identifier must be at most 63 bytes in UTF-8.")

    if not isinstance(name, str):
        raise TypeError("Identifier must be a string.")

    if not allow_qualified and "." in name:
        raise ValueError("Identifier must be unqualified; pass schema separately.")

    if allow_qualified and "." in name:
        for segment in name.split("."):
            _check(segment)
    else:
        _check(name)


def _validate_enum_labels(values: 'Iterable[str]') -> tuple[str, ...]:
    """
    Validate enum labels and return them in a tuple.

    The check rejects ``None`` values, empty strings, duplicate entries, labels
    longer than 63 bytes in UTF-8, and any label containing the NUL byte. The
    original ordering is preserved so the resulting tuple may be fed straight
    into ``CREATE TYPE ... AS ENUM``.

    Parameters
    ----------
    values : Iterable[str]
        Iterable of labels to validate.

    Returns
    -------
    tuple[str, ...]
        Validated labels, in the order supplied.

    Raises
    ------
    TypeError
        If *values* is a string instead of an iterable, or any label is not a
        string (excluding ``None`` values, which raise ``ValueError``).
    ValueError
        If no labels are supplied, or any label is ``None`` or empty, contains
        the NUL byte, exceeds 63 bytes in UTF‑8, or duplicates another label.

    Examples
    --------
    >>> _validate_enum_labels(["FILE", "DATASET", "CONTAINER"])
    ('FILE', 'DATASET', 'CONTAINER')
    """

    if isinstance(values, str):
        raise TypeError("Enum labels must be provided as an iterable of strings, not a single string.")

    labels = tuple(values)
    if not labels:
        raise ValueError("Enum labels iterable must not be empty.")

    seen = set()
    for label in labels:
        if label is None:
            raise ValueError("Enum labels must not be None.")
        if not isinstance(label, str):
            raise TypeError("Enum labels must be strings.")
        if label == "":
            raise ValueError("Enum labels must be non-empty strings.")
        if "\x00" in label:
            raise ValueError("Enum labels must not contain NUL (\\x00) bytes.")
        if len(label.encode("utf-8")) > 63:
            raise ValueError("Enum labels must be at most 63 bytes in UTF-8.")
        if label in seen:
            raise ValueError("Enum labels must be unique.")
        seen.add(label)
    return labels


def _assert_postgresql() -> None:
    """
    Ensure the active Alembic dialect is PostgreSQL (or unknown/offline).

    The helpers are implemented exclusively for PostgreSQL. When the dialect is
    known and differs, a clear exception is raised. Uses the shared helpers so
    that offline SQL rendering (no live MigrationContext) is also checked.

    Raises
    ------
    NotImplementedError
        If the current dialect is known and not PostgreSQL.

    Examples
    --------
    >>> _assert_postgresql()  # no-op under PostgreSQL/unknown
    """

    name = get_current_dialect()
    if name is not None and name != "postgresql":
        raise NotImplementedError("These enum DDL helpers are for PostgreSQL only.")


def render_enum_name(
        name: str,
        schema: 'Optional[str]' = None
) -> str:
    """
    Render a schema-qualified, safely-quoted enum type name.

    What this does
    --------------
    * Validates that ``name`` is an unqualified PostgreSQL identifier
      (no dots, non-empty, <= 63 bytes, no NULs).
    * Chooses the effective schema:
      - ``schema`` argument if provided and non-empty; an empty string (``""``) is
        treated like ``None``, otherwise
      - `get_effective_schema` when available, else no schema.
    * Quotes schema and name with SQLAlchemy's identifier preparer so the
      result is safe to interpolate into raw SQL.

    Parameters
    ----------
    name : str
        Unqualified enum type name (e.g. ``"request_state"``).
    schema : Optional[str]
        Target schema. If ``None`` or an empty string (``""``), uses `get_effective_schema`
        when available; otherwise emits an unqualified type name.

    Returns
    -------
    str
        The fully rendered enum type identifier, quoted and optionally
        schema-qualified (i.e. either ``"schema"."name"`` or just ``"name"``).

    Raises
    ------
    TypeError
        If ``name`` or a non‑empty ``schema`` fails identifier type validation.
    ValueError
        If ``name`` is an invalid identifier value (empty string, contains NUL, or exceeds
        the 63‑byte limit), or a non‑empty ``schema`` violates the same constraints.

    Examples
    --------
    >>> render_enum_name("request_state", schema="rucio")
    '"rucio"."request_state"'
    >>> # falls back to Alembic's version_table_schema when present
    >>> render_enum_name("request_state")
    '"rucio"."request_state"'
    """

    _validate_identifier(name, allow_qualified=False)
    effective_schema = get_effective_schema() if schema in (None, "") else schema
    if effective_schema:
        _validate_identifier(effective_schema, allow_qualified=False)
        return f"{quote_identifier(effective_schema)}.{quote_identifier(name)}"
    return quote_identifier(name)


def enum_values_clause(
        values: 'Iterable[str]'
) -> str:
    """
    Return a comma-separated list of quoted enum labels.

    All labels are validated and then single-quoted for SQL, producing a
    fragment suitable for interpolating into ``CREATE TYPE ... AS ENUM``.

    Parameters
    ----------
    values : Iterable[str]
        Labels to include. Order is preserved and defines the enum's sort
        order within PostgreSQL.

    Returns
    -------
    str
        A fragment of the form ``'value1', 'value2', ...``.

    Raises
    ------
    TypeError
        If *values* is a string instead of an iterable, or any label is not a
        string.
    ValueError
        If no labels are supplied, or any label is ``None`` or empty, contains
        the NUL byte, exceeds 63 bytes in UTF‑8, or duplicates another label.

    Examples
    --------
    >>> enum_values_clause(["QUEUED", "SUBMITTED", "DONE"])
    "'QUEUED', 'SUBMITTED', 'DONE'"
    """

    validated = _validate_enum_labels(values)
    return ", ".join(quote_literal(value) for value in validated)


def create_enum_sql(
        name: str,
        values: 'Iterable[str]',
        *,
        schema: 'Optional[str]' = None,
        if_not_exists: bool = False,
) -> str:
    """
    Build a ``CREATE TYPE ... AS ENUM`` statement for PostgreSQL.

    This function only *constructs* SQL — it does not execute anything.
    Identifiers are validated and quoted; labels are validated, quoted and
    kept in the given order (which defines the enum's collation order).

    Parameters
    ----------
    name : str
        Unqualified enum type name.
    values : Iterable[str]
        Iterable of enum labels. Order defines the enum's sort ordering.
    schema : Optional[str]
        Target schema. If omitted, `get_effective_schema` is used when available;
        otherwise the type name is unqualified.
    if_not_exists : bool, optional
        Not implemented. Kept for parity with other helpers.
        Use :func:`create_enum_if_absent_sql` for idempotent creation.

    Returns
    -------
    str
        A single SQL statement, for example:
        ``CREATE TYPE "rucio"."request_state" AS ENUM ('QUEUED', 'SUBMITTED', 'DONE')``.

    Raises
    ------
    NotImplementedError
        If ``if_not_exists=True`` (use :func:`create_enum_if_absent_sql` instead).
    TypeError
        If ``name`` or any label fails type validation.
    ValueError
        If ``name`` or any label fails value validation (for example empty
        identifiers, ``None`` labels, NUL bytes, excessive length, or duplicates).

    Examples
    --------
    >>> from alembic import op
    >>> sql = create_enum_sql(
    ...     "request_state",
    ...     ["QUEUED", "SUBMITTED", "DONE", "FAILED"],
    ...     schema="rucio",
    ... )
    >>> op.execute(sql)
    """

    _assert_postgresql()
    if if_not_exists:
        raise NotImplementedError(
            "PostgreSQL lacks 'CREATE TYPE IF NOT EXISTS'; use create_enum_if_absent_sql()."
        )

    _validate_identifier(name, allow_qualified=False)
    validated_values = _validate_enum_labels(values)

    parts = ["CREATE TYPE", render_enum_name(name, schema), "AS ENUM (", enum_values_clause(validated_values), ")"]
    return " ".join(parts)


def drop_enum_sql(
        name: str,
        *,
        schema: 'Optional[str]' = None,
        if_exists: bool = True,
        cascade: bool = False,
) -> str:
    """
    Build a ``DROP TYPE`` statement for a PostgreSQL enum.

    Parameters
    ----------
    name : str
        Unqualified enum type name.
    schema : Optional[str]
        Schema of the type. If omitted, `get_effective_schema` is used when available;
        otherwise an unqualified name is emitted.
    if_exists : bool, default True
        Include ``IF EXISTS`` so the statement is idempotent.
    cascade : bool, default False
        Append ``CASCADE`` to drop dependent objects (use with care).

    Returns
    -------
    str
        The assembled SQL, e.g. ``DROP TYPE IF EXISTS "dev"."status"``.

    Raises
    ------
    TypeError
        If ``name`` is not a string (including ``None``).
    ValueError
        If ``name`` is an invalid identifier value (empty string, contains NUL,
        or exceeds the 63‑byte limit).

    Examples
    --------
    >>> from alembic import op
    >>> # Safe drop (no error if missing)
    >>> op.execute(drop_enum_sql("request_state", schema="rucio"))
    >>> # Force drop of dependents
    >>> op.execute(drop_enum_sql("request_state", schema="rucio", cascade=True))
    """

    _assert_postgresql()
    _validate_identifier(name, allow_qualified=False)

    parts = ["DROP TYPE"]
    if if_exists:
        parts.append("IF EXISTS")
    parts.append(render_enum_name(name, schema))
    if cascade:
        parts.append("CASCADE")
    return " ".join(parts)


def try_drop_enum(
        name: str,
        *,
        schema: 'Optional[str]' = None,
        if_exists: bool = True,
        cascade: bool = False,
) -> None:
    """
    Execute :func:`drop_enum_sql` via Alembic's :func:`op.execute`.

    This thin wrapper keeps migrations readable by skipping the explicit
    ``op.execute(drop_enum_sql(...))`` pattern when no additional SQL needs to
    be composed.

    Examples
    --------
    >>> try_drop_enum("request_state", schema="rucio")
    >>> try_drop_enum("request_state", schema="rucio", cascade=True)
    """

    op.execute(drop_enum_sql(
        name,
        schema=schema,
        if_exists=if_exists,
        cascade=cascade,
    ))


def alter_enum_add_value_sql(
        name: str,
        value: str,
        *,
        schema: 'Optional[str]' = None,
        before: 'Optional[str]' = None,
        after: 'Optional[str]' = None,
        if_not_exists: bool = False,
) -> str:
    """
    Build an ``ALTER TYPE ... ADD VALUE`` statement for PostgreSQL.

    The statement can place the new label before or after an existing label.
    On newer PostgreSQL versions, ``IF NOT EXISTS`` may be used to make the
    operation idempotent when the server supports it.

    Parameters
    ----------
    name : str
        Unqualified enum type name.
    value : str
        New label to add.
    schema : Optional[str]
        Optional schema where the type exists.
    before : Optional[str]
        Insert the new label before this existing label.
    after : Optional[str]
        Insert the new label after this existing label.
    if_not_exists : bool, optional
        If ``True``, prefer ``IF NOT EXISTS`` on PostgreSQL 9.3+; otherwise
        emit an idempotent DO block that ignores ``duplicate_object`` on
        older servers or when the version is unknown.

    Returns
    -------
    str
        A single SQL statement, e.g.:
        ``ALTER TYPE "rucio"."request_state" ADD VALUE IF NOT EXISTS 'ARCHIVED' AFTER 'DONE'``,
        or a small ``DO $$ ... $$`` block on older servers.

    Raises
    ------
    TypeError
        If ``name`` or any provided label (``value``, ``before``, ``after``)
        is not a string.
    ValueError
        If both ``before`` and ``after`` are provided; if a position label is
        empty or equals ``value``; or if any label is otherwise invalid
        (``None``, empty, contains NUL, or exceeds the 63‑byte limit).

    Notes
    -----
    * On PostgreSQL < 12, ``ALTER TYPE ... ADD VALUE`` cannot run inside a
      transaction block. On 12+, it can, but the new label remains unusable
      until the transaction commits.

    Examples
    --------
    >>> from alembic import op
    >>> # Add a value after an existing label
    >>> op.execute(alter_enum_add_value_sql("request_state", "ARCHIVED", after="DONE", schema="rucio"))
    >>> # Idempotent add (uses native IF NOT EXISTS when available; otherwise a DO block)
    >>> op.execute(alter_enum_add_value_sql(
    ...     "request_state",
    ...     "RETRYING",
    ...     before="SUBMITTED",
    ...     schema="rucio",
    ...     if_not_exists=True,
    ... ))
    """

    _assert_postgresql()
    _validate_identifier(name, allow_qualified=False)

    # Disallow contradictory positioning instructions explicitly.
    if before is not None and after is not None:
        raise ValueError("'before' and 'after' are mutually exclusive")

    # Validate the new label itself (type, length, NUL, emptiness, etc.).
    _validate_enum_labels((value,))

    # Empty position labels are rejected explicitly for clearer error messages.
    if before == "" or after == "":
        raise ValueError("Position labels (before/after) must be non-empty if provided.")

    # Validate position labels when supplied (they are enum labels, not identifiers).
    if before is not None:
        _validate_enum_labels((before,))
        if before == value:
            raise ValueError("'before' label cannot equal the value being added.")

    if after is not None:
        _validate_enum_labels((after,))
        if after == value:
            raise ValueError("'after' label cannot equal the value being added.")

    ver = get_server_version_info()

    # Build the core ALTER TYPE ... ADD VALUE statement parts
    parts = ["ALTER TYPE", render_enum_name(name, schema), "ADD VALUE"]

    use_do_block = False
    if if_not_exists:
        # "IF NOT EXISTS" for enum ADD VALUE is available on PG 9.3+.
        # For older or unknown versions, emit a DO block that ignores
        # duplicate_object to keep migrations idempotent.
        if ver and ver >= (9, 3):
            parts.append("IF NOT EXISTS")
        else:
            use_do_block = True

    parts.append(quote_literal(value))
    if before:
        parts.extend(["BEFORE", quote_literal(before)])
    elif after:
        parts.extend(["AFTER", quote_literal(after)])

    stmt = " ".join(parts)

    if use_do_block:
        return f"DO $$ BEGIN {stmt}; EXCEPTION WHEN duplicate_object THEN NULL; END $$ LANGUAGE plpgsql;"

    return stmt


def create_enum_if_absent_sql(
        name: str,
        values: 'Sequence[str]',
        *,
        schema: 'Optional[str]' = None,
) -> str:
    """
    Return a PL/pgSQL ``DO`` block that creates an enum only if missing.

    PostgreSQL lacks ``CREATE TYPE IF NOT EXISTS``. The block emitted here is
    the standard workaround; it traps ``duplicate_object`` and quietly skips the
    creation when the type already exists.

    Parameters
    ----------
    name : str
        Unqualified enum type name.
    values : Sequence[str]
        Enum labels. Order defines the enum's sort ordering.
    schema : Optional[str]
        Optional schema where the type should be created.

    Returns
    -------
    str
        A ``DO $$ ... $$`` block that creates the type if it does not exist.

    Caveats
    -------
    This pattern only guards against the presence of a type with the same name.
    It does not verify that an existing type's label set matches ``values``.
    If you need to reconcile label differences, use the other helpers to add/rename labels.

    Examples
    --------
    >>> from alembic import op
    >>> # Create the enum if it's not already present (idempotent)
    >>> op.execute(create_enum_if_absent_sql("did_type", ["FILE", "DATASET", "CONTAINER"], schema="rucio"))
    """

    create_stmt = create_enum_sql(name, values, schema=schema, if_not_exists=False)
    return f"DO $$ BEGIN {create_stmt}; EXCEPTION WHEN duplicate_object THEN NULL; END $$ LANGUAGE plpgsql;"


def try_create_enum_if_absent(
        name_or_enum: 'Union[str, "sa.Enum", "pg.ENUM"]',
        values: 'Optional[Sequence[str]]' = None,
        *,
        schema: 'Optional[str]' = None,
) -> None:
    """
    Execute :func:`create_enum_if_absent_sql` via Alembic's :func:`op.execute`.

    What this does
    --------------
    * Accepts either an explicit ``name``/``values`` pair or a SQLAlchemy
      ``Enum`` instance. This mirrors the flexibility offered by
      :mod:`alembic`'s operations objects while keeping migrations concise.
    * Validates that a usable name and value list are present before emitting
      DDL, raising clear errors otherwise.
    * Defers schema resolution to ``create_enum_if_absent_sql`` and
      ``render_enum_name``, reusing the central helper logic.

    Parameters
    ----------
    name_or_enum : str or sqlalchemy.Enum or sqlalchemy.dialects.postgresql.ENUM
        Either the unqualified enum name or a SQLAlchemy enum object whose
        ``name`` and ``enums`` attributes describe the type to create.
    values : Sequence[str] or None, optional
        Enum labels when *name_or_enum* is a string. Ignored when an enum
        object is provided. Required when supplying a name directly.
    schema : str or None, optional
        Optional schema where the type should be created. When an enum object
        is provided, this overrides ``enum.schema`` if supplied.

    Raises
    ------
    TypeError
        If *name_or_enum* is not a string or SQLAlchemy ``Enum`` instance.
    ValueError
        If enum labels are missing, the enum instance has no name, or its
        value list is empty.

    Examples
    --------
    >>> try_create_enum_if_absent("did_type", ["FILE", "DATASET", "CONTAINER"], schema="rucio")
    >>> did_type_enum = sa.Enum("FILE", "DATASET", "CONTAINER", name="did_type", schema="rucio")
    >>> try_create_enum_if_absent(did_type_enum)
    """

    if isinstance(name_or_enum, (sa.Enum, pg.ENUM)):
        enum_name = name_or_enum.name
        enum_values = name_or_enum.enums
        effective_schema = schema if schema is not None else name_or_enum.schema

        if not enum_name:
            raise ValueError("Enum must define a name before rendering DDL.")
        if not enum_values:
            raise ValueError("Enum must declare at least one value before rendering DDL.")

    elif isinstance(name_or_enum, str):
        if values is None:
            raise ValueError("Enum values must be provided when specifying a name explicitly.")

        enum_name = name_or_enum
        enum_values = values
        effective_schema = schema

    else:
        raise TypeError("try_create_enum_if_absent expects either a name or a SQLAlchemy Enum instance.")

    op.execute(create_enum_if_absent_sql(enum_name, enum_values, schema=effective_schema))


def try_alter_enum_add_value(
        name: str,
        value: str,
        *,
        schema: 'Optional[str]' = None,
        before: 'Optional[str]' = None,
        after: 'Optional[str]' = None,
        if_not_exists: bool = False,
) -> None:
    """
    Execute :func:`alter_enum_add_value_sql` via Alembic's :func:`op.execute`.

    This wrapper mirrors :func:`try_drop_enum` to keep migrations concise when
    no additional SQL composition is required.

    Examples
    --------
    >>> try_alter_enum_add_value("request_state", "ARCHIVED", after="DONE", schema="rucio")
    >>> try_alter_enum_add_value(
    ...     "request_state",
    ...     "RETRYING",
    ...     before="SUBMITTED",
    ...     schema="rucio",
    ...     if_not_exists=True,
    ... )
    """

    op.execute(alter_enum_add_value_sql(
        name,
        value,
        schema=schema,
        before=before,
        after=after,
        if_not_exists=if_not_exists,
    ))


__all__ = [
    "alter_enum_add_value_sql",
    "create_enum_if_absent_sql",
    "create_enum_sql",
    "drop_enum_sql",
    "enum_values_clause",
    "render_enum_name",
    "try_alter_enum_add_value",
    "try_create_enum_if_absent",
    "try_drop_enum",
]
