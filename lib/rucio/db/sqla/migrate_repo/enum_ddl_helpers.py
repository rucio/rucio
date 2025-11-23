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

from alembic import op

from .ddl_helpers import (
    get_current_dialect,
    get_effective_schema,
    quote_identifier
    quote_literal,
)

if TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import Optional


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


__all__ = [
    "drop_enum_sql",
    "enum_values_clause",
    "render_enum_name",
    "try_drop_enum",
]
