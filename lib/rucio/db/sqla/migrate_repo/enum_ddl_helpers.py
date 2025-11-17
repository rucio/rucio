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

from .ddl_helpers import get_effective_schema, quote_identifier

if TYPE_CHECKING:
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


__all__ = [
    "render_enum_name",
]
