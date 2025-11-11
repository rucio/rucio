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
"""Runtime startup checks shared by daemons and the REST application."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from rucio.common.startup_checks import register_startup_check
from rucio.db.sqla.session import get_session
from rucio.db.sqla.util import oracle_legacy_json_columns

if TYPE_CHECKING:
    from collections.abc import Sequence


logger = logging.getLogger(__name__)

LegacyColumn = tuple[str, str]

__all__ = ['legacy_oracle_json_columns', 'ensure_oracle_json_columns_are_native', 'register_all']


def legacy_oracle_json_columns() -> Sequence[LegacyColumn] | None:
    """Return legacy Oracle JSON columns or ``None`` when not using Oracle."""

    session_scoped = get_session()

    with session_scoped() as session:
        if session.bind.dialect.name != 'oracle':  # type: ignore[attr-defined]
            return None

        legacy = oracle_legacy_json_columns(session)

    # Normalise the return type to a tuple to keep a consistent, hashable type.
    return tuple(legacy)


def ensure_oracle_json_columns_are_native() -> None:
    """Ensure Oracle JSON columns were migrated to native types in 21c+."""

    legacy = legacy_oracle_json_columns()

    if legacy is None:
        logger.debug('Skipping Oracle JSON column check; database dialect is not Oracle.')
        return

    if not legacy:
        logger.info('Oracle JSON column check passed: all JSON columns use native types.')
        return

    formatted = ', '.join(f"{table}.{column}" for table, column in legacy)
    message = (
        'Oracle 21c+ requires native JSON columns. '
        f'The following columns remain legacy CLOBs: {formatted}'
    )

    logger.error(message)
    raise RuntimeError(message)


def register_all() -> None:
    """Register all built-in startup checks."""

    register_startup_check(
        name='oracle-json-columns',
        callback=ensure_oracle_json_columns_are_native,
        description='Ensure Oracle JSON columns are migrated to native types on 21c+',
        replace=True,
    )
