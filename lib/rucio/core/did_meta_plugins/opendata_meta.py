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

from typing import TYPE_CHECKING

from sqlalchemy import and_, false, null
from sqlalchemy.sql.expression import case, select, true

from rucio.db.sqla import models

if TYPE_CHECKING:
    from sqlalchemy.sql.selectable import Select


def add_is_opendata_column(stmt: "Select") -> "Select":
    opendata_subquery = select(
        models.OpenDataDid.scope,
        models.OpenDataDid.name
    ).subquery()

    return stmt.add_columns(
        case(
            (opendata_subquery.c.scope.isnot(null()), true()),
            else_=false()
        ).label("is_opendata")
    ).outerjoin(
        opendata_subquery,
        and_(
            models.DataIdentifier.scope == opendata_subquery.c.scope,
            models.DataIdentifier.name == opendata_subquery.c.name
        )
    )
