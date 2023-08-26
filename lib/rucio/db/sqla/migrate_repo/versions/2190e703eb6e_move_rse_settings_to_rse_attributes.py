# -*- coding: utf-8 -*-
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

""" move rse settings to rse attributes """

import sqlalchemy as sa
from alembic import context
from alembic.op import get_bind

from rucio.db.sqla.types import GUID, BooleanString

# Alembic revision identifiers
revision = "2190e703eb6e"
down_revision = "f41ffe206f37"


def get_changed_rse_settings():
    return [
        ("city", sa.String(255)),
        ("region_code", sa.String(2)),
        ("country_name", sa.String(255)),
        ("continent", sa.String(2)),
        ("time_zone", sa.String(255)),
        ("ISP", sa.String(255)),
        ("ASN", sa.String(255)),
    ]


def get_schema():
    return context.get_context().version_table_schema \
        if context.get_context().version_table_schema \
        else ""


def get_rse_attr_association():
    return sa.sql.table(
        "rse_attr_map",
        sa.Column("rse_id", GUID()),
        sa.Column("key", sa.String(255)),
        sa.Column("value", BooleanString(255)),
        sa.Column("created_at", sa.DateTime),
        sa.Column("updated_at", sa.DateTime),
        schema=get_schema(),
    )


def upgrade():
    """
    Upgrade the database to this revision
    """
    if context.get_context().dialect.name in ["oracle", "mysql", "postgresql"]:
        conn = get_bind()
        for setting, setting_datatype in get_changed_rse_settings():
            rse_table = sa.sql.table(
                "rses",
                sa.Column("id", GUID()),
                sa.Column(setting, setting_datatype),
                sa.Column("created_at", sa.DateTime),
                sa.Column("updated_at", sa.DateTime),
                schema=get_schema(),
            )

            select_stmt = (
                sa.select(
                    sa.column("id").label("rse_id"),
                    sa.literal(setting).label("key"),
                    sa.column(setting).label("value"),
                    sa.column("created_at"),
                    sa.column("updated_at"),
                )
                .select_from(rse_table)
                .where(sa.column(setting) != None)  # noqa: E711
            )

            conn.execute(
                sa.insert((get_rse_attr_association())).from_select(
                    ["rse_id", "key", "value", "created_at", "updated_at"], select_stmt
                )
            )


def downgrade():
    """
    Downgrade the database to the previous revision
    """
    if context.get_context().dialect.name in ["oracle", "mysql", "postgresql"]:
        conn = get_bind()
        for setting, setting_datatype in get_changed_rse_settings():
            rse_table = sa.sql.table(
                "rses",
                sa.Column("id", GUID()),
                sa.Column(setting, setting_datatype),
                schema=get_schema(),
            )

            rse_attr_association = sa.sql.table(
                "rse_attr_map",
                sa.Column("rse_id", GUID()),
                sa.Column("key", sa.String(255)),
                sa.Column("value", BooleanString(255)),
                schema=get_schema(),
            )

            # Oracle needs the sub-query, since multi-table updates are not supported.
            select_stmt = (
                sa.select(rse_attr_association.c.value)
                .where(
                    rse_table.c.id == rse_attr_association.c.rse_id,
                    rse_attr_association.c.key == setting,
                )
                .limit(1)
                .scalar_subquery()
            )

            conn.execute(
                sa.update(rse_table).values(
                    {setting: select_stmt}
                )
            )

            conn.execute(
                rse_attr_association.delete().where(rse_attr_association.c.key == setting)
            )
