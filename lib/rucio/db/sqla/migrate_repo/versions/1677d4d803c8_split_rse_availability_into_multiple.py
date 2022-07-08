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

""" split rse availability into multiple """

import sqlalchemy as sa
from alembic import context
from alembic.op import add_column, drop_column, get_bind
from sqlalchemy.sql.expression import true

from rucio.db.sqla.types import GUID

# Alembic revision identifiers
revision = "1677d4d803c8"
down_revision = "fe1a65b176c9"


def upgrade():
    """
    Upgrade the database to this revision
    """

    if context.get_context().dialect.name in ["oracle", "mysql", "postgresql"]:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ""

        add_column("rses", sa.Column("availability_read", sa.Boolean, server_default=true()), schema=schema)
        add_column("rses", sa.Column("availability_write", sa.Boolean, server_default=true()), schema=schema)
        add_column("rses", sa.Column("availability_delete", sa.Boolean, server_default=true()), schema=schema)

        RSE = sa.sql.table(
            "rses",
            sa.Column("id", GUID()),
            sa.Column("availability", sa.Integer),
            sa.Column("availability_read", sa.Boolean, server_default=true()),
            sa.Column("availability_write", sa.Boolean, server_default=true()),
            sa.Column("availability_delete", sa.Boolean, server_default=true()),
            schema=schema,
        )

        conn = get_bind()

        conn.execute(RSE.update().where(RSE.c.availability.in_([0, 1, 2, 3])).values({"availability_read": False}))
        conn.execute(RSE.update().where(RSE.c.availability.in_([0, 1, 4, 5])).values({"availability_write": False}))
        conn.execute(RSE.update().where(RSE.c.availability.in_([0, 2, 4, 6])).values({"availability_delete": False}))


def downgrade():
    """
    Downgrade the database to the previous revision
    """

    if context.get_context().dialect.name in ["oracle", "mysql", "postgresql"]:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ""

        drop_column("rses", "availability_read", schema=schema)
        drop_column("rses", "availability_write", schema=schema)
        drop_column("rses", "availability_delete", schema=schema)
