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

"""add generic checksum column"""    # noqa: D400, D415

import sqlalchemy as sa
from alembic import context
from alembic.op import add_column, drop_column

# Alembic revision identifiers
revision = '8ab4d628cffb'
down_revision = '3b943000da18'


def upgrade():
    """Upgrade the database to this revision."""

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('replicas', sa.Column('checksum', sa.JSON(), nullable=True), schema=schema)
        add_column('dids', sa.Column('checksum', sa.JSON(), nullable=True), schema=schema)
        add_column('deleted_dids', sa.Column('checksum', sa.JSON(), nullable=True), schema=schema)
        add_column('quarantined_replicas', sa.Column('checksum', sa.JSON(), nullable=True), schema=schema)
        add_column('quarantined_replicas_history', sa.Column('checksum', sa.JSON(), nullable=True), schema=schema)
        add_column('contents', sa.Column('checksum', sa.JSON(), nullable=True), schema=schema)
        add_column('archive_contents', sa.Column('checksum', sa.JSON(), nullable=True), schema=schema)
        add_column('archive_contents_history', sa.Column('checksum', sa.JSON(), nullable=True), schema=schema)
        add_column('contents_history', sa.Column('checksum', sa.JSON(), nullable=True), schema=schema)
        add_column('requests', sa.Column('checksum', sa.JSON(), nullable=True), schema=schema)
        add_column('requests_history', sa.Column('checksum', sa.JSON(), nullable=True), schema=schema)


def downgrade():
    """Downgrade the database to the previous revision."""
    schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
    drop_column('replicas', 'checksum', schema=schema)
    drop_column('dids', 'checksum', schema=schema)
    drop_column('deleted_dids', 'checksum', schema=schema)
    drop_column('quarantined_replicas', 'checksum', schema=schema)
    drop_column('quarantined_replicas_history', 'checksum', schema=schema)
    drop_column('contents', 'checksum', schema=schema)
    drop_column('archive_contents', 'checksum', schema=schema)
    drop_column('archive_contents_history', 'checksum', schema=schema)
    drop_column('contents_history', 'checksum', schema=schema)
    drop_column('requests', 'checksum', schema=schema)
    drop_column('requests_history', 'checksum', schema=schema)
