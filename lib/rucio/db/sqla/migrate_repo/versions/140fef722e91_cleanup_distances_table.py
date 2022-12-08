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

''' cleanup distances table '''

import sqlalchemy as sa

from alembic import context
from alembic.op import add_column, drop_column, alter_column

# Alembic revision identifiers
revision = '140fef722e91'
down_revision = '13d4f70c66a9'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_column('distances', 'agis_distance', schema=schema)
        drop_column('distances', 'geoip_distance', schema=schema)
        drop_column('distances', 'active', schema=schema)
        drop_column('distances', 'submitted', schema=schema)
        drop_column('distances', 'finished', schema=schema)
        drop_column('distances', 'failed', schema=schema)
        drop_column('distances', 'transfer_speed', schema=schema)
        drop_column('distances', 'packet_loss', schema=schema)
        drop_column('distances', 'latency', schema=schema)
        drop_column('distances', 'mbps_file', schema=schema)
        drop_column('distances', 'mbps_link', schema=schema)
        drop_column('distances', 'queued_total', schema=schema)
        drop_column('distances', 'done_1h', schema=schema)
        drop_column('distances', 'done_6h', schema=schema)

        alter_column('distances', 'ranking', existing_type=sa.Integer, new_column_name='distance', schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:

        alter_column('distances', 'distance', existing_type=sa.Integer, new_column_name='ranking', schema=schema)

        add_column('distances', sa.Column('agis_distance', sa.Integer), schema=schema)
        add_column('distances', sa.Column('geoip_distance', sa.Integer), schema=schema)
        add_column('distances', sa.Column('active', sa.Integer), schema=schema)
        add_column('distances', sa.Column('submitted', sa.Integer), schema=schema)
        add_column('distances', sa.Column('finished', sa.Integer), schema=schema)
        add_column('distances', sa.Column('failed', sa.Integer), schema=schema)
        add_column('distances', sa.Column('transfer_speed', sa.Integer), schema=schema)
        add_column('distances', sa.Column('packet_loss', sa.Integer), schema=schema)
        add_column('distances', sa.Column('latency', sa.Integer), schema=schema)
        add_column('distances', sa.Column('mbps_file', sa.Integer), schema=schema)
        add_column('distances', sa.Column('mbps_link', sa.Integer), schema=schema)
        add_column('distances', sa.Column('queued_total', sa.Integer), schema=schema)
        add_column('distances', sa.Column('done_1h', sa.Integer), schema=schema)
        add_column('distances', sa.Column('done_6h', sa.Integer), schema=schema)
