# -*- coding: utf-8 -*-
# Copyright 2015-2021 CERN
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
#
# Authors:
# - Vincent Garonne <vincent.garonne@cern.ch>, 2015-2017
# - Martin Barisits <martin.barisits@cern.ch>, 2016
# - Mario Lassnig <mario.lassnig@cern.ch>, 2019
# - Benedikt Ziemons <benedikt.ziemons@cern.ch>, 2021

''' added purge column to rules '''

import sqlalchemy as sa

from alembic import context
from alembic.op import add_column, drop_column, create_check_constraint


# Alembic revision identifiers
revision = 'd6dceb1de2d'
down_revision = '25821a8a45a3'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        add_column('rules', sa.Column('purge_replicas', sa.Boolean(name='RULES_PURGE_REPLICAS_CHK', create_constraint=True), default=False), schema=schema)
        create_check_constraint('RULES_PURGE_REPLICAS_NN', 'rules', "PURGE_REPLICAS IS NOT NULL")


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        drop_column('rules', 'purge_replicas', schema=schema)
