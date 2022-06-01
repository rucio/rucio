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

''' create transfer hops table '''

import datetime

import sqlalchemy as sa

from alembic import context
from alembic.op import (create_table, create_primary_key, create_foreign_key,
                        create_check_constraint, create_index, drop_table)

from rucio.db.sqla.types import GUID


# Alembic revision identifiers
revision = '0f1adb7a599a'
down_revision = '9a45bc4ea66d'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('transfer_hops',
                     sa.Column('request_id', GUID()),
                     sa.Column('next_hop_request_id', GUID()),
                     sa.Column('initial_request_id', GUID()),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))

        create_primary_key('TRANSFER_HOPS_PK', 'transfer_hops', ['request_id', 'next_hop_request_id', 'initial_request_id'])
        create_foreign_key('TRANSFER_HOPS_INIT_REQ_ID_FK', 'transfer_hops', 'requests', ['initial_request_id'], ['id'])
        create_foreign_key('TRANSFER_HOPS_REQ_ID_FK', 'transfer_hops', 'requests', ['request_id'], ['id'])
        create_foreign_key('TRANSFER_HOPS_NH_REQ_ID_FK', 'transfer_hops', 'requests', ['next_hop_request_id'], ['id'])
        create_check_constraint('TRANSFER_HOPS_CREATED_NN', 'transfer_hops', 'created_at is not null')
        create_check_constraint('TRANSFER_HOPS_UPDATED_NN', 'transfer_hops', 'updated_at is not null')
        create_index('TRANSFER_HOPS_INITIAL_REQ_IDX', 'transfer_hops', ['initial_request_id'])
        create_index('TRANSFER_HOPS_NH_REQ_IDX', 'transfer_hops', ['next_hop_request_id'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('transfer_hops')
