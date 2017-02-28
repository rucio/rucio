# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Wen Guan, <wen.guan@cern.ch>, 2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

"""create distance table

Revision ID: 4783c1f49cb4
Revises: 277b5fbb41d3
Create Date: 2015-05-21 08:11:14.318464

"""

from alembic.op import (create_table, create_primary_key, create_foreign_key,
                        create_check_constraint, create_index, drop_table)
from alembic import context
import sqlalchemy as sa

from rucio.db.sqla.types import GUID

# revision identifiers, used by Alembic.
revision = '4783c1f49cb4'
down_revision = '277b5fbb41d3'


def upgrade():
    '''
    upgrade method
    '''
    create_table('distances',
                 sa.Column('src_rse_id', GUID()),
                 sa.Column('dest_rse_id', GUID()),
                 sa.Column('ranking', sa.Integer),
                 sa.Column('agis_distance', sa.Integer),
                 sa.Column('geoip_distance', sa.Integer),
                 sa.Column('updated_at', sa.DateTime),
                 sa.Column('created_at', sa.DateTime))

    if context.get_context().dialect.name != 'sqlite':
        create_primary_key('DISTANCES_PK', 'distances', ['src_rse_id', 'dest_rse_id'])
        create_foreign_key('DISTANCES_SRC_RSES_FK', 'distances', 'rses', ['src_rse_id'], ['id'])
        create_foreign_key('DISTANCES_DEST_RSES_FK', 'distances', 'rses', ['dest_rse_id'], ['id'])
        create_check_constraint('DISTANCES_CREATED_NN', 'distances', 'created_at is not null')
        create_check_constraint('DISTANCES_UPDATED_NN', 'distances', 'updated_at is not null')
        create_index('DISTANCES_DEST_RSEID_IDX', 'distances', ['dest_rse_id'])


def downgrade():
    '''
    downgrade method
    '''
    drop_table('distances')
