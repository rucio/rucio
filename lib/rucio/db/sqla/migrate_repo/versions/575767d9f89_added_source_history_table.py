"""
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2015-2017

added source history table

Revision ID: 575767d9f89
Revises: 379a19b5332d
Create Date: 2015-10-29 11:56:09.820585

"""
from alembic.op import create_table, add_column, drop_column, drop_table
from alembic import context
import sqlalchemy as sa

from rucio.db.sqla.types import GUID

# revision identifiers, used by Alembic.
revision = '575767d9f89'  # pylint:disable=invalid-name
down_revision = '379a19b5332d'  # pylint:disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name not in ['sqlite']:
        create_table('sources_history',
                     sa.Column('request_id', GUID()),
                     sa.Column('scope', sa.String(25)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('rse_id', GUID()),
                     sa.Column('dest_rse_id', GUID()),
                     sa.Column('url', sa.String(2048)),
                     sa.Column('bytes', sa.BigInteger),
                     sa.Column('ranking', sa.Integer()),
                     sa.Column('is_using', sa.Boolean(), default=False))
        add_column('requests', sa.Column('estimated_at', sa.DateTime))
        add_column('requests_history', sa.Column('estimated_at', sa.DateTime))


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name not in ['sqlite']:
        drop_column('requests', 'estimated_at')
        drop_column('requests_history', 'estimated_at')
        drop_table('sources_history')
