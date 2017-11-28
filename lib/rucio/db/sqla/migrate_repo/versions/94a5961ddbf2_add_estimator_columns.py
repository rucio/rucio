'''
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Joaquin Bogadog, <jbogadog@cern.ch>, 2017
add estimator columns at requeste table

Revision ID: d8a74228b483
Revises: c5c0418f31aa
Create Date: 2017-11-03 13:29:06.198850
'''
from alembic.op import add_column, drop_column

import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '94a5961ddbf2'  # pylint: disable=invalid-name
down_revision = '1c45d9730ca6'  # pylint: disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    add_column('requests', sa.Column('estimated_started_at', sa.DateTime()))
    add_column('requests', sa.Column('estimated_transferred_at', sa.DateTime()))


def downgrade():
    '''
    downgrade method
    '''
    drop_column('requests', 'estimated_started_at')
    drop_column('requests', 'estimated_transferred_at')
