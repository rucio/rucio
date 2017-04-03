"""
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Vincent Garonne, <vincent.garonne@cern.ch>, 2014-2017
  - Cedric Serfon, <cedric.serfon@cern.ch>, 2014
  - Mario Lassnig, <mario.lassnig@cern.ch>, 2014

Add availability column to table RSEs

Revision ID: 22cf51430c78
Revises: 49a21b4d4357
Create Date: 2014-06-12 14:54:23.160946

"""

from alembic.op import add_column, drop_column

import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '22cf51430c78'  # pylint:disable=invalid-name
down_revision = '49a21b4d4357'  # pylint:disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    add_column('rses', sa.Column('availability', sa.Integer, server_default='7'))


def downgrade():
    '''
    downgrade method
    '''
    drop_column('rses', 'availability')
