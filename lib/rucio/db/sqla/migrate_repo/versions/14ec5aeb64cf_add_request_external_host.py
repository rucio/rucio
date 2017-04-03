"""
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Mario Lassnig, <mario.lassnig@cern.ch>, 2014
  - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

add request external_host

Revision ID: 14ec5aeb64cf
Revises: 52fd9f4916fa
Create Date: 2014-08-22 13:25:22.132950

"""

from alembic.op import add_column, drop_column

import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '14ec5aeb64cf'  # pylint:disable=invalid-name
down_revision = '52fd9f4916fa'  # pylint:disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    add_column('requests', sa.Column('external_host', sa.String(256)))


def downgrade():
    '''
    downgrade method
    '''
    drop_column('requests', 'external_host')
