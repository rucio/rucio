"""
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Vincent Garonne, <vincent.garonne@cern.ch>, 2015-2017

 Added third_party_copy column to rse_protocols

Revision ID: fe8ea2fa9788
Revises: 0437a40dbfd1
Create Date: 2016-08-25 13:26:40.642215

"""

from alembic.op import add_column, drop_column
from alembic import context

import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fe8ea2fa9788'  # pylint: disable=invalid-name
down_revision = '0437a40dbfd1'  # pylint: disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name not in ('sqlite'):
        add_column('rse_protocols', sa.Column('third_party_copy', sa.Integer, server_default='0'))


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name not in ('sqlite'):
        drop_column('rse_protocols', 'third_party_copy')
