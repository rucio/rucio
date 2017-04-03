"""
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Vincent Garonne, <vincent.garonne@cern.ch>, 2014-2017

 create index on table replicas(path)

Revision ID: 16a0aca82e12
Revises: None
Create Date: 2014-02-20 09:35:24.044458

"""

from alembic.op import create_index, drop_index

# revision identifiers, used by Alembic.
revision = '16a0aca82e12'  # pylint:disable=invalid-name
down_revision = None  # pylint:disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    create_index('REPLICAS_PATH_IDX', 'replicas', ['path'])


def downgrade():
    '''
    downgrade method
    '''
    drop_index('REPLICAS_PATH_IDX', 'replicas')
