'''
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Martin Barisits, <martin.barisits@cern.ch>, 2014
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

Removing created_at index

Revision ID: 469d262be19
Revises: 16a0aca82e12
Create Date: 2014-04-16 14:52:30.562161
'''
from alembic.op import create_index, drop_index


# revision identifiers, used by Alembic.
revision = '469d262be19'  # pylint: disable=invalid-name
down_revision = '16a0aca82e12'  # pylint: disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    create_index('UPDATED_DIDS_SCOPERULENAME_IDX', 'updated_dids', ['scope', 'rule_evaluation_action', 'name'])
    drop_index('CREATED_AT_IDX', 'updated_dids')


def downgrade():
    '''
    downgrade method
    '''
    drop_index('UPDATED_DIDS_SCOPERULENAME_IDX', 'updated_dids')
    create_index('CREATED_AT_IDX', 'updated_dids', ['created_at'])
