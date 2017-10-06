'''
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

Added INCOMPLETE state

Revision ID: c5c0418f31aa
Revises: b4293a99f344
Create Date: 2017-09-21 15:02:41.011358

'''
from alembic.op import create_check_constraint, drop_constraint

from alembic import context

# revision identifiers, used by Alembic.
revision = 'c5c0418f31aa'  # pylint: disable=invalid-name
down_revision = 'b4293a99f344'  # pylint: disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        drop_constraint('DIDS_AVAILABILITY_CHK', 'dids')
        drop_constraint('DEL_DIDS_AVAIL_CHK', 'deleted_dids')
        create_check_constraint(name='DIDS_AVAILABILITY_CHK',
                                source='dids',
                                condition="availability in ('L', 'D', 'A', 'I')")
        create_check_constraint(name='DEL_DIDS_AVAIL_CHK',
                                source='deleted_dids',
                                condition="availability in ('L', 'D', 'A', 'I')")


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name != 'sqlite':
        drop_constraint('DIDS_AVAILABILITY_CHK', 'dids')
        drop_constraint('DEL_DIDS_AVAIL_CHK', 'deleted_dids')
        create_check_constraint(name='DIDS_AVAILABILITY_CHK',
                                source='dids',
                                condition="availability in ('L', 'D', 'A')")
        create_check_constraint(name='DEL_DIDS_AVAIL_CHK',
                                source='deleted_dids',
                                condition="availability in ('L', 'D', 'A')")
