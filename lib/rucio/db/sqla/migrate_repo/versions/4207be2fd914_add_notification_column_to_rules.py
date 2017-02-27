# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2014
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

"""Add notification column to rules

Revision ID: 4207be2fd914
Revises: 14ec5aeb64cf
Create Date: 2014-09-29 15:32:16.342473

"""
from alembic.op import add_column, drop_constraint, drop_column
from alembic import context

import sqlalchemy as sa

from rucio.db.sqla.constants import RuleNotification

# revision identifiers, used by Alembic.
revision = '4207be2fd914'
down_revision = '14ec5aeb64cf'


def upgrade():
    '''
    upgrade method
    '''
    add_column('rules', sa.Column('notification', RuleNotification.db_type(name='RULES_NOTIFICATION_CHK'), default=RuleNotification.NO))


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name not in ('sqlite', 'mysql'):
        drop_constraint('RULES_NOTIFICATION_CHK', 'rules', type_='check')
    drop_column('rules', 'notification')
