'''
 Copyright European Organization for Nuclear Research (CERN)

 Licensed under the Apache License, Version 2.0 (the "License");
 You may not use this file except in compliance with the License.
 You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

 Authors:
 - Martin Barisits, <martin.barisits@cern.ch>, 2017

Add metadata to rule tables

Revision ID: 5673b4b6e843
Revises: e59300c8b179
Create Date: 2017-08-14 14:18:06.883909

'''
from alembic.op import (add_column, drop_column)

from alembic import context

import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5673b4b6e843'  # pylint: disable=invalid-name
down_revision = 'e59300c8b179'  # pylint: disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    add_column('rules', sa.Column('meta', sa.String(4000)))
    add_column('rules_history', sa.Column('meta', sa.String(4000)))
    add_column('rules_hist_recent', sa.Column('meta', sa.String(4000)))


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name not in ('sqlite'):  # pylint: disable=no-member
        drop_column('rules', 'meta')
        drop_column('rules_history', 'meta')
        drop_column('rules_hist_recent', 'meta')
