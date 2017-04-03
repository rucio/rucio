"""
  Copyright European Organization for Nuclear Research (CERN)

  Licensed under the Apache License, Version 2.0 (the "License");
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

  Authors:
  - Vincent Garonne, <vincent.garonne@cern.ch>, 2015-2017
  - Cedric Serfon, <cedric.serfon@cern.ch>, 2015

Index in rule_history on scope, name

Revision ID: 2f648fc909f3
Revises: 269fee20dee9
Create Date: 2015-07-21 13:04:18.896813

"""

from alembic.op import create_index, drop_index

# revision identifiers, used by Alembic.
revision = '2f648fc909f3'   # pylint:disable=invalid-name
down_revision = 'bb695f45c04'  # pylint:disable=invalid-name


def upgrade():
    '''
    upgrade method
    '''
    create_index('RULES_HISTORY_SCOPENAME_IDX', 'rules_history', ['scope', 'name'])


def downgrade():
    '''
    downgrade method
    '''
    drop_index('RULES_HISTORY_SCOPENAME_IDX', 'rules_history')
