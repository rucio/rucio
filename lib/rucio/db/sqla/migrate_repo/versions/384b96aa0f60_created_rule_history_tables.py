# Copyright European Organization for Nuclear Research (CERN)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Authors:
# - Martin Barisits, <martin.barisits@cern.ch>, 2015
# - Vincent Garonne, <vincent.garonne@cern.ch>, 2017

"""Created rule history tables

Revision ID: 384b96aa0f60
Revises: 271a46ea6244
Create Date: 2015-01-21 15:30:23.689422

"""

from alembic import context
from alembic.op import create_table, create_index, drop_table, drop_index
import sqlalchemy as sa

from rucio.db.sqla.constants import (DIDType, RuleGrouping, RuleState, RuleNotification)
from rucio.db.sqla.types import GUID

# revision identifiers, used by Alembic.
revision = '384b96aa0f60'
down_revision = '4cf0a2e127d4'


def upgrade():
    '''
    upgrade method
    '''
    create_table('rules_hist_recent',
                 sa.Column('history_id', GUID()),
                 sa.Column('id', GUID()),
                 sa.Column('subscription_id', GUID()),
                 sa.Column('account', sa.String(25)),
                 sa.Column('scope', sa.String(25)),
                 sa.Column('name', sa.String(255)),
                 sa.Column('did_type', DIDType.db_type()),
                 sa.Column('state', RuleState.db_type()),
                 sa.Column('error', sa.String(255)),
                 sa.Column('rse_expression', sa.String(255)),
                 sa.Column('copies', sa.SmallInteger),
                 sa.Column('expires_at', sa.DateTime),
                 sa.Column('weight', sa.String(255)),
                 sa.Column('locked', sa.Boolean()),
                 sa.Column('locks_ok_cnt', sa.BigInteger),
                 sa.Column('locks_replicating_cnt', sa.BigInteger),
                 sa.Column('locks_stuck_cnt', sa.BigInteger),
                 sa.Column('source_replica_expression', sa.String(255)),
                 sa.Column('activity', sa.String(50)),
                 sa.Column('grouping', RuleGrouping.db_type()),
                 sa.Column('notification', RuleNotification.db_type()),
                 sa.Column('stuck_at', sa.DateTime),
                 sa.Column('purge_replicas', sa.Boolean()),
                 sa.Column('ignore_availability', sa.Boolean()),
                 sa.Column('updated_at', sa.DateTime),
                 sa.Column('created_at', sa.DateTime))
    create_table('rules_history',
                 sa.Column('history_id', GUID()),
                 sa.Column('id', GUID()),
                 sa.Column('subscription_id', GUID()),
                 sa.Column('account', sa.String(25)),
                 sa.Column('scope', sa.String(25)),
                 sa.Column('name', sa.String(255)),
                 sa.Column('did_type', DIDType.db_type()),
                 sa.Column('state', RuleState.db_type()),
                 sa.Column('error', sa.String(255)),
                 sa.Column('rse_expression', sa.String(255)),
                 sa.Column('copies', sa.SmallInteger),
                 sa.Column('expires_at', sa.DateTime),
                 sa.Column('weight', sa.String(255)),
                 sa.Column('locked', sa.Boolean()),
                 sa.Column('locks_ok_cnt', sa.BigInteger),
                 sa.Column('locks_replicating_cnt', sa.BigInteger),
                 sa.Column('locks_stuck_cnt', sa.BigInteger),
                 sa.Column('source_replica_expression', sa.String(255)),
                 sa.Column('activity', sa.String(50)),
                 sa.Column('grouping', RuleGrouping.db_type()),
                 sa.Column('notification', RuleNotification.db_type()),
                 sa.Column('stuck_at', sa.DateTime),
                 sa.Column('purge_replicas', sa.Boolean()),
                 sa.Column('ignore_availability', sa.Boolean()),
                 sa.Column('updated_at', sa.DateTime),
                 sa.Column('created_at', sa.DateTime))
    if context.get_context().dialect.name != 'sqlite':
        create_index('RULES_HIST_RECENT_ID_IDX', 'rules_hist_recent', ["id"])


def downgrade():
    '''
    downgrade method
    '''
    if context.get_context().dialect.name is 'postgresql':
        drop_index('RULES_HIST_RECENT_ID_IDX', 'rules_hist_recent')
    drop_table('rules_hist_recent')
    drop_table('rules_history')
