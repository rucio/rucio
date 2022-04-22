# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

''' created rule history tables '''

import datetime

import sqlalchemy as sa

from alembic import context
from alembic.op import create_table, create_index, drop_table, drop_index, create_primary_key

from rucio.db.sqla.constants import (DIDType, RuleGrouping, RuleState, RuleNotification)
from rucio.db.sqla.types import GUID


# Alembic revision identifiers
revision = '384b96aa0f60'
down_revision = '4cf0a2e127d4'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table('rules_hist_recent',
                     sa.Column('history_id', GUID()),
                     sa.Column('id', GUID()),
                     sa.Column('subscription_id', GUID()),
                     sa.Column('account', sa.String(25)),
                     sa.Column('scope', sa.String(25)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('did_type', sa.Enum(DIDType,
                                                   name='RULES_HIST_RECENT_DIDTYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj])),
                     sa.Column('state', sa.Enum(RuleState,
                                                name='RULES_HIST_RECENT_STATE_CHK',
                                                create_constraint=True,
                                                values_callable=lambda obj: [e.value for e in obj])),
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
                     sa.Column('grouping', sa.Enum(RuleGrouping,
                                                   name='RULES_HIST_RECENT_GROUPING_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj])),
                     sa.Column('notification', sa.Enum(RuleNotification,
                                                       name='RULES_HIST_RECENT_NOTIFY_CHK',
                                                       create_constraint=True,
                                                       values_callable=lambda obj: [e.value for e in obj])),
                     sa.Column('stuck_at', sa.DateTime),
                     sa.Column('purge_replicas', sa.Boolean()),
                     sa.Column('ignore_availability', sa.Boolean()),
                     sa.Column('ignore_account_limit', sa.Boolean()),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        create_table('rules_history',
                     sa.Column('history_id', GUID()),
                     sa.Column('id', GUID()),
                     sa.Column('subscription_id', GUID()),
                     sa.Column('account', sa.String(25)),
                     sa.Column('scope', sa.String(25)),
                     sa.Column('name', sa.String(255)),
                     sa.Column('did_type', sa.Enum(DIDType,
                                                   name='RULES_HISTORY_DIDTYPE_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj])),
                     sa.Column('state', sa.Enum(RuleState,
                                                name='RULES_HISTORY_STATE_CHK',
                                                create_constraint=True,
                                                values_callable=lambda obj: [e.value for e in obj])),
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
                     sa.Column('grouping', sa.Enum(RuleGrouping,
                                                   name='RULES_HISTORY_GROUPING_CHK',
                                                   create_constraint=True,
                                                   values_callable=lambda obj: [e.value for e in obj])),
                     sa.Column('notification', sa.Enum(RuleNotification,
                                                       name='RULES_HISTORY_NOTIFY_CHK',
                                                       create_constraint=True,
                                                       values_callable=lambda obj: [e.value for e in obj])),
                     sa.Column('stuck_at', sa.DateTime),
                     sa.Column('purge_replicas', sa.Boolean()),
                     sa.Column('ignore_availability', sa.Boolean()),
                     sa.Column('ignore_account_limit', sa.Boolean()),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        create_primary_key('RULES_HIST_RECENT_PK', 'rules_hist_recent', ['history_id'])
        create_index('RULES_HIST_RECENT_ID_IDX', 'rules_hist_recent', ["id"])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql']:
        drop_index('RULES_HIST_RECENT_ID_IDX', 'rules_hist_recent')
        drop_table('rules_hist_recent')
        drop_table('rules_history')

    elif context.get_context().dialect.name == 'postgresql':
        drop_table('rules_hist_recent')
        drop_table('rules_history')
