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

"""add load injection tables"""    # noqa: D400, D415

import datetime

import sqlalchemy as sa
from alembic import context
from alembic.op import (
    create_check_constraint,
    create_foreign_key,
    create_index,
    create_primary_key,
    create_table,
    create_unique_constraint,
    drop_table,
)

from rucio.db.sqla.types import GUID

# Alembic revision identifiers
revision = '8e60cb4b5c39'
down_revision = '3b943000da18'


def upgrade():
    """Upgrade the database to this revision."""
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table(
            'load_injection_datasets',
            sa.Column('scope', sa.String(25)),
            sa.Column('name', sa.String(250)),
            sa.Column('bytes', sa.BigInteger),
            sa.Column('length', sa.BigInteger),
            sa.Column('src_rse_id', GUID()),
            sa.Column('dest_rse_id', GUID()),
            sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
            sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow),
        )
        create_primary_key('LOAD_INJECTION_DATASETS_PK', 'load_injection_datasets',
                           ['scope', 'name', 'src_rse_id', 'dest_rse_id'])
        create_foreign_key('LOAD_INJECTION_DATASETS_SCOPE_NAME_FK', 'load_injection_datasets',
                           'dids', ['scope', 'name'], ['scope', 'name'])
        create_foreign_key('LOAD_INJECTION_DATASETS_SRC_RSE_FK', 'load_injection_datasets',
                           'rses', ['src_rse_id'], ['id'])
        create_foreign_key('LOAD_INJECTION_DATASETS_DEST_RSE_FK', 'load_injection_datasets',
                           'rses', ['dest_rse_id'], ['id'])
        create_index('LOAD_INJECTION_DATASETS_SCOPE_NAME_IDX', 'load_injection_datasets',
                     ['scope', 'name'])
        create_index('LOAD_INJECTION_DATASETS_SRC_RSE_DEST_RSE_IDX', 'load_injection_datasets',
                     ['src_rse_id', 'dest_rse_id'])
        create_check_constraint('LOAD_INJECTION_DATASETS_CREATED_NN', 'load_injection_datasets', 'created_at IS NOT NULL')
        create_check_constraint('LOAD_INJECTION_DATASETS_UPDATED_NN', 'load_injection_datasets', 'updated_at IS NOT NULL')

        create_table(
            'load_injection_plans',
            sa.Column('plan_id', GUID(), nullable=False),
            sa.Column('src_rse_id', GUID()),
            sa.Column('dest_rse_id', GUID()),
            sa.Column('vo', sa.String(3)),
            sa.Column('inject_rate', sa.BigInteger, nullable=False),
            sa.Column('interval', sa.BigInteger, nullable=False),
            sa.Column('start_time', sa.DateTime),
            sa.Column('end_time', sa.DateTime),
            sa.Column('fudge', sa.Float),
            sa.Column('max_injection', sa.Float),
            sa.Column('expiration_delay', sa.BigInteger),
            sa.Column('big_first', sa.Boolean),
            sa.Column('rule_lifetime', sa.BigInteger),
            sa.Column('comments', sa.String(4000)),
            sa.Column('dry_run', sa.Boolean),
            sa.Column('state', sa.Enum('W', 'I', 'F', 'K', name='LOAD_INJECTION_PLANS_STATE_CHK', create_constraint=True), nullable=False),
            sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
            sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow),
        )
        create_primary_key('LOAD_INJECTION_PLANS_PK', 'load_injection_plans',
                           ['src_rse_id', 'dest_rse_id'])
        create_foreign_key('LOAD_INJECTION_PLANS_SRC_RSE_FK', 'load_injection_plans',
                           'rses', ['src_rse_id'], ['id'])
        create_foreign_key('LOAD_INJECTION_PLANS_DEST_RSE_FK', 'load_injection_plans',
                           'rses', ['dest_rse_id'], ['id'])
        create_unique_constraint('LOAD_INJECTION_PLANS_PLAN_UC', 'load_injection_plans', ['plan_id'])
        create_check_constraint('LOAD_INJECTION_PLANS_CREATED_NN', 'load_injection_plans', 'created_at IS NOT NULL')
        create_check_constraint('LOAD_INJECTION_PLANS_UPDATED_NN', 'load_injection_plans', 'updated_at IS NOT NULL')

        create_table(
            'load_injection_plans_history',
            sa.Column('plan_id', GUID(), nullable=False),
            sa.Column('src_rse_id', GUID()),
            sa.Column('dest_rse_id', GUID()),
            sa.Column('vo', sa.String(3)),
            sa.Column('inject_rate', sa.BigInteger, nullable=False),
            sa.Column('interval', sa.BigInteger, nullable=False),
            sa.Column('start_time', sa.DateTime),
            sa.Column('end_time', sa.DateTime),
            sa.Column('fudge', sa.Float),
            sa.Column('max_injection', sa.Float),
            sa.Column('expiration_delay', sa.BigInteger),
            sa.Column('big_first', sa.Boolean),
            sa.Column('rule_lifetime', sa.BigInteger),
            sa.Column('comments', sa.String(4000)),
            sa.Column('dry_run', sa.Boolean),
            sa.Column('state', sa.Enum('W', 'I', 'F', 'K', name='LOAD_INJECTION_PLANS_HISTORY_STATE_CHK', create_constraint=True), nullable=False),
            sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
            sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow),
        )
        create_primary_key('LOAD_INJECTION_PLANS_HISTORY_PK', 'load_injection_plans_history',
                           ['plan_id', 'src_rse_id', 'dest_rse_id'])
        create_foreign_key('LOAD_INJECTION_PLANS_HISTORY_SRC_RSE_FK', 'load_injection_plans_history',
                           'rses', ['src_rse_id'], ['id'])
        create_foreign_key('LOAD_INJECTION_PLANS_HISTORY_DEST_RSE_FK', 'load_injection_plans_history',
                           'rses', ['dest_rse_id'], ['id'])
        create_index('LOAD_INJECTION_PLANS_HISTORY_PLAN_IDX', 'load_injection_plans_history', ['plan_id'])
        create_index('LOAD_INJECTION_PLANS_HISTORY_RSE_IDX', 'load_injection_plans_history',
                     ['src_rse_id', 'dest_rse_id'])
        create_check_constraint('LOAD_INJECTION_PLANS_HISTORY_CREATED_NN', 'load_injection_plans_history', 'created_at IS NOT NULL')
        create_check_constraint('LOAD_INJECTION_PLANS_HISTORY_UPDATED_NN', 'load_injection_plans_history', 'updated_at IS NOT NULL')


def downgrade():
    """Downgrade the database to the previous revision."""
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table('load_injection_plans_history')
        drop_table('load_injection_plans')
        drop_table('load_injection_datasets')
        if context.get_context().dialect.name == 'postgresql':
            context.get_context().execute(
                'DROP TYPE IF EXISTS "LOAD_INJECTION_PLANS_STATE_CHK"'
            )
            context.get_context().execute(
                'DROP TYPE IF EXISTS "LOAD_INJECTION_PLANS_HISTORY_STATE_CHK"'
            )
