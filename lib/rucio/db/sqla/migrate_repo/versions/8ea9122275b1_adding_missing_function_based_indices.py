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

''' Adding missing function based indices '''

from alembic import context
from alembic.op import create_index, drop_index, drop_constraint, create_foreign_key

# Alembic revision identifiers
revision = '8ea9122275b1'
down_revision = '50280c53117c'


def upgrade():
    '''
    Upgrade the database to this revision
    '''
    create_index('SUBSCRIPTIONS_STATE_IDX', 'subscriptions', ['state'])
    create_index('CONTENTS_RULE_EVAL_FB_IDX', 'contents', ['rule_evaluation'])
    create_index('REPLICAS_STATE_IDX', 'replicas', ['state'])
    create_index('BAD_REPLICAS_ACCOUNT_IDX', 'bad_replicas', ['account'])
    create_index('REQUESTS_DEST_RSE_ID_IDX', 'requests', ['dest_rse_id'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['mysql']:
        drop_constraint('BAD_REPLICAS_ACCOUNT_FK', 'bad_replicas', type_='foreignkey')
        drop_constraint('REQUESTS_RSES_FK', 'requests', type_='foreignkey')

    drop_index('SUBSCRIPTIONS_STATE_IDX', 'subscriptions')
    drop_index('CONTENTS_RULE_EVAL_FB_IDX', 'contents')
    drop_index('REPLICAS_STATE_IDX', 'replicas')
    drop_index('BAD_REPLICAS_ACCOUNT_IDX', 'bad_replicas')
    drop_index('REQUESTS_DEST_RSE_ID_IDX', 'requests')

    if context.get_context().dialect.name in ['mysql']:
        create_foreign_key('BAD_REPLICAS_ACCOUNT_FK', 'bad_replicas', 'accounts', ['account'], ['account'])
        create_foreign_key('REQUESTS_RSES_FK', 'requests', 'rses', ['dest_rse_id'], ['id'])
