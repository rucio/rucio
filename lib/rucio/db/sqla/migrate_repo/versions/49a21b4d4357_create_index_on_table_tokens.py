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

''' add tokens index '''

from alembic import context
from alembic.op import (create_foreign_key, create_index,
                        drop_constraint, drop_index)


# Alembic revision identifiers
revision = '49a21b4d4357'
down_revision = '2eef46be23d4'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_constraint('TOKENS_ACCOUNT_FK', 'tokens', type_='foreignkey')
        create_index('TOKENS_ACCOUNT_EXPIRED_AT_IDX', 'tokens', ['account', 'expired_at'])
        create_foreign_key('TOKENS_ACCOUNT_FK', 'tokens', 'accounts', ['account'], ['account'])


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_constraint('TOKENS_ACCOUNT_FK', 'tokens', type_='foreignkey')
        drop_index('TOKENS_ACCOUNT_EXPIRED_AT_IDX', 'tokens')
        create_foreign_key('TOKENS_ACCOUNT_FK', 'tokens', 'accounts', ['account'], ['account'])
