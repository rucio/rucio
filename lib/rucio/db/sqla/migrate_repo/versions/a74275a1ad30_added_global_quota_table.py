# Copyright 2013-2019 CERN for the benefit of the ATLAS collaboration.
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
#
# Authors:
# - Hannes Hansen <hannes.jakob.hansen@cern.ch>, 2019

''' added global acount limits table '''

import datetime
import sqlalchemy as sa

from alembic import context
from alembic.op import (create_primary_key, create_check_constraint,
                        create_table, drop_table)


# Alembic revision identifiers
revision = 'a74275a1ad30'
down_revision = '2cbee484dcf9'

table_name = 'account_glob_limits'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        create_table(table_name,
                     sa.Column('rse_expression', sa.String(3000)),
                     sa.Column('bytes', sa.BigInteger()),
                     sa.Column('account', sa.String(25)),
                     sa.Column('created_at', sa.DateTime, default=datetime.datetime.utcnow),
                     sa.Column('updated_at', sa.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow))
        create_primary_key('account_glob_limits_pk', table_name, ['account', 'rse_expression'])
        create_check_constraint('account_glob_limits_created_nn', table_name, 'created_at is not null')
        create_check_constraint('account_glob_limits_updated_nn', table_name, 'updated_at is not null')


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        drop_table(table_name)
