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

''' set third_party_copy_read and write fields '''

from alembic import context
from alembic.op import execute, alter_column  # pylint: disable=no-member

# Alembic revision identifiers
revision = 'fe1a65b176c9'
down_revision = '0f1adb7a599a'


def upgrade():
    '''
    Upgrade the database to this revision
    '''
    if context.get_context().dialect.name in ['oracle', 'mysql', 'postgresql']:
        schema = context.get_context().version_table_schema if context.get_context().version_table_schema else ''
        schema_prefix = schema + '.' if schema else ''
        execute('UPDATE ' + schema_prefix + 'rse_protocols SET third_party_copy_read=third_party_copy WHERE third_party_copy_read is NULL')
        execute('UPDATE ' + schema_prefix + 'rse_protocols SET third_party_copy_write=third_party_copy WHERE third_party_copy_write is NULL')
        # Add server default to 0. The initial alembic migration creates the column without the default, even if it is set in 'models'
        alter_column('rse_protocols', 'third_party_copy_read', server_default='0', schema=schema)
        alter_column('rse_protocols', 'third_party_copy_write', server_default='0', schema=schema)


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''
    pass
