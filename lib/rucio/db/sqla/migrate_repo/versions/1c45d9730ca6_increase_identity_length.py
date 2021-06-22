# Copyright 2017-2021
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
# - Martin Barisits <martin.barisits@cern.ch>, 2017
# - Mario Lassnig <mario.lassnig@cern.ch>, 2017-2021
# - Robert Illingworth <illingwo@fnal.gov>, 2019

''' increase identity length '''

import sqlalchemy as sa
from alembic import context, op
from alembic.op import alter_column, create_check_constraint, create_foreign_key, drop_constraint, execute

from rucio.db.sqla.util import try_drop_constraint

# Alembic revision identifiers
revision = '1c45d9730ca6'
down_revision = 'b4293a99f344'


def upgrade():
    '''
    Upgrade the database to this revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    if context.get_context().dialect.name in ['oracle', 'postgresql']:

        alter_column('tokens', 'identity', existing_type=sa.String(255), type_=sa.String(2048), schema=schema[:-1])
        alter_column('identities', 'identity', existing_type=sa.String(255), type_=sa.String(2048), schema=schema[:-1])
        alter_column('account_map', 'identity', existing_type=sa.String(255), type_=sa.String(2048), schema=schema[:-1])

        try_drop_constraint('IDENTITIES_TYPE_CHK', 'identities')
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH')")
        try_drop_constraint('ACCOUNT_MAP_ID_TYPE_CHK', 'account_map')
        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH')")

    elif context.get_context().dialect.name == 'mysql':
        alter_column('tokens', 'identity', existing_type=sa.String(255), type_=sa.String(2048), schema=schema[:-1])

        # MySQL does not allow altering a column referenced by a ForeignKey
        # so we need to drop that one first
        drop_constraint('ACCOUNT_MAP_ID_TYPE_FK', 'account_map', type_='foreignkey')
        alter_column('identities', 'identity', existing_type=sa.String(255), type_=sa.String(2048), nullable=False, schema=schema[:-1])
        alter_column('account_map', 'identity', existing_type=sa.String(255), type_=sa.String(2048), nullable=False, schema=schema[:-1])
        create_foreign_key('ACCOUNT_MAP_ID_TYPE_FK', 'account_map', 'identities', ['identity', 'identity_type'], ['identity', 'identity_type'])

        op.execute('ALTER TABLE ' + schema + 'identities DROP CHECK IDENTITIES_TYPE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH')")
        op.execute('ALTER TABLE ' + schema + 'account_map DROP CHECK ACCOUNT_MAP_ID_TYPE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS', 'SSH')")


def downgrade():
    '''
    Downgrade the database to the previous revision
    '''

    schema = context.get_context().version_table_schema + '.' if context.get_context().version_table_schema else ''

    # Attention!
    # This automatically removes all SSH keys to accommodate the column size and check constraint.

    if context.get_context().dialect.name == 'oracle':
        execute("DELETE FROM account_map WHERE identity_type='SSH'")  # pylint: disable=no-member
        execute("DELETE FROM identities WHERE identity_type='SSH'")  # pylint: disable=no-member

        try_drop_constraint('IDENTITIES_TYPE_CHK', 'identities')
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS')")

        try_drop_constraint('ACCOUNT_MAP_ID_TYPE_CHK', 'account_map')

        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS')")

        alter_column('tokens', 'identity', existing_type=sa.String(2048), type_=sa.String(255))
        alter_column('account_map', 'identity', existing_type=sa.String(2048), type_=sa.String(255))
        alter_column('identities', 'identity', existing_type=sa.String(2048), type_=sa.String(255))

    elif context.get_context().dialect.name == 'postgresql':
        execute("DELETE FROM " + schema + "account_map WHERE identity_type='SSH'")  # pylint: disable=no-member
        execute("DELETE FROM " + schema + "identities WHERE identity_type='SSH'")  # pylint: disable=no-member

        drop_constraint('ACCOUNT_MAP_ID_TYPE_FK', 'account_map', type_='foreignkey')
        op.execute('ALTER TABLE ' + schema + 'identities DROP CONSTRAINT IF EXISTS "IDENTITIES_TYPE_CHK", ALTER COLUMN identity_type TYPE VARCHAR')  # pylint: disable=no-member
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS')")

        op.execute('ALTER TABLE ' + schema + 'account_map DROP CONSTRAINT IF EXISTS "ACCOUNT_MAP_ID_TYPE_CHK", ALTER COLUMN identity_type TYPE VARCHAR')  # pylint: disable=no-member
        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS')")
        create_foreign_key('ACCOUNT_MAP_ID_TYPE_FK', 'account_map', 'identities', ['identity', 'identity_type'], ['identity', 'identity_type'])

        alter_column('tokens', 'identity', existing_type=sa.String(2048), type_=sa.String(255), schema=schema[:-1])
        alter_column('account_map', 'identity', existing_type=sa.String(2048), type_=sa.String(255), schema=schema[:-1])
        alter_column('identities', 'identity', existing_type=sa.String(2048), type_=sa.String(255), schema=schema[:-1])

    elif context.get_context().dialect.name == 'mysql':
        execute("DELETE FROM " + schema + "account_map WHERE identity_type='SSH'")  # pylint: disable=no-member
        execute("DELETE FROM " + schema + "identities WHERE identity_type='SSH'")  # pylint: disable=no-member

        op.execute('ALTER TABLE ' + schema + 'identities DROP CHECK IDENTITIES_TYPE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='IDENTITIES_TYPE_CHK',
                                table_name='identities',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS')")

        op.execute('ALTER TABLE ' + schema + 'account_map DROP CHECK ACCOUNT_MAP_ID_TYPE_CHK')  # pylint: disable=no-member
        create_check_constraint(constraint_name='ACCOUNT_MAP_ID_TYPE_CHK',
                                table_name='account_map',
                                condition="identity_type in ('X509', 'GSS', 'USERPASS')")

        alter_column('tokens', 'identity', existing_type=sa.String(2048), type_=sa.String(255), schema=schema[:-1])

        # MySQL does not allow altering a column referenced by a ForeignKey
        # so we need to drop that one first
        drop_constraint('ACCOUNT_MAP_ID_TYPE_FK', 'account_map', type_='foreignkey')
        alter_column('account_map', 'identity', existing_type=sa.String(2048), type_=sa.String(255), nullable=False, schema=schema[:-1])
        alter_column('identities', 'identity', existing_type=sa.String(2048), type_=sa.String(255), nullable=False, schema=schema[:-1])
        create_foreign_key('ACCOUNT_MAP_ID_TYPE_FK', 'account_map', 'identities', ['identity', 'identity_type'], ['identity', 'identity_type'])
